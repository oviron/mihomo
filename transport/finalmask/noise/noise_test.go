package noise

import (
	"encoding/binary"
	"net"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newConn(t *testing.T, settings map[string]any) (sender net.PacketConn, receiver net.PacketConn) {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	receiver, err = net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close(); _ = receiver.Close() })
	sender, err = m.WrapPacketConn(raw, netip.AddrPort{})
	require.NoError(t, err)
	return sender, receiver
}

// drain reads every datagram that arrives within the timeout.
func drain(t *testing.T, conn net.PacketConn) [][]byte {
	t.Helper()
	var packets [][]byte
	buf := make([]byte, 65535)
	for {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return packets
		}
		packets = append(packets, append([]byte(nil), buf[:n]...))
	}
}

func TestNoiseItems(t *testing.T) {
	sender, receiver := newConn(t, map[string]any{
		"noise": []any{
			map[string]any{"rand": "10-20"},
			map[string]any{"rand": 30, "randRange": "65-70", "delay": "5-10"},
			map[string]any{"packet": []any{1, 2, 3}},
			map[string]any{"type": "str", "packet": "hello"},
			map[string]any{"type": "hex", "packet": "c0ffee"},
			map[string]any{"type": "base64", "packet": "aGk="},
		},
	})
	for i := 0; i < 3; i++ {
		_, err := sender.WriteTo([]byte("data"), receiver.LocalAddr())
		require.NoError(t, err)
	}
	packets := drain(t, receiver)
	// the noise goes once, ahead of the first packet
	require.Len(t, packets, 6+3)
	require.GreaterOrEqual(t, len(packets[0]), 10)
	require.Less(t, len(packets[0]), 20)
	require.Len(t, packets[1], 30)
	for _, b := range packets[1] {
		require.GreaterOrEqual(t, b, byte(65))
		require.LessOrEqual(t, b, byte(70))
	}
	require.Equal(t, []byte{1, 2, 3}, packets[2])
	require.Equal(t, []byte("hello"), packets[3])
	require.Equal(t, []byte{0xc0, 0xff, 0xee}, packets[4])
	require.Equal(t, []byte("hi"), packets[5])
	for _, p := range packets[6:] {
		require.Equal(t, []byte("data"), p)
	}
}

func TestNoiseExp(t *testing.T) {
	sender, receiver := newConn(t, map[string]any{
		"noise": []any{map[string]any{"type": "exp", "packet": "<b 0xdead> <rc 5> <rd 4-4> <t> <c> <n> <r 3-6>"}},
	})
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer other.Close()

	_, err = sender.WriteTo([]byte("data"), receiver.LocalAddr())
	require.NoError(t, err)
	_, err = sender.WriteTo([]byte("data"), other.LocalAddr()) // another address gets its own noise
	require.NoError(t, err)

	for i, conn := range []net.PacketConn{receiver, other} {
		packets := drain(t, conn)
		require.Len(t, packets, 2)
		p := packets[0]
		require.GreaterOrEqual(t, len(p), 2+5+4+4+4+8+3)
		require.LessOrEqual(t, len(p), 2+5+4+4+4+8+6)
		require.Equal(t, []byte{0xde, 0xad}, p[:2])
		require.Regexp(t, regexp.MustCompile(`^[a-zA-Z]{5}[0-9]{4}$`), string(p[2:11]))
		require.InDelta(t, time.Now().Unix(), int64(binary.BigEndian.Uint32(p[11:15])), 5)
		require.Equal(t, uint32(i+1), binary.BigEndian.Uint32(p[15:19]), "the counter runs per connection")
	}
}

func TestNoiseReset(t *testing.T) {
	sender, receiver := newConn(t, map[string]any{
		"reset": 1,
		"noise": []any{map[string]any{"type": "str", "packet": "noise"}},
	})
	write := func() {
		_, err := sender.WriteTo([]byte("data"), receiver.LocalAddr())
		require.NoError(t, err)
	}
	write()
	write()
	require.Len(t, drain(t, receiver), 3)
	time.Sleep(1200 * time.Millisecond) // idle for longer than reset
	write()
	require.Len(t, drain(t, receiver), 2)
}

// Writes that keep coming push the idle deadline forward: no noise in between.
func TestNoiseResetIsAnIdleTime(t *testing.T) {
	sender, receiver := newConn(t, map[string]any{
		"reset": 1,
		"noise": []any{map[string]any{"type": "str", "packet": "noise"}},
	})
	for i := 0; i < 5; i++ {
		_, err := sender.WriteTo([]byte("data"), receiver.LocalAddr())
		require.NoError(t, err)
		time.Sleep(400 * time.Millisecond)
	}
	require.Len(t, drain(t, receiver), 1+5)
}

func TestSettings(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"packet and rand":    {"noise": []any{map[string]any{"rand": 5, "packet": []any{1}}}},
		"script and noise":   {"script": "noise.lua", "noise": []any{map[string]any{"rand": 5}}},
		"bad rand range":     {"noise": []any{map[string]any{"rand": 5, "rand-range": "0-300"}}},
		"bad exp":            {"noise": []any{map[string]any{"type": "exp", "packet": "<x 1>"}}},
		"exp needs size":     {"noise": []any{map[string]any{"type": "exp", "packet": "<r>"}}},
		"exp junk":           {"noise": []any{map[string]any{"type": "exp", "packet": "abc <r 1>"}}},
		"empty exp":          {"noise": []any{map[string]any{"type": "exp", "packet": " "}}},
		"bad hex":            {"noise": []any{map[string]any{"type": "hex", "packet": "zz"}}},
		"unknown type":       {"noise": []any{map[string]any{"type": "utf16", "packet": "a"}}},
		"unknown type only":  {"noise": []any{map[string]any{"type": "utf16"}}},
		"hex without packet": {"noise": []any{map[string]any{"type": "hex"}}},
		"negative rand":      {"noise": []any{map[string]any{"rand": "-5-10"}}},
		"huge rand":          {"noise": []any{map[string]any{"rand": "10-100000"}}},
		"negative delay":     {"noise": []any{map[string]any{"rand": 5, "delay": -1}}},
		"negative reset":     {"reset": -1, "noise": []any{map[string]any{"rand": 5}}},
	} {
		_, err := New(settings)
		require.Error(t, err, name)
	}
}
