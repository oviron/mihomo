package salamander

import (
	"bytes"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/stretchr/testify/require"
)

func udpPair(t *testing.T) (a, b net.PacketConn) {
	t.Helper()
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	b, err = net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func wrap(t *testing.T, conn net.PacketConn, settings map[string]any) net.PacketConn {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	wrapped, err := m.WrapPacketConn(conn, netip.AddrPort{})
	require.NoError(t, err)
	return wrapped
}

func roundTrip(t *testing.T, from, to net.PacketConn, payload []byte, bufSize int) {
	t.Helper()
	_, err := from.WriteTo(payload, to.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, to.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, bufSize)
	n, addr, err := to.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, from.LocalAddr().String(), addr.String())
	require.True(t, bytes.Equal(payload, buf[:n]), "payload of %d bytes came back as %d bytes", len(payload), n)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// The mask and the Salamander of sing-quic, which the hysteria2 outbound
// uses, must understand each other.
func TestSalamanderMatchesSingQuic(t *testing.T) {
	a, b := udpPair(t)
	ours := wrap(t, a, map[string]any{"password": "secret"})
	theirs := hysteria2.NewSalamanderConn(b, []byte("secret"))
	for _, size := range []int{1, 100, 1200, 4000} {
		roundTrip(t, ours, theirs, randomBytes(size), 8192)
		roundTrip(t, theirs, ours, randomBytes(size), 8192)
	}
}

func TestSalamanderWire(t *testing.T) {
	a, b := udpPair(t)
	ours := wrap(t, a, map[string]any{"password": "secret"})
	payload := []byte("the payload")
	_, err := ours.WriteTo(payload, b.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 100)
	require.NoError(t, b.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, _, err := b.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 8+len(payload), n)
	require.False(t, bytes.Contains(buf[:n], payload))

	// Datagrams shorter than the salt are dropped, a caller buffer smaller
	// than the masked datagram still gets the whole payload.
	_, err = b.WriteTo([]byte("short"), a.LocalAddr())
	require.NoError(t, err)
	roundTrip(t, wrap(t, b, map[string]any{"password": "secret"}), ours, payload, len(payload))
}

func TestGecko(t *testing.T) {
	a, b := udpPair(t)
	settings := map[string]any{"password": "secret", "packetSize": "600-900"}
	one, two := wrap(t, a, settings), wrap(t, b, settings)
	for _, size := range []int{40, 300, 1200} {
		long := randomBytes(size)
		long[0] |= 0x80 // a long header QUIC packet: split and padded
		roundTrip(t, one, two, long, 1500)
		short := randomBytes(size)
		short[0] &^= 0x80 // a short header packet: plain Salamander
		roundTrip(t, two, one, short, 1500)
	}

	// A long header packet leaves as several datagrams of the configured size.
	raw, peer := udpPair(t)
	sender := wrap(t, raw, settings)
	long := randomBytes(1000)
	long[0] |= 0x80
	_, err := sender.WriteTo(long, peer.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 4096)
	count := 0
	for {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			break
		}
		count++
		require.GreaterOrEqual(t, n, 600)
		require.LessOrEqual(t, n, 900)
	}
	require.GreaterOrEqual(t, count, 2)
	require.LessOrEqual(t, count, 8)
}

// Datagrams with nothing after the salt are dropped, also under Gecko.
func TestShortDatagramsAreDropped(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"salamander": {"password": "secret"},
		"gecko":      {"password": "secret", "packet-size": "600-900"},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := udpPair(t)
			sender, receiver := wrap(t, a, settings), wrap(t, b, settings)
			for _, size := range []int{1, 7, 8} {
				_, err := a.WriteTo(randomBytes(size), b.LocalAddr())
				require.NoError(t, err)
			}
			payload := randomBytes(700)
			payload[0] |= 0x80
			roundTrip(t, sender, receiver, payload, 700) // a buffer just large enough for the payload
		})
	}
}

func TestSettings(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"short password": {"password": "abc"},
		"no password":    {},
		"gecko too big":  {"password": "secret", "packet-size": "100-4000"},
		"gecko zero min": {"password": "secret", "packet-size": "0-900"},
	} {
		_, err := New(settings)
		require.Error(t, err, name)
	}
}
