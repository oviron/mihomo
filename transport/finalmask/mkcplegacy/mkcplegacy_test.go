package mkcplegacy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func wrap(t *testing.T, conn net.PacketConn, settings ...map[string]any) net.PacketConn {
	t.Helper()
	// the last mask of a list is applied first
	for i := len(settings) - 1; i >= 0; i-- {
		m, err := New(settings[i])
		require.NoError(t, err)
		conn, err = m.WrapPacketConn(conn, netip.AddrPort{})
		require.NoError(t, err)
	}
	return conn
}

func pair(t *testing.T) (a, b net.PacketConn) {
	t.Helper()
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	b, err = net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestRoundTrip(t *testing.T) {
	for name, settings := range map[string][]map[string]any{
		"original":        {{}},
		"seed":            {{"value": "seed"}},
		"dns":             {{"header": "dns"}},
		"dns domain":      {{"header": "DNS", "value": "example.org"}},
		"dtls":            {{"header": "dtls"}},
		"srtp":            {{"header": "srtp"}},
		"utp":             {{"header": "utp"}},
		"wechat":          {{"header": "wechat"}},
		"wireguard":       {{"header": "wireguard"}},
		"seed and header": {{"value": "seed"}, {"header": "wechat"}},
		"header and seed": {{"header": "dtls"}, {"value": "seed"}},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t)
			one, two := wrap(t, a, settings...), wrap(t, b, settings...)
			for _, size := range []int{1, 2, 3, 5, 100, 1350} {
				payload := make([]byte, size)
				_, _ = rand.Read(payload)
				_, err := one.WriteTo(payload, two.LocalAddr())
				require.NoError(t, err)
				require.NoError(t, two.SetReadDeadline(time.Now().Add(5*time.Second)))
				buf := make([]byte, 2000)
				n, _, err := two.ReadFrom(buf)
				require.NoError(t, err)
				require.True(t, bytes.Equal(payload, buf[:n]), "size %d", size)
			}
		})
	}
}

func read(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2000)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	return buf[:n]
}

func TestWire(t *testing.T) {
	payload := []byte("payload")

	t.Run("original", func(t *testing.T) {
		a, b := pair(t)
		_, err := wrap(t, a, map[string]any{}).WriteTo(payload, b.LocalAddr())
		require.NoError(t, err)
		got := read(t, b)
		require.Len(t, got, 6+len(payload))
		// undo the XOR, then: FNV-1a 32 of the rest, the length, the payload
		for i := len(got) - 1; i >= 4; i-- {
			got[i] ^= got[i-4]
		}
		hash := fnv.New32a()
		_, _ = hash.Write(got[4:])
		require.Equal(t, hash.Sum32(), binary.BigEndian.Uint32(got))
		require.Equal(t, append([]byte{0, byte(len(payload))}, payload...), got[4:])
	})

	t.Run("seed", func(t *testing.T) {
		a, b := pair(t)
		_, err := wrap(t, a, map[string]any{"value": "seed"}).WriteTo(payload, b.LocalAddr())
		require.NoError(t, err)
		require.Len(t, read(t, b), 12+len(payload)+16)
	})

	t.Run("dns", func(t *testing.T) {
		a, b := pair(t)
		conn := wrap(t, a, map[string]any{"header": "dns", "value": "example.org"})
		_, err := conn.WriteTo(payload, b.LocalAddr())
		require.NoError(t, err)
		got := read(t, b)
		want := append([]byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7}, "example\x03org\x00\x00\x01\x00\x01"...)
		require.Equal(t, want, got[2:len(got)-len(payload)])
		require.Equal(t, payload, got[len(got)-len(payload):])
	})

	t.Run("headers", func(t *testing.T) {
		for header, want := range map[string][]byte{
			"dtls":      {23, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			"srtp":      {0, 0, 0, 1},
			"utp":       {0, 0, 0, 0},
			"wechat":    {0xa1, 0x08, 0, 0, 0, 1, 0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30},
			"wireguard": {4, 0, 0, 0},
		} {
			a, b := pair(t)
			_, err := wrap(t, a, map[string]any{"header": header}).WriteTo(payload, b.LocalAddr())
			require.NoError(t, err)
			require.Equal(t, append(append([]byte(nil), want...), payload...), read(t, b), header)
		}
	})

	// The security mask first and the header last is the classic mKCP layout.
	t.Run("seed then header", func(t *testing.T) {
		a, b := pair(t)
		conn := wrap(t, a, map[string]any{"value": "seed"}, map[string]any{"header": "wireguard"})
		_, err := conn.WriteTo(payload, b.LocalAddr())
		require.NoError(t, err)
		got := read(t, b)
		require.Equal(t, []byte{4, 0, 0, 0}, got[:4])
		require.Len(t, got, 4+12+len(payload)+16)
	})
}

func TestForeignPacketsAreDropped(t *testing.T) {
	a, b := pair(t)
	receiver := wrap(t, b, map[string]any{"value": "seed"})
	_, err := a.WriteTo([]byte("not an mkcp packet, long enough for nonce and tag"), b.LocalAddr())
	require.NoError(t, err)
	_, err = wrap(t, a, map[string]any{"value": "seed"}).WriteTo([]byte("real"), b.LocalAddr())
	require.NoError(t, err)
	require.Equal(t, []byte("real"), read(t, receiver))
}

func TestSettings(t *testing.T) {
	_, err := New(map[string]any{"header": "quic"})
	require.Error(t, err)
	_, err = New(map[string]any{"header": "dns", "value": strings.Repeat("a", 64) + ".org"})
	require.Error(t, err)
}

// The name is packed as Xray-core packs it, whatever the setting looks like:
// the two ends must cut off a header of the same length.
func TestDNSName(t *testing.T) {
	for domain, want := range map[string]string{
		"example.org":   "\x07example\x03org\x00",
		"example.org.":  "\x07example\x03org\x00\x00", // one more, empty, label
		"a..b":          "\x01a\x00\x01b\x00",
		`dotted\.label`: "\x0cdotted.label\x00",
	} {
		header, err := dnsHeader(domain)
		require.NoError(t, err, domain)
		require.Equal(t, []byte(want), header[12:len(header)-4], domain)
	}
}
