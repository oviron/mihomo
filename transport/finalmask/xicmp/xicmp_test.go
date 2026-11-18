package xicmp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var testClientID = [clientIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8}

func TestSettings(t *testing.T) {
	m, err := New(nil)
	require.NoError(t, err)
	require.False(t, m.dgram)
	require.Empty(t, m.ips)

	m, err = New(map[string]any{"ips": []any{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.2"}})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.2"),
	}, m.ips)

	// the names of the Xray-core protobuf config
	m, err = New(map[string]any{"DGRAM": datagramSupported, "IPs": []string{"192.0.2.1"}})
	require.NoError(t, err)
	require.Equal(t, datagramSupported, m.dgram)
	require.Len(t, m.ips, 1)

	for name, settings := range map[string]map[string]any{
		"a domain":    {"ips": []any{"example.org"}},
		"a prefix":    {"ips": []any{"192.0.2.0/24"}},
		"with a port": {"ips": []any{"192.0.2.1:443"}},
		"not a list":  {"ips": 5},
		"not a bool":  {"dgram": "maybe"},
	} {
		_, err = New(settings)
		require.Error(t, err, name)
	}

	_, err = New(map[string]any{"dgram": true})
	if datagramSupported {
		require.NoError(t, err)
	} else {
		require.ErrorContains(t, err, "not supported")
	}
}

func TestRegisteredAsCarrier(t *testing.T) {
	m, err := mask.BuildUDP("xicmp", map[string]any{"ips": []any{"192.0.2.1"}})
	require.NoError(t, err)
	_, ok := m.(mask.UDPCarrier)
	require.True(t, ok)
	// it opens the socket itself and cannot wrap one
	_, err = m.WrapPacketConn(nil, netip.AddrPort{})
	require.Error(t, err)
}

func TestChecksum(t *testing.T) {
	// the example of RFC 1071
	require.Equal(t, uint16(0x220d), checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}))
	// an odd length is padded with a zero byte
	require.Equal(t, checksum([]byte{0x12, 0x34, 0x56, 0x00}), checksum([]byte{0x12, 0x34, 0x56}))
	require.Equal(t, uint16(0xffff), checksum(nil))
}

// The requests are what the Xray-core client sends: an ordinary echo request
// whose data is the client id and the datagram.
func TestEchoRequestWireFormat(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("x"), []byte("an even payload!"), bytes.Repeat([]byte{0xff}, MaxPayload)} {
		data := append(append([]byte(nil), testClientID[:]...), payload...)

		got := appendEchoRequest(nil, false, 0xbeef, 0x0102, testClientID, payload)
		want, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 0xbeef, Seq: 0x0102, Data: data}}).Marshal(nil)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, uint16(0), checksum(got), "a message with a right checksum sums up to zero")
		require.Len(t, got, headerSize+clientIDSize+len(payload))

		// ICMPv6: the checksum is left to the kernel
		got = appendEchoRequest(nil, true, 0xbeef, 0x0102, testClientID, payload)
		want, err = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 0xbeef, Seq: 0x0102, Data: data}}).Marshal(nil)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, []byte{128, 0, 0, 0, 0xbe, 0xef, 0x01, 0x02}, got[:headerSize])
	}

	// it appends
	got := appendEchoRequest([]byte("head"), false, 1, 2, testClientID, []byte("data"))
	require.Equal(t, "head", string(got[:4]))
	require.Equal(t, appendEchoRequest(nil, false, 1, 2, testClientID, []byte("data")), got[4:])
	require.Equal(t, 4096, headerSize+clientIDSize+MaxPayload)
}

// reply is what the Xray-core server sends: an echo reply with the bare
// datagram.
func reply(t *testing.T, typ icmp.Type, id int, data []byte) []byte {
	t.Helper()
	b, err := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: 9, Data: data}}).Marshal(nil)
	require.NoError(t, err)
	return b
}

func TestAccept(t *testing.T) {
	c := &Conn{clientID: testClientID, id: 0x1234, checkID: true}
	datagram := []byte("a datagram of the server")

	data, ok := c.accept(reply(t, ipv4.ICMPTypeEchoReply, 0x1234, datagram), false)
	require.True(t, ok)
	require.Equal(t, datagram, data)
	data, ok = c.accept(reply(t, ipv6.ICMPTypeEchoReply, 0x1234, datagram), true)
	require.True(t, ok)
	require.Equal(t, datagram, data)

	drop := func(name string, message []byte, v6 bool) {
		_, ok := c.accept(message, v6)
		require.False(t, ok, name)
	}
	drop("another identifier", reply(t, ipv4.ICMPTypeEchoReply, 0x1235, datagram), false)
	drop("a request", reply(t, ipv4.ICMPTypeEcho, 0x1234, datagram), false)
	drop("a request, v6", reply(t, ipv6.ICMPTypeEchoRequest, 0x1234, datagram), true)
	drop("an ICMPv4 reply on the v6 socket", reply(t, ipv4.ICMPTypeEchoReply, 0x1234, datagram), true)
	drop("an ICMPv6 reply on the v4 socket", reply(t, ipv6.ICMPTypeEchoReply, 0x1234, datagram), false)
	drop("a short message", []byte{0, 0, 0, 0, 0x12, 0x34, 0}, false)
	drop("empty", nil, false)
	// the pinged host itself answers with a copy of the request
	own := appendEchoRequest(nil, false, 0x1234, 1, testClientID, datagram)
	own[0] = typeEchoReply4
	drop("the echo of a request", own, false)
	drop("the echo of an empty request", own[:headerSize+clientIDSize], false)

	// a Linux datagram socket has its own identifier and filters by itself
	c.checkID = false
	data, ok = c.accept(reply(t, ipv4.ICMPTypeEchoReply, 0x1235, datagram), false)
	require.True(t, ok)
	require.Equal(t, datagram, data)
	drop("the echo of a request", own, false)

	// a reply without data is an empty datagram
	data, ok = c.accept(reply(t, ipv4.ICMPTypeEchoReply, 0x1235, nil), false)
	require.True(t, ok)
	require.Empty(t, data)
}

func TestStripIPv4Header(t *testing.T) {
	message := reply(t, ipv4.ICMPTypeEchoReply, 1, []byte("data"))
	header := make([]byte, 20)
	header[0] = 0x45
	require.Equal(t, message, stripIPv4Header(append(header, message...)))
	options := make([]byte, 28)
	options[0] = 0x47
	require.Equal(t, message, stripIPv4Header(append(options, message...)))
	// not an IP packet: left as it is
	require.Equal(t, message, stripIPv4Header(message))
	bad := append([]byte{0x4f}, make([]byte, 30)...)
	require.Equal(t, bad, stripIPv4Header(bad))
}

// dial opens the tunnel to a host that answers echo requests, loopback
// unless XICMP_TEST_HOST (IPv4) or XICMP_TEST_HOST6 names another one. The
// test is skipped when the socket cannot be opened.
func dial(t *testing.T, dgram, v6 bool, settings map[string]any) (*Conn, netip.AddrPort) {
	t.Helper()
	host, env := "127.0.0.1", "XICMP_TEST_HOST"
	if v6 {
		host, env = "::1", "XICMP_TEST_HOST6"
	}
	if value := os.Getenv(env); value != "" {
		host = value
	}
	dest := netip.AddrPortFrom(netip.MustParseAddr(host), 443)
	if settings == nil {
		settings = map[string]any{}
	}
	settings["dgram"] = dgram
	m, err := New(settings)
	if err != nil && !datagramSupported {
		t.Skip(err)
	}
	require.NoError(t, err)
	pc, err := m.DialPacketConn(context.Background(), nil, dest)
	if err != nil {
		t.Skipf("no ICMP socket (dgram=%v needs net.ipv4.ping_group_range on Linux, raw needs root): %v", dgram, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*Conn), dest
}

// Every socket goes through the socket hook before it is used: on Android
// that is what keeps it out of the VPN.
func TestSocketHook(t *testing.T) {
	for _, dgram := range []bool{false, true} {
		name := "raw"
		if dgram {
			name = "dgram"
		}
		t.Run(name, func(t *testing.T) {
			var calls []string
			var hookErr error
			dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
				calls = append(calls, network+" "+address)
				if hookErr != nil {
					return hookErr
				}
				return conn.Control(func(uintptr) {})
			}
			t.Cleanup(func() { dialer.DefaultSocketHook = nil })

			settings := map[string]any{"ips": []any{"127.0.0.1", "::1", "127.0.0.2"}}
			c, dest := dial(t, dgram, false, settings)
			require.Equal(t, []string{"ip4 127.0.0.1:0", "ip6 [::1]:0"}, calls, "one socket for each family")

			// no socket is left behind when the hook refuses one
			calls, hookErr = nil, errors.New("refused")
			m, err := New(settings)
			require.NoError(t, err)
			_, err = m.DialPacketConn(context.Background(), nil, dest)
			require.ErrorIs(t, err, hookErr)
			require.Len(t, calls, 1)
			_ = c.Close()
		})
	}
}

func TestNoAddress(t *testing.T) {
	m, err := New(nil)
	require.NoError(t, err)
	_, err = m.DialPacketConn(context.Background(), nil, netip.AddrPort{})
	require.Error(t, err)
}

// TestSockets drives the real sockets with the help of the pinged host, which
// answers an echo request with a copy of it: a request with a foreign client
// id comes back as if a server had sent it, one with the own client id has to
// be dropped.
func TestSockets(t *testing.T) {
	for _, test := range []struct {
		name      string
		dgram, v6 bool
	}{
		{"raw-ipv4", false, false},
		{"raw-ipv6", false, true},
		{"dgram-ipv4", true, false},
		{"dgram-ipv6", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, dest := dial(t, test.dgram, test.v6, nil)
			family := 0
			if test.v6 {
				family = 1
			}
			require.NotNil(t, c.sockets[family])
			require.Nil(t, c.sockets[1-family], "only the family of the server is opened")

			foreign := [clientIDSize]byte{9, 9, 9, 9, 9, 9, 9, 9}
			payload := bytes.Repeat([]byte("xicmp"), 60)
			request := appendEchoRequest(nil, test.v6, c.id, 1, foreign, payload)
			_, err := c.sockets[family].WriteTo(request, c.targets[0].addr)
			require.NoError(t, err)

			buf := make([]byte, 4096)
			require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
			n, from, err := c.ReadFrom(buf)
			if os.IsTimeout(err) {
				t.Skipf("%s does not answer echo requests", dest.Addr())
			}
			require.NoError(t, err)
			require.Equal(t, append(append([]byte(nil), foreign[:]...), payload...), buf[:n])
			require.Equal(t, net.UDPAddrFromAddrPort(dest), from, "the source is the server address")

			// the address given to WriteTo does not matter; the echo of the own request is dropped
			n, err = c.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1})
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			require.NoError(t, c.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
			_, _, err = c.ReadFrom(buf)
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)

			// a datagram that is too large is refused
			n, err = c.WriteTo(make([]byte, MaxPayload+1), nil)
			require.ErrorContains(t, err, "too large")
			require.Zero(t, n)

			// Close wakes a blocked reader and stops the receiver
			require.NoError(t, c.SetReadDeadline(time.Time{}))
			done := make(chan error, 1)
			go func() {
				_, _, err := c.ReadFrom(buf)
				done <- err
			}()
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, c.Close())
			select {
			case err = <-done:
				require.ErrorIs(t, err, net.ErrClosed)
			case <-time.After(2 * time.Second):
				t.Fatal("ReadFrom did not return after Close")
			}
			require.NoError(t, c.Close())
			_, _, err = c.ReadFrom(buf)
			require.ErrorIs(t, err, net.ErrClosed)
			_, err = c.WriteTo(payload, nil)
			require.ErrorIs(t, err, net.ErrClosed)
			_, _, err = c.sockets[family].ReadFrom(buf)
			require.ErrorIs(t, err, net.ErrClosed, "the socket is closed")
		})
	}
}

// With ips the packets go to these addresses and the sockets are opened for
// their families, not for the one of the server address.
func TestTargets(t *testing.T) {
	c, _ := dial(t, false, true, map[string]any{"ips": []any{"127.0.0.1", "127.0.0.2"}})
	require.NotNil(t, c.sockets[0])
	require.Nil(t, c.sockets[1])
	require.Len(t, c.targets, 2)
	require.Equal(t, "127.0.0.1", c.targets[0].addr.String())
	require.Equal(t, "127.0.0.2", c.targets[1].addr.String())
	for i := 0; i < 64; i++ {
		_, err := c.WriteTo([]byte("data"), nil)
		require.NoError(t, err)
	}
	require.Equal(t, uint32(64), c.seq.Load(), "every packet has its own sequence number")

	c, _ = dial(t, false, false, map[string]any{"ips": []any{"127.0.0.1", "::1"}})
	require.NotNil(t, c.sockets[0])
	require.NotNil(t, c.sockets[1])
	require.Equal(t, []int{0, 1}, []int{c.targets[0].family, c.targets[1].family})
}
