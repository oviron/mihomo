package finalmask

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/stretchr/testify/require"
)

// tag is a test mask that puts a byte in front of every datagram, or of the
// first write of a TCP connection, and expects the same byte back.
type tag byte

func (b tag) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	return &tagPacketConn{PacketConn: conn, tag: byte(b)}, nil
}

type tagPacketConn struct {
	net.PacketConn
	tag byte
}

func (c *tagPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	_, err := c.PacketConn.WriteTo(append([]byte{c.tag}, p...), addr)
	return len(p), err
}

func (c *tagPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+1)
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	return copy(p, buf[1:n]), addr, nil
}

func (b tag) WrapConn(conn net.Conn) (net.Conn, error) {
	return &tagConn{Conn: conn, tag: byte(b)}, nil
}

type tagConn struct {
	net.Conn
	tag  byte
	sent bool
}

func (c *tagConn) Write(p []byte) (int, error) {
	if !c.sent {
		c.sent = true
		_, err := c.Conn.Write(append([]byte{c.tag}, p...))
		return len(p), err
	}
	return c.Conn.Write(p)
}

// carrier is a test mask that opens the socket itself.
type carrier struct {
	mask.CarrierOnly
	dialed chan netip.AddrPort
}

func (c *carrier) DialPacketConn(ctx context.Context, dialer mask.Dialer, dest netip.AddrPort) (net.PacketConn, error) {
	c.dialed <- dest
	return dialer.ListenPacket(ctx, "udp", "", dest)
}

var testCarrier = &carrier{dialed: make(chan netip.AddrPort, 4)}

func init() {
	mask.RegisterTCP("test-a", func(map[string]any) (mask.TCPMask, error) { return tag('a'), nil })
	mask.RegisterTCP("test-b", func(map[string]any) (mask.TCPMask, error) { return tag('b'), nil })
	mask.RegisterUDP("test-a", func(map[string]any) (mask.UDPMask, error) { return tag('a'), nil })
	mask.RegisterUDP("test-b", func(map[string]any) (mask.UDPMask, error) { return tag('b'), nil })
	mask.RegisterUDP("test-carrier", func(map[string]any) (mask.UDPMask, error) { return testCarrier, nil })
}

// plain is the dialer under the masks.
type plain struct{}

func (plain) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (plain) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func masks(names ...string) []any {
	list := make([]any, len(names))
	for i, name := range names {
		list[i] = map[string]any{"type": name}
	}
	return list
}

func readPacket(t *testing.T, conn net.PacketConn) ([]byte, net.Addr) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 100)
	n, addr, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	return buf[:n], addr
}

// The last mask of a list is the one closest to the wire.
func TestOrder(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer l.Close()
		dialer := NewDialer(plain{}, map[string]any{"tcp": append(masks("test-a", "filter", "test-b"), map[string]any{"type": "FILTER", "settings": map[string]any{"allowedSourceIPs": []any{"10.0.0.0/8"}}})})
		conn, err := dialer.DialContext(context.Background(), "tcp", l.Addr().String())
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("data"))
		require.NoError(t, err)
		server, err := l.Accept()
		require.NoError(t, err)
		defer server.Close()
		buf := make([]byte, 6)
		require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err = server.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "badata", string(buf))
	})

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	t.Run("udp listen", func(t *testing.T) {
		dialer := NewDialer(plain{}, map[string]any{"udp": masks("test-a", "test-b")})
		pc, err := dialer.ListenPacket(context.Background(), "udp", "", serverAddr)
		require.NoError(t, err)
		defer pc.Close()
		_, err = pc.WriteTo([]byte("data"), server.LocalAddr())
		require.NoError(t, err)
		got, client := readPacket(t, server)
		require.Equal(t, "badata", string(got))
		_, err = server.WriteTo([]byte("baback"), client)
		require.NoError(t, err)
		got, from := readPacket(t, pc)
		require.Equal(t, "back", string(got))
		require.Equal(t, server.LocalAddr().String(), from.String())

		// nothing but the PacketConn methods and the buffer sizes is reachable
		_, isUDPConn := pc.(*net.UDPConn)
		require.False(t, isUDPConn)
		_, hasSyscallConn := pc.(interface{ SyscallConn() })
		require.False(t, hasSyscallConn)
		require.NoError(t, pc.(interface{ SetReadBuffer(int) error }).SetReadBuffer(1<<20))
	})

	// The outbounds that ask for a connected socket get one, masked the same way.
	t.Run("udp dial", func(t *testing.T) {
		dialer := NewDialer(plain{}, map[string]any{"udp": masks("test-a", "test-b")})
		conn, err := dialer.DialContext(context.Background(), "udp", server.LocalAddr().String())
		require.NoError(t, err)
		defer conn.Close()
		require.Equal(t, server.LocalAddr().String(), conn.RemoteAddr().String())
		_, err = conn.Write([]byte("data"))
		require.NoError(t, err)
		got, client := readPacket(t, server)
		require.Equal(t, "badata", string(got))
		for _, reply := range []string{"baone", "batwo"} { // datagram boundaries are kept
			_, err = server.WriteTo([]byte(reply), client)
			require.NoError(t, err)
		}
		buf := make([]byte, 100)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "one", string(buf[:n]))
		n, err = conn.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "two", string(buf[:n]))
	})

	t.Run("carrier", func(t *testing.T) {
		dialer := NewDialer(plain{}, map[string]any{"udp": masks("test-a", "test-carrier")})
		for _, dial := range []func() (net.PacketConn, error){
			func() (net.PacketConn, error) {
				return dialer.ListenPacket(context.Background(), "udp", "", serverAddr)
			},
			func() (net.PacketConn, error) {
				conn, err := dialer.DialContext(context.Background(), "udp", server.LocalAddr().String())
				if err != nil {
					return nil, err
				}
				return conn.(net.PacketConn), nil
			},
		} {
			pc, err := dial()
			require.NoError(t, err)
			require.Equal(t, serverAddr, <-testCarrier.dialed)
			_, err = pc.WriteTo([]byte("data"), server.LocalAddr())
			require.NoError(t, err)
			got, _ := readPacket(t, server)
			require.Equal(t, "adata", string(got))
			require.NoError(t, pc.Close())
		}

		// A carrier needs the server address, which e.g. WireGuard with several
		// peers does not give when it opens the socket.
		for _, noAddr := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:0"), netip.MustParseAddrPort("[::]:443")} {
			_, err := dialer.ListenPacket(context.Background(), "udp", "", noAddr)
			require.Error(t, err)
		}
	})
}

func TestNoMasksIsTheInnerDialer(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	dialer := NewDialer(plain{}, map[string]any{"quic-params": map[string]any{"congestion": "bbr"}})
	pc, err := dialer.ListenPacket(context.Background(), "udp", "", server.LocalAddr().(*net.UDPAddr).AddrPort())
	require.NoError(t, err)
	defer pc.Close()
	require.IsType(t, &net.UDPConn{}, pc)
	conn, err := dialer.DialContext(context.Background(), "tcp", l.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	require.IsType(t, &net.TCPConn{}, conn)

	require.Equal(t, plain{}, Raw(dialer))
	require.Equal(t, plain{}, Raw(plain{}))
	require.NotNil(t, QuicParamsOf(dialer))
	require.Nil(t, QuicParamsOf(plain{}))
	require.Nil(t, ConfigOf(plain{}))
}

// A connection with a finalmask of its own gets those masks and not the
// ones of the outbound.
func TestDialerFor(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()
	outbound := NewDialer(plain{}, map[string]any{"udp": masks("test-a"), "quic-params": map[string]any{"congestion": "reno"}})

	own, err := DialerFor(outbound, map[string]any{"udp": masks("test-b")})
	require.NoError(t, err)
	pc, err := own.ListenPacket(context.Background(), "udp", "", serverAddr)
	require.NoError(t, err)
	defer pc.Close()
	_, err = pc.WriteTo([]byte("data"), server.LocalAddr())
	require.NoError(t, err)
	got, _ := readPacket(t, server)
	require.Equal(t, "bdata", string(got))
	require.Nil(t, QuicParamsOf(own))

	none, err := DialerFor(outbound, nil)
	require.NoError(t, err)
	require.Equal(t, plain{}, none)

	_, err = DialerFor(outbound, map[string]any{"udp": masks("no-such-mask")})
	require.Error(t, err)
}

func TestBrokenOption(t *testing.T) {
	for name, raw := range map[string]map[string]any{
		"unknown mask":     {"tcp": masks("no-such-mask")},
		"udp mask in tcp":  {"tcp": masks("test-carrier")},
		"carrier not last": {"udp": masks("test-carrier", "test-a")},
		"two carriers":     {"udp": masks("test-carrier", "test-carrier")},
		"same key twice":   {"tcp": masks("test-a"), "TCP": masks("test-b")},
		"quic":             {"quicParams": map[string]any{"maxIdleTimeout": 3}},
	} {
		_, err := Parse(raw)
		require.Error(t, err, name)

		dialer := NewDialer(plain{}, raw)
		_, err = dialer.DialContext(context.Background(), "tcp", "127.0.0.1:1")
		require.Error(t, err, name)
		_, err = dialer.ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("127.0.0.1:1"))
		require.Error(t, err, name)
		require.Error(t, ValidateProxy(map[string]any{"FinalMask": raw}), name)
	}
	require.NoError(t, ValidateProxy(map[string]any{"name": "proxy"}))
	require.Error(t, ValidateProxy(map[string]any{"finalmask": "fragment"}))
}

func TestQuicParams(t *testing.T) {
	parse := func(raw map[string]any) *QuicParams {
		config, err := Parse(map[string]any{"quic-params": raw})
		require.NoError(t, err)
		return config.Quic
	}

	// rates are bits per second with binary multiples, kept as bytes per second
	p := parse(map[string]any{"brutalUp": "100 mbps", "brutal-down": "8m", "congestion": "Brutal"})
	require.Equal(t, uint64(100<<20/8), p.BrutalUp)
	require.Equal(t, uint64(1<<20), p.BrutalDown)
	for value, want := range map[string]uint64{"524288": 65536, "1.5 mb": 196608, "1g": 1 << 27, "2 Gbps": 1 << 28, "": 0} {
		got, err := parseBandwidth(value)
		require.NoError(t, err, value)
		require.Equal(t, want, got, value)
	}

	shared := &quic.Config{MaxIdleTimeout: time.Minute, InitialStreamReceiveWindow: 1}
	config := parse(map[string]any{
		"maxStreamReceiveWindow": 1 << 20, "keepAlivePeriod": 10, "disablePathMTUDiscovery": true, "maxIncomingStreams": 16,
	}).HTTP3Config(shared)
	require.Equal(t, &quic.Config{
		MaxIdleTimeout: time.Minute, InitialStreamReceiveWindow: 1, // what is not set stays
		MaxStreamReceiveWindow: 1 << 20, KeepAlivePeriod: 10 * time.Second, DisablePathMTUDiscovery: true, MaxIncomingStreams: 16,
	}, config)
	// the config the dials share is left alone
	require.Equal(t, &quic.Config{MaxIdleTimeout: time.Minute, InitialStreamReceiveWindow: 1}, shared)
	var none *QuicParams
	none.ApplyTo(config)
	require.Same(t, shared, none.HTTP3Config(shared))
	none.ApplyHysteria2(nil, 0)
	none.ApplyCongestion(nil, 0)
	require.NoError(t, none.CheckHTTP3([]string{"h3"}))
	require.Error(t, parse(map[string]any{"congestion": "brutal"}).CheckHTTP3([]string{"h3"}))
	require.NoError(t, parse(map[string]any{"congestion": "brutal"}).CheckHTTP3([]string{"h2"}))
	require.NoError(t, parse(map[string]any{"congestion": "force-brutal", "brutalUp": "1m"}).CheckHTTP3([]string{"h3"}))

	// Hysteria 2: who picks the sender
	bbr := func(*quic.Conn) {}
	for _, tc := range []struct {
		params   map[string]any
		send     uint64 // what the client offers to send at: the negotiated Brutal
		receive  uint64
		fallback bool // the outbound's own BBR callback is kept
	}{
		{map[string]any{}, 1000, 2000, true},
		{map[string]any{"brutalUp": "1m", "brutalDown": "2m"}, 1 << 17, 1 << 18, true},
		{map[string]any{"congestion": "bbr", "brutalUp": "1m"}, 0, 2000, true},
		{map[string]any{"congestion": "bbr", "bbrProfile": "aggressive"}, 0, 2000, false},
		{map[string]any{"congestion": "reno"}, 0, 2000, false},
		{map[string]any{"brutalUp": "0", "brutalDown": 0}, 0, 0, true}, // an explicit zero overrides up and down of the outbound
		{map[string]any{"congestion": "force-brutal", "brutalUp": "1m"}, 0, 2000, false},
	} {
		options := hysteria2.ClientOptions{SendBPS: 1000, ReceiveBPS: 2000, SetBBRCongestion: bbr}
		parse(tc.params).ApplyHysteria2(&options, 0)
		require.Equal(t, tc.send, options.SendBPS, tc.params)
		require.Equal(t, tc.receive, options.ReceiveBPS, tc.params)
		kept := reflect.ValueOf(options.SetBBRCongestion).Pointer() == reflect.ValueOf(bbr).Pointer()
		require.Equal(t, tc.fallback, kept, tc.params)
	}

	for name, raw := range map[string]map[string]any{
		"congestion":       {"congestion": "cubic"},
		"profile":          {"bbr-profile": "fast"},
		"slow brutal":      {"brutal-up": "1k"},
		"force without up": {"congestion": "force-brutal"},
		"small window":     {"max-connection-receive-window": 100},
		"negative window":  {"init-stream-receive-window": -1},
		"idle":             {"max-idle-timeout": 200},
		"keepalive":        {"keep-alive-period": 1},
		"streams":          {"max-incoming-streams": 2},
		"unit":             {"brutal-up": "10 furlongs"},
	} {
		_, err := Parse(map[string]any{"quic-params": raw})
		require.Error(t, err, name)
	}
}
