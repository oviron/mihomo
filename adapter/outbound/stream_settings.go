package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// StreamSettings is the `stream-settings` block of a proxy: a transport and a
// security layer under the proxy protocol, whatever the protocol. Xray-core
// has streamSettings on every inbound, so a Shadowsocks, SOCKS or HTTP server
// may sit behind TLS, REALITY, WebSocket, gRPC, XHTTP or mKCP; this is the
// client side for the adapters that have no transport options of their own.
// VLESS, VMess and Trojan have, and take theirs.
//
// It works as a dialer: where the adapter dials the server over TCP it gets
// the established transport instead. UDP sockets are not touched.
type StreamSettings struct {
	Network           string         `proxy:"network,omitempty"` // raw (default), ws, httpupgrade, grpc, xhttp, kcp
	TLS               bool           `proxy:"tls,omitempty"`
	ALPN              []string       `proxy:"alpn,omitempty"`
	ServerName        string         `proxy:"servername,omitempty"`
	SkipCertVerify    bool           `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify    string         `proxy:"name-cert-verify,omitempty"`
	Fingerprint       string         `proxy:"fingerprint,omitempty"`
	Certificate       string         `proxy:"certificate,omitempty"`
	PrivateKey        string         `proxy:"private-key,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
	ECHOpts           ECHOptions     `proxy:"ech-opts,omitempty"`
	RealityOpts       RealityOptions `proxy:"reality-opts,omitempty"`
	WSOpts            WSOptions      `proxy:"ws-opts,omitempty"`
	GrpcOpts          GrpcOptions    `proxy:"grpc-opts,omitempty"`
	XHTTPOpts         XHTTPOptions   `proxy:"xhttp-opts,omitempty"`
	MKCPOpts          MKCPOptions    `proxy:"mkcp-opts,omitempty"`
}

// wrap puts the transport on top of inner, the dialer that reaches the wire.
// A mistake in the settings shows when the proxy first dials.
func (s *StreamSettings) wrap(inner C.Dialer, opts []dialer.Option) C.Dialer {
	d := &streamDialer{Dialer: inner, settings: s, dialOptions: opts}
	d.ech, d.err = s.ECHOpts.Parse()
	if d.err == nil {
		d.reality, d.err = s.RealityOpts.Parse()
	}
	switch s.Network {
	case "", "raw", "tcp", "grpc", "xhttp":
	case "ws", "httpupgrade", "kcp", "mkcp":
		if d.reality != nil && d.err == nil {
			d.err = errors.New("stream-settings: REALITY goes with raw, grpc and xhttp only")
		}
	default:
		d.err = fmt.Errorf("stream-settings: unknown network %q", s.Network)
	}
	if d.reality != nil && !s.TLS && d.err == nil {
		d.err = errors.New("stream-settings: REALITY requires tls")
	}
	// the proxy has no way to close its dialer
	runtime.SetFinalizer(d, (*streamDialer).close)
	return d
}

type streamDialer struct {
	C.Dialer    // the dialer under the transport, also the one for UDP
	settings    *StreamSettings
	dialOptions []dialer.Option
	ech         *ech.Config
	reality     *tlsC.RealityConfig
	err         error

	mu    sync.Mutex
	gun   map[string]*gun.Client   // by server address
	xhttp map[string]*xhttp.Client // by server address
}

func (d *streamDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, client := range d.gun {
		_ = client.Close()
	}
	for _, client := range d.xhttp {
		_ = client.Close()
	}
	d.gun, d.xhttp = nil, nil
}

// tlsConfig is the security layer for the server at address.
func (d *streamDialer) tlsConfig(address string, alpn []string) *vmess.TLSConfig {
	s := d.settings
	host := s.ServerName
	if host == "" {
		host, _, _ = net.SplitHostPort(address)
	}
	return &vmess.TLSConfig{
		Host:              host,
		SkipCertVerify:    s.SkipCertVerify,
		NameCertVerify:    s.NameCertVerify,
		FingerPrint:       s.Fingerprint,
		Certificate:       s.Certificate,
		PrivateKey:        s.PrivateKey,
		ClientFingerprint: s.ClientFingerprint,
		NextProtos:        alpn,
		ECH:               d.ech,
		Reality:           d.reality,
	}
}

func (d *streamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if len(network) < 3 || network[:3] != "tcp" {
		return d.Dialer.DialContext(ctx, network, address)
	}
	if d.err != nil {
		return nil, d.err
	}
	s := d.settings
	switch s.Network {
	case "grpc":
		client, err := d.gunClient(address)
		if err != nil {
			return nil, err
		}
		return client.Dial()
	case "xhttp":
		client, err := d.xhttpClient(address)
		if err != nil {
			return nil, err
		}
		return client.Dial(ctx)
	case "kcp", "mkcp":
		conn, err := dialMKCP(ctx, d.Dialer, address, s.MKCPOpts)
		if err != nil {
			return nil, err
		}
		return d.secure(ctx, conn, address, s.ALPN)
	}

	conn, err := d.Dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	switch s.Network {
	case "ws", "httpupgrade":
		conn, err = d.websocket(ctx, conn, address)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return d.secure(ctx, conn, address, s.ALPN)
	}
}

// secure adds TLS or REALITY when the settings have it; it closes conn on failure.
func (d *streamDialer) secure(ctx context.Context, conn net.Conn, address string, alpn []string) (net.Conn, error) {
	if !d.settings.TLS {
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
	defer cancel()
	secured, err := vmess.StreamTLSConn(ctx, conn, d.tlsConfig(address, alpn))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secured, nil
}

// websocket is WebSocket, or HTTPUpgrade, the way the VLESS adapter sets it up.
func (d *streamDialer) websocket(ctx context.Context, conn net.Conn, address string) (net.Conn, error) {
	s := d.settings
	host, port, _ := net.SplitHostPort(address)
	wsOpts := &vmess.WebsocketConfig{
		Host:                     host,
		Port:                     port,
		Path:                     s.WSOpts.Path,
		MaxEarlyData:             s.WSOpts.MaxEarlyData,
		EarlyDataHeaderName:      s.WSOpts.EarlyDataHeaderName,
		V2rayHttpUpgrade:         s.WSOpts.V2rayHttpUpgrade || s.Network == "httpupgrade",
		V2rayHttpUpgradeFastOpen: s.WSOpts.V2rayHttpUpgradeFastOpen,
		ClientFingerprint:        s.ClientFingerprint,
		ECHConfig:                d.ech,
		Headers:                  http.Header{},
	}
	for key, value := range s.WSOpts.Headers {
		wsOpts.Headers.Add(key, value)
	}
	if s.TLS {
		serverName := host
		if s.ServerName != "" {
			serverName = s.ServerName
		} else if host := wsOpts.Headers.Get("Host"); host != "" {
			serverName = host
		}
		var err error
		wsOpts.TLS = true
		wsOpts.TLSConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: s.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			},
			Fingerprint:    s.Fingerprint,
			NameCertVerify: s.NameCertVerify,
			Certificate:    s.Certificate,
			PrivateKey:     s.PrivateKey,
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	ws, err := vmess.StreamWebsocketConn(ctx, conn, wsOpts)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ws, nil
}

func (d *streamDialer) gunClient(address string) (*gun.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if client := d.gun[address]; client != nil {
		return client, nil
	}
	s := d.settings
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dialer.DialContext(ctx, "tcp", address)
	}
	gunConfig := &gun.Config{
		ServiceName:  s.GrpcOpts.GrpcServiceName,
		UserAgent:    s.GrpcOpts.GrpcUserAgent,
		Host:         s.ServerName,
		PingInterval: s.GrpcOpts.PingInterval,
		Authority:    s.GrpcOpts.Authority,
	}
	if gunConfig.Host == "" {
		gunConfig.Host = address
	}
	var tlsConfig *vmess.TLSConfig
	if s.TLS {
		tlsConfig = d.tlsConfig(address, []string{"h2"})
	}
	client := gun.NewClient(
		func() *gun.Transport { return gun.NewTransport(dial, tlsConfig, gunConfig) },
		s.GrpcOpts.MaxConnections, s.GrpcOpts.MinStreams, s.GrpcOpts.MaxStreams,
	)
	if d.gun == nil {
		d.gun = map[string]*gun.Client{}
	}
	d.gun[address] = client
	return client, nil
}

func (d *streamDialer) xhttpClient(address string) (*xhttp.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if client := d.xhttp[address]; client != nil {
		return client, nil
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil { // JoinHostPort adds the brackets back
		host = ip.String()
	}
	s := d.settings
	tlsConfig := d.tlsConfig(address, nil)
	tlsConfig.Host = s.ServerName
	client, err := newXHTTPClient(xhttpTransport{
		DialOptions: d.dialOptions, Dialer: d.Dialer, Server: host, Port: port,
		TLS: s.TLS, ALPN: s.ALPN, Options: &s.XHTTPOpts, TLSConfig: *tlsConfig,
	})
	if err != nil {
		return nil, err
	}
	if d.xhttp == nil {
		d.xhttp = map[string]*xhttp.Client{}
	}
	d.xhttp[address] = client
	return client, nil
}
