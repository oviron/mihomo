package finalmask

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// Dialer applies the masks to every connection the inner dialer opens. An
// outbound dials its server through it; use Raw for a connection to anything
// else.
type Dialer struct {
	inner  C.Dialer
	config *Config
	err    error
}

var _ C.Dialer = (*Dialer)(nil)

// NewDialer wraps inner with the masks of a raw finalmask option. A broken
// option makes every dial fail with the parse error: the outbound constructors
// have no way to return it. adapter.ParseProxy rejects such options earlier.
func NewDialer(inner C.Dialer, raw map[string]any) C.Dialer {
	config, err := Parse(raw)
	return &Dialer{inner: inner, config: config, err: err}
}

// Raw returns the dialer without the masks, for connections that do not go to
// the outbound's server.
func Raw(dialer C.Dialer) C.Dialer {
	if d, ok := dialer.(*Dialer); ok {
		return d.inner
	}
	return dialer
}

// ConfigOf returns the finalmask of a dialer made by NewDialer, nil for any
// other dialer or a broken option.
func ConfigOf(dialer C.Dialer) *Config {
	if d, ok := dialer.(*Dialer); ok {
		return d.config
	}
	return nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	if strings.HasPrefix(network, "udp") {
		return d.dialUDP(ctx, network, address)
	}
	conn, err := d.inner.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	for _, m := range d.config.tcp {
		wrapped, err := m.WrapConn(conn)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("finalmask: %w", err)
		}
		conn = wrapped
	}
	return conn, nil
}

// dialUDP serves the outbounds that ask for a connected UDP socket (mKCP,
// WireGuard with one peer).
func (d *Dialer) dialUDP(ctx context.Context, network, address string) (net.Conn, error) {
	if !d.config.HasUDP() {
		return d.inner.DialContext(ctx, network, address)
	}
	if d.config.carrier != nil {
		dest, err := resolveAddrPort(ctx, address)
		if err != nil {
			return nil, err
		}
		pc, err := d.listenPacket(ctx, network, "", dest)
		if err != nil {
			return nil, err
		}
		return &packetNetConn{PacketConn: pc, remote: net.UDPAddrFromAddrPort(dest)}, nil
	}
	conn, err := d.inner.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	remote := conn.RemoteAddr()
	var dest netip.AddrPort
	if addr, ok := remote.(*net.UDPAddr); ok {
		dest = addr.AddrPort()
	} else if remote != nil {
		dest, _ = netip.ParseAddrPort(remote.String())
	}
	pc, err := d.wrapPacketConn(&connPacketConn{Conn: conn, remote: remote}, dest)
	if err != nil {
		return nil, err
	}
	return &packetNetConn{PacketConn: pc, remote: remote}, nil
}

func (d *Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	if d.err != nil {
		return nil, d.err
	}
	if !d.config.HasUDP() {
		return d.inner.ListenPacket(ctx, network, address, rAddrPort)
	}
	return d.listenPacket(ctx, network, address, rAddrPort)
}

func (d *Dialer) listenPacket(ctx context.Context, network, address string, dest netip.AddrPort) (net.PacketConn, error) {
	var pc net.PacketConn
	var err error
	serverAddr := dest
	if !dest.IsValid() || dest.Addr().IsUnspecified() || dest.Port() == 0 {
		// e.g. WireGuard with several peers opens the socket without naming one
		serverAddr = netip.AddrPort{}
	}
	if d.config.carrier != nil {
		if !serverAddr.IsValid() {
			return nil, fmt.Errorf("finalmask: the last udp mask needs the server address, which this outbound does not give when it opens the socket")
		}
		pc, err = d.config.carrier.DialPacketConn(ctx, d.inner, serverAddr)
		if err != nil {
			return nil, fmt.Errorf("finalmask: %w", err)
		}
	} else {
		pc, err = d.inner.ListenPacket(ctx, network, address, dest)
		if err != nil {
			return nil, err
		}
	}
	return d.wrapPacketConn(pc, serverAddr)
}

func (d *Dialer) wrapPacketConn(socket net.PacketConn, dest netip.AddrPort) (net.PacketConn, error) {
	// The masks get a plain PacketConn and return one: nothing above may reach
	// the socket through SyscallConn or ReadMsgUDP and send around the masks.
	var pc net.PacketConn = plainPacketConn{socket}
	for _, m := range d.config.udp {
		wrapped, err := m.WrapPacketConn(pc, dest)
		if err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("finalmask: %w", err)
		}
		pc = wrapped
	}
	return &maskedPacketConn{PacketConn: pc, socket: socket}, nil
}

func resolveAddrPort(ctx context.Context, address string) (netip.AddrPort, error) {
	if dest, err := netip.ParseAddrPort(address); err == nil {
		return netip.AddrPortFrom(dest.Addr().Unmap(), dest.Port()), nil
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
}

// plainPacketConn hides every method of the wrapped connection but those of
// net.PacketConn.
type plainPacketConn struct {
	net.PacketConn
}

// maskedPacketConn is what the outbound gets. Besides net.PacketConn it only
// lets the socket buffers be sized, which QUIC and WireGuard do.
type maskedPacketConn struct {
	net.PacketConn
	socket net.PacketConn
}

func (c *maskedPacketConn) SetReadBuffer(bytes int) error {
	if s, ok := c.socket.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(bytes)
	}
	return nil
}

func (c *maskedPacketConn) SetWriteBuffer(bytes int) error {
	if s, ok := c.socket.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(bytes)
	}
	return nil
}

// connPacketConn turns a connected UDP socket into a PacketConn for the masks.
type connPacketConn struct {
	net.Conn
	remote net.Addr
}

func (c *connPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *connPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

// packetNetConn turns the masked PacketConn back into the connected socket
// the outbound asked for.
type packetNetConn struct {
	net.PacketConn
	remote net.Addr
}

func (c *packetNetConn) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func (c *packetNetConn) Write(p []byte) (int, error) {
	return c.PacketConn.WriteTo(p, c.remote)
}

func (c *packetNetConn) RemoteAddr() net.Addr {
	return c.remote
}

// CheckMKCP rejects the mKCP options that can't work together. raw tells that
// the transport sends bare mKCP, obfuscated that it was given a seed or a
// header of its own.
func CheckMKCP(dialer C.Dialer, raw, obfuscated bool) error {
	if raw && obfuscated {
		return fmt.Errorf("mkcp-opts: raw can't be used together with seed or header")
	}
	if config := ConfigOf(dialer); config != nil && config.MKCPLegacy && !raw {
		return fmt.Errorf("finalmask: the mkcp-legacy mask needs mkcp-opts: {raw: true}, the packets would be obfuscated twice otherwise")
	}
	return nil
}

// DialerFor returns the dialer for a connection that has a finalmask option
// of its own, such as the download server of XHTTP: the masks of raw over
// what base dials with underneath its own masks. A nil raw gives that
// unmasked dialer. Unlike NewDialer it reports a broken option at once.
func DialerFor(base C.Dialer, raw map[string]any) (C.Dialer, error) {
	inner := Raw(base)
	if raw == nil {
		return inner, nil
	}
	config, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return &Dialer{inner: inner, config: config}, nil
}
