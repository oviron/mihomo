package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/muxcool"

	M "github.com/metacubex/sing/common/metadata"
)

// MuxCoolOption is the "mux" option of a proxy, named after the "mux" object
// of an Xray-core outbound.
type MuxCoolOption struct {
	Enabled bool `proxy:"enabled,omitempty"`
	// Concurrency is the number of sessions on one connection. 0 means 128,
	// which is what Xray-core v26.11.9 makes of every value up to 128; a
	// negative value leaves TCP alone.
	Concurrency int `proxy:"concurrency,omitempty"`
	// XudpConcurrency above 0 gives UDP connections of its own with that many
	// sessions each, 0 lets UDP share the connections of TCP, a negative
	// value leaves UDP to the proxy.
	XudpConcurrency int `proxy:"xudp-concurrency,omitempty"`
	// XudpProxyUDP443 is what happens to UDP port 443 (QUIC): "reject" (the
	// default), "allow", or "skip", which leaves it to the proxy.
	XudpProxyUDP443 string `proxy:"xudp-proxy-udp443,omitempty"`
}

// MuxCool multiplexes the connections of a proxy with Mux.Cool, the protocol
// an Xray-core server speaks on every proxy inbound.
type MuxCool struct {
	ProxyAdapter
	tcp    *muxcool.Client // nil: TCP is not multiplexed
	udp    *muxcool.Client // nil: UDP is left to the proxy
	shared bool            // udp is tcp
	udp443 string
}

// DialContext implements C.ProxyAdapter
func (m *MuxCool) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if m.tcp == nil {
		return m.ProxyAdapter.DialContext(ctx, metadata)
	}
	c, err := m.tcp.DialContext(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, fmt.Errorf("%s mux error: %w", m.Addr(), err)
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *MuxCool) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if metadata.DstPort == 443 {
		switch m.udp443 {
		case "reject":
			return nil, errors.New("mux rejected UDP/443 traffic")
		case "skip":
			return m.ProxyAdapter.ListenPacketContext(ctx, metadata)
		}
	}
	if m.udp == nil {
		return m.ProxyAdapter.ListenPacketContext(ctx, metadata)
	}
	if err := m.ProxyAdapter.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	var globalID [8]byte
	if metadata.SourceValid() {
		globalID = utils.GlobalID(metadata.SourceAddress())
	}
	pc, err := m.udp.ListenPacket(ctx, M.SocksaddrFromNet(metadata.UDPAddr()), globalID)
	if err != nil {
		return nil, fmt.Errorf("%s mux error: %w", m.Addr(), err)
	}
	if m.udp443 != "allow" {
		pc = &muxCoolNoUDP443{pc}
	}
	return NewPacketConn(N.NewThreadSafePacketConn(pc), m), nil
}

// muxCoolNoUDP443 keeps UDP/443 out of an association that started with
// another port. The rule cannot move such a packet to the proxy any more.
type muxCoolNoUDP443 struct {
	net.PacketConn
}

func (c *muxCoolNoUDP443) WriteTo(b []byte, addr net.Addr) (int, error) {
	if M.SocksaddrFromNet(addr).Port == 443 {
		return 0, errors.New("mux rejected UDP/443 traffic")
	}
	return c.PacketConn.WriteTo(b, addr)
}

// SupportUDP implements C.ProxyAdapter
func (m *MuxCool) SupportUDP() bool {
	return m.udp != nil || m.ProxyAdapter.SupportUDP()
}

// SupportUOT implements C.ProxyAdapter
func (m *MuxCool) SupportUOT() bool {
	return m.udp != nil || m.ProxyAdapter.SupportUOT()
}

// Close implements C.ProxyAdapter
func (m *MuxCool) Close() error {
	if m.tcp != nil {
		_ = m.tcp.Close()
	}
	if m.udp != nil && !m.shared {
		_ = m.udp.Close()
	}
	return m.ProxyAdapter.Close()
}

func NewMuxCool(option MuxCoolOption, proxy ProxyAdapter) (ProxyAdapter, error) {
	switch option.XudpProxyUDP443 {
	case "":
		option.XudpProxyUDP443 = "reject"
	case "reject", "allow", "skip":
	default:
		return nil, fmt.Errorf("mux: unknown xudp-proxy-udp443: %s", option.XudpProxyUDP443)
	}
	switch proxy.Type() {
	case C.Vless, C.Vmess, C.Trojan, C.Shadowsocks, C.Socks5, C.Http:
		// what Xray-core has an inbound for; all its inbounds take Mux.Cool
	default:
		return nil, fmt.Errorf("mux is not supported by %s", proxy.Type())
	}
	m := &MuxCool{ProxyAdapter: proxy, udp443: option.XudpProxyUDP443}

	// An XTLS Vision account takes no TCP sessions in Mux.Cool, the server
	// breaks such a connection. TCP stays on Vision and UDP on the XUDP
	// connections the proxy opens itself; only the UDP/443 rule applies.
	if vless, ok := proxy.(*Vless); ok && vless.option.Flow != "" {
		return m, nil
	}
	// An inbound on XHTTP takes UDP sessions only, XHTTP has a multiplexing
	// of its own for the rest (Xray-core, app/proxyman/inbound/inbound.go).
	tcp := !muxCoolOverXHTTP(proxy)

	dial := func(ctx context.Context) (net.Conn, error) {
		return proxy.DialContext(ctx, &C.Metadata{
			NetWork: C.TCP,
			Host:    muxcool.Destination,
			DstPort: muxcool.DestinationPort,
		})
	}
	if option.Concurrency >= 0 && tcp {
		m.tcp = muxcool.NewClient(dial, option.Concurrency)
	}
	switch {
	case option.XudpConcurrency > 0:
		m.udp = muxcool.NewClient(dial, option.XudpConcurrency)
	case option.XudpConcurrency == 0 && m.tcp != nil:
		m.udp, m.shared = m.tcp, true
	case option.XudpConcurrency == 0 && option.Concurrency >= 0: // TCP has no connections to share
		m.udp = muxcool.NewClient(dial, option.Concurrency)
	}
	return m, nil
}

// muxCoolOverXHTTP reports whether the proxy reaches its server over XHTTP:
// with a transport of its own, or with the one of stream-settings, which
// carries every TCP connection the proxy makes.
func muxCoolOverXHTTP(proxy ProxyAdapter) bool {
	var network string
	var basic *BasicOption
	switch p := proxy.(type) {
	case *Vless:
		network, basic = p.option.Network, &p.option.BasicOption
	case *Vmess:
		network, basic = p.option.Network, &p.option.BasicOption
	case *Trojan:
		network, basic = p.option.Network, &p.option.BasicOption
	case *ShadowSocks:
		basic = &p.option.BasicOption
	case *Socks5:
		basic = &p.option.BasicOption
	case *Http:
		basic = &p.option.BasicOption
	}
	switch network {
	case "xhttp":
		return true
	case "kcp", "hysteria": // over UDP, past stream-settings
		return false
	}
	return basic != nil && basic.StreamSettings != nil && basic.StreamSettings.Network == "xhttp"
}
