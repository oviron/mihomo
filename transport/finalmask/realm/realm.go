// Package realm is the "realm" UDP mask of Xray-core's finalmask, the hole
// punching of Hysteria 2.9: it reaches a server that sits behind NAT. Both ends
// learn their public addresses from STUN servers and tell them to a rendezvous
// server over HTTP; then they send punch packets at each other until one gets
// through. After that the mask is transparent and the transport above talks
// to the address that answered.
//
// The rendezvous server is an external service (hysteria-realm-server, or the
// hysteria2-realm listener of mihomo). Port mapping (UPnP, NAT-PMP), which
// Xray-core can ask the home router for, is not implemented.
package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/http"
	"github.com/metacubex/sing-quic/hysteria2/realm"
	"github.com/metacubex/tls"
)

func init() {
	mask.RegisterUDP("realm", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// URL is realm://token@host[:port]/realm-id for a rendezvous server over
	// HTTPS, realm+http://... for plain HTTP.
	URL         string   `mask:"url,omitempty"`
	STUNServers []string `mask:"stun-servers,omitempty"`
	// TLSConfig is for the connection to the rendezvous server.
	TLSConfig TLSOptions `mask:"tls-config,omitempty"`
	// IPMode is "dual" (default), "v4" or "v6".
	IPMode      string             `mask:"ip-mode,omitempty"`
	PortMapping PortMappingOptions `mask:"port-mapping,omitempty"`
}

// TLSOptions are the tls-config fields that are supported. A config that
// sets any other field is rejected: it would ask for a check of the server
// that is not made.
type TLSOptions struct {
	ServerName string   `mask:"server-name,omitempty"`
	ALPN       []string `mask:"alpn,omitempty"`
	// PinnedPeerCertSha256 is the hex SHA-256 of the server certificate,
	// VerifyPeerCertByName a name the certificate is checked against instead
	// of the server name.
	PinnedPeerCertSha256 string         `mask:"pinned-peer-cert-sha256,omitempty"`
	VerifyPeerCertByName string         `mask:"verify-peer-cert-by-name,omitempty"`
	Other                map[string]any `mask:",remain"`
}

// PortMappingOptions is there to tell that the setting is not supported.
type PortMappingOptions struct {
	Enabled bool `mask:"enabled,omitempty"`
}

// Mask is a parsed realm mask.
type Mask struct {
	mask.CarrierOnly
	serverURL   string
	token       string
	realmID     string
	stunServers []string
	tlsConfig   *tls.Config
	ipv4, ipv6  bool
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	if options.PortMapping.Enabled {
		return nil, errors.New("port-mapping is not supported")
	}
	u, err := url.Parse(options.URL)
	if err != nil {
		return nil, err
	}
	m := &Mask{}
	var scheme, port string
	switch u.Scheme {
	case "realm":
		scheme, port = "https", "443"
	case "realm+http":
		scheme, port = "http", "80"
	default:
		return nil, fmt.Errorf("invalid url scheme %q, want realm or realm+http", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("url has no host")
	}
	if u.Port() != "" {
		port = u.Port()
	}
	m.serverURL = scheme + "://" + net.JoinHostPort(u.Hostname(), port)
	if m.token, err = url.PathUnescape(u.User.String()); err != nil {
		return nil, err
	}
	if m.token == "" {
		return nil, errors.New("url has no token")
	}
	if m.realmID, err = url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/")); err != nil {
		return nil, err
	}
	if m.realmID == "" {
		return nil, errors.New("url has no realm id")
	}
	// Xray-core escapes the id twice on its way into the request path, and
	// the server registers under what it sent; the control client escapes
	// once more.
	m.realmID = url.PathEscape(m.realmID)
	if len(options.STUNServers) == 0 {
		return nil, errors.New("empty stun-servers")
	}
	for _, server := range options.STUNServers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return nil, fmt.Errorf("stun server %q: %w", server, err)
		}
	}
	m.stunServers = options.STUNServers
	switch strings.ToLower(options.IPMode) {
	case "v4":
		m.ipv4 = true
	case "v6":
		m.ipv6 = true
	default:
		m.ipv4, m.ipv6 = true, true
	}
	for key, value := range options.TLSConfig.Other {
		if value == nil || value == false || value == "" {
			continue
		}
		return nil, fmt.Errorf("tls-config: %q is not supported", key)
	}
	if scheme == "https" {
		serverName := options.TLSConfig.ServerName
		if serverName == "" {
			serverName = u.Hostname()
		}
		m.tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig:      &tls.Config{ServerName: serverName, NextProtos: options.TLSConfig.ALPN},
			Fingerprint:    options.TLSConfig.PinnedPeerCertSha256,
			NameCertVerify: options.TLSConfig.VerifyPeerCertByName,
		})
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// family is the socket of one address family while the peer is looked for.
type family struct {
	ipv4   bool
	conn   net.PacketConn
	locals []netip.AddrPort
}

// How long the whole search for the peer may take; the punch alone gives up
// after 10 seconds.
const dialTimeout = 30 * time.Second

// DialPacketConn finds the server through the rendezvous server and returns
// the socket a punch packet got through on. dest is not used to send to.
func (m *Mask) DialPacketConn(ctx context.Context, dialer mask.Dialer, dest netip.AddrPort) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var families []*family
	closeAll := func() {
		for _, f := range families {
			_ = f.conn.Close()
		}
	}
	var openErr error
	for _, ipv4 := range []bool{true, false} {
		if (ipv4 && !m.ipv4) || (!ipv4 && !m.ipv6) {
			continue
		}
		network, bind := "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
		if ipv4 {
			network, bind = "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
		}
		conn, err := dialer.ListenPacket(ctx, network, "", bind)
		if err != nil {
			openErr = err
			continue
		}
		families = append(families, &family{ipv4: ipv4, conn: conn})
	}
	if len(families) == 0 {
		return nil, fmt.Errorf("realm: open socket: %w", openErr)
	}

	// A STUN server that does not resolve is skipped, as in Xray-core.
	var stunServers []netip.AddrPort
	var stunErr error
	for _, server := range m.stunServers {
		addrs, err := realm.ResolveSTUNServers(ctx, []string{server}, resolveHost, m.ipv4, m.ipv6)
		if err != nil {
			stunErr = err
			continue
		}
		stunServers = append(stunServers, addrs...)
	}
	if len(stunServers) == 0 {
		closeAll()
		return nil, fmt.Errorf("realm: resolve STUN servers: %w", stunErr)
	}

	// Each family asks the STUN servers of its kind for its public address.
	var wg sync.WaitGroup
	discoverErrs := make([]error, len(families))
	for i, f := range families {
		i, f := i, f
		wg.Add(1)
		go func() {
			defer wg.Done()
			var servers []netip.AddrPort
			for _, server := range stunServers {
				if server.Addr().Unmap().Is4() == f.ipv4 {
					servers = append(servers, server)
				}
			}
			if len(servers) == 0 {
				discoverErrs[i] = errors.New("no STUN server of this address family")
				return
			}
			locals, err := realm.Discover(ctx, f.conn, servers)
			for _, local := range locals {
				if local.Addr().Unmap().Is4() == f.ipv4 {
					f.locals = append(f.locals, local)
				}
			}
			discoverErrs[i] = err
		}()
	}
	wg.Wait()
	var surviving []*family
	var locals []netip.AddrPort
	var err error
	for i, f := range families {
		if discoverErrs[i] != nil || len(f.locals) == 0 {
			if discoverErrs[i] != nil {
				err = discoverErrs[i]
			}
			_ = f.conn.Close()
			continue
		}
		surviving = append(surviving, f)
		locals = append(locals, f.locals...)
	}
	families = surviving
	if len(families) == 0 {
		return nil, fmt.Errorf("realm: STUN discovery found no address: %v", err)
	}

	metadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		closeAll()
		return nil, err
	}
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       m.tlsConfig.Clone(), // the transport changes its config
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
	defer httpClient.CloseIdleConnections()
	control, err := realm.NewControlClient(m.serverURL, m.token, httpClient)
	if err != nil {
		closeAll()
		return nil, err
	}
	response, err := control.Connect(ctx, m.realmID, locals, metadata)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("realm: %w", err)
	}

	// The families punch in parallel; the first one that hears the peer
	// wins and the others are closed at once, which ends their punch.
	type outcome struct {
		family *family
		peer   netip.AddrPort
		err    error
	}
	results := make(chan outcome, len(families))
	for _, f := range families {
		f := f
		go func() {
			var peers []netip.AddrPort
			for _, peer := range response.Addresses {
				if peer.Addr().Unmap().Is4() == f.ipv4 {
					peers = append(peers, peer)
				}
			}
			result, err := realm.Punch(ctx, f.conn, peers, response.PunchMetadata)
			results <- outcome{family: f, peer: result.PeerAddr, err: err}
		}()
	}
	for range families {
		result := <-results
		if result.err != nil {
			err = result.err
			_ = result.family.conn.Close()
			continue
		}
		for _, f := range families {
			if f != result.family {
				_ = f.conn.Close()
			}
		}
		_ = result.family.conn.SetReadDeadline(time.Time{})
		return &Conn{
			PacketConn: result.family.conn,
			peer:       net.UDPAddrFromAddrPort(netip.AddrPortFrom(result.peer.Addr().Unmap(), result.peer.Port())),
			logical:    net.UDPAddrFromAddrPort(dest),
		}, nil
	}
	return nil, fmt.Errorf("realm: %w", err)
}

func resolveHost(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	if ipv4 && !ipv6 {
		return resolver.LookupIPv4WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	} else if ipv6 && !ipv4 {
		return resolver.LookupIPv6WithResolver(ctx, host, resolver.ProxyServerHostResolver)
	}
	return resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
}

// Conn sends everything to the peer the punch found and reports the address
// the connection was created for as the source of what the peer sends.
type Conn struct {
	net.PacketConn
	peer    *net.UDPAddr
	logical *net.UDPAddr
}

func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.peer)
}

// ReadFrom returns what the peer sends. Anything else that reaches the
// socket, a late STUN answer for one, is dropped.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if from, ok := addr.(*net.UDPAddr); ok && (from.Port != c.peer.Port || !from.IP.Equal(c.peer.IP)) {
			continue
		}
		return n, c.logical, nil
	}
}
