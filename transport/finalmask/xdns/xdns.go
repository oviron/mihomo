// Package xdns is the "xdns" UDP mask of Xray-core's finalmask: a DNS tunnel.
// Every datagram the outbound sends leaves as a DNS query whose name carries
// the bytes in base32 under one of the configured domains, and the datagrams
// of the server come back in the answers (TXT, A, AAAA or CNAME records). The
// queries go to ordinary resolvers over UDP, TCP or DNS over HTTPS; these
// find the server because it is the authoritative name server of the domain.
// The mask therefore never sends anything to the server address itself.
//
//	udp:
//	  - type: xdns
//	    settings:
//	      domains:
//	        - names: [t.example.com]
//	          types: [16]       # 16 TXT (default), 1 A, 5 CNAME, 28 AAAA
//	          edns0: 1232       # UDP payload size to announce, 0 (none) or 512-4096
//	          len-limit: 255    # longest query name on the wire
//	          label-limit: 63   # longest label that carries data
//	      resolvers:
//	        - addrs: [192.0.2.1, "tcp://192.0.2.2:53", "https://dns.example/dns-query"]
//	          worker: 32        # concurrent requests of a DNS over HTTPS resolver
//	          tls-config: {server-name: dns.example, alpn: [h3]}
//	          quic-config: {congestion: bbr, max-idle-timeout: 30}
//	      extra-poll: 0         # more polls after every query, 0-3
//
// The server can only answer queries, so once the first datagram has come
// the client keeps asking: one poll for every answer that brought data, and
// polls 0.5 to 10 seconds apart while there is none.
//
// An answer holds whole datagrams only, and how many bytes fit depends on the
// record type, on edns0 and on the length of the query name; without EDNS a
// DNS message is 512 bytes. The server drops a datagram that does not fit, so
// the transport above the mask needs a small MTU on both sides. Towards the
// server a datagram larger than one query name is split over several queries,
// 255 at most.
//
// Two things a recursive resolver on the way may do, as with the client of
// Xray-core: an answer it truncates (TC) is lost, there is no retry over TCP,
// so edns0 has to be within what the resolver passes; and a CNAME answer of
// several records does not survive a resolver that keeps one CNAME per name
// (Unbound does), so CNAME is for answers that fit one record.
package xdns

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

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func init() {
	mask.RegisterUDP("xdns", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	Domains   []DomainOptions   `mask:"domains,omitempty"`
	Resolvers []ResolverOptions `mask:"resolvers,omitempty"`
	// ExtraPoll is how many polls follow every query, 0 to 3. They give the
	// server more answers to put its datagrams into.
	ExtraPoll int `mask:"extra-poll,omitempty"`
}

// DomainOptions describe domains the server is authoritative for. A query
// goes to one of them, picked at random.
type DomainOptions struct {
	Names []string `mask:"names,omitempty"`
	// LenLimit is the longest query name as it is on the wire, 255 by default.
	LenLimit int `mask:"len-limit,omitempty"`
	// LabelLimit is the longest label that carries data, 63 by default.
	LabelLimit int `mask:"label-limit,omitempty"`
	// Types are the record types to ask for, picked at random per datagram:
	// 1 (A), 5 (CNAME), 16 (TXT, the default) and 28 (AAAA).
	Types []int `mask:"types,omitempty"`
	// EDNS0 is the UDP payload size announced in the queries, 512 to 4096.
	// With 0 the queries have no EDNS and the answers stay within 512 bytes.
	EDNS0 int `mask:"edns0,omitempty"`
}

// ResolverOptions describe resolvers to send the queries through.
type ResolverOptions struct {
	// Addrs are "host", "host:port", "udp://host:port", "tcp://host:port"
	// (port 53 by default) and "https://..." URLs.
	Addrs []string `mask:"addrs,omitempty"`
	// Worker is the number of concurrent requests to an https resolver, 32 by
	// default.
	Worker int `mask:"worker,omitempty"`
	// TLSConfig applies to the https resolvers. An ALPN of exactly ["h3"]
	// selects HTTP/3; otherwise it is HTTP/2 or HTTP/1.1 over TCP, whichever
	// of the two the list has, both when there is no list.
	TLSConfig mask.TLSOptions `mask:"tls-config,omitempty"`
	// QUICConfig applies to the HTTP/3 resolvers.
	QUICConfig QUICOptions `mask:"quic-config,omitempty"`
}

// QUICOptions tune the QUIC connection of an HTTP/3 resolver: the quicParams
// of Xray-core. The settings of it that have no counterpart here (debug,
// disableGSO, disableChromeParrot, disableStatelessReset and the brutal
// ones) are accepted and ignored.
type QUICOptions struct {
	// Congestion is "reno" (the default) or "bbr". The brutal controls send
	// at a fixed rate that a Hysteria server tells; a resolver is none.
	Congestion string `mask:"congestion,omitempty"`
	// BBRProfile is "conservative", "standard" (the default) or "aggressive".
	BBRProfile string `mask:"bbr-profile,omitempty"`
	// The receive windows are in bytes, 16384 at least.
	InitStreamReceiveWindow     int64 `mask:"init-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow      int64 `mask:"max-stream-receive-window,omitempty"`
	InitConnectionReceiveWindow int64 `mask:"init-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow  int64 `mask:"max-connection-receive-window,omitempty"`
	// MaxIdleTimeout (4-120) and KeepAlivePeriod (2-60) are in seconds.
	MaxIdleTimeout          int64 `mask:"max-idle-timeout,omitempty"`
	KeepAlivePeriod         int64 `mask:"keep-alive-period,omitempty"`
	DisablePathMTUDiscovery bool  `mask:"disable-path-mtu-discovery,omitempty"`
	// MaxIncomingStreams is 8 at least.
	MaxIncomingStreams int64 `mask:"max-incoming-streams,omitempty"`
}

// Mask is a parsed xdns mask.
type Mask struct {
	mask.CarrierOnly
	domains   []*domain
	resolvers []resolverConfig
	extraPoll int

	// limit is the largest datagram the tunnel carries, which is what widest,
	// the domain with the longest query names, carries.
	limit        int
	widest       *domain
	warnTooLarge sync.Once
}

var _ mask.UDPCarrier = (*Mask)(nil)

// resolverConfig is one resolver address with the options of its entry.
type resolverConfig struct {
	scheme string // udp, tcp or https
	addr   string // host:port, or the URL of an https resolver
	// writeTimeout of a udp or tcp resolver, 0 for the default.
	writeTimeout time.Duration

	// of an https resolver
	worker int
	tls    *tls.Config

	// of an HTTP/3 resolver
	quic       *quic.Config
	congestion string
	bbrProfile string
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{extraPoll: options.ExtraPoll}
	for _, o := range options.Domains {
		for _, name := range o.Names {
			d, err := newDomain(name, o.LenLimit, o.LabelLimit, o.Types, o.EDNS0)
			if err != nil {
				return nil, fmt.Errorf("domain %q: %w", name, err)
			}
			m.domains = append(m.domains, d)
			if d.limit() > m.limit {
				m.limit, m.widest = d.limit(), d
			}
		}
	}
	for _, o := range options.Resolvers {
		for _, addr := range o.Addrs {
			rc, err := newResolverConfig(addr, o)
			if err != nil {
				return nil, fmt.Errorf("resolver %q: %w", addr, err)
			}
			m.resolvers = append(m.resolvers, rc)
		}
	}
	if len(m.domains) == 0 {
		return nil, errors.New("empty domains")
	}
	if len(m.resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}
	if m.extraPoll < 0 || m.extraPoll > 3 {
		return nil, errors.New("extra-poll must be within 0-3")
	}
	return m, nil
}

func newResolverConfig(addr string, o ResolverOptions) (resolverConfig, error) {
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return resolverConfig{}, err
	}
	if u.Hostname() == "" {
		return resolverConfig{}, errors.New("no host")
	}
	rc := resolverConfig{scheme: u.Scheme, worker: o.Worker}
	// The options of the entry are checked whatever the address is.
	if rc.worker == 0 {
		rc.worker = 32
	}
	if rc.worker < 1 {
		return resolverConfig{}, errors.New("invalid worker")
	}
	if rc.tls, err = o.TLSConfig.Config(u.Hostname()); err != nil {
		return resolverConfig{}, err
	}
	if len(rc.tls.NextProtos) == 0 {
		rc.tls.NextProtos = []string{"h2", "http/1.1"}
	}
	if rc.quic, err = o.QUICConfig.config(); err != nil {
		return resolverConfig{}, fmt.Errorf("quic-config: %w", err)
	}
	rc.congestion, rc.bbrProfile = strings.ToLower(o.QUICConfig.Congestion), strings.ToLower(o.QUICConfig.BBRProfile)

	switch u.Scheme {
	case "udp", "tcp":
		port := u.Port()
		if port == "" {
			port = "53"
		}
		rc.addr = net.JoinHostPort(u.Hostname(), port)
	case "https":
		rc.addr = u.String()
	default:
		return resolverConfig{}, errors.New("invalid protocol, want udp, tcp or https")
	}
	return rc, nil
}

// http3 tells whether an https resolver is reached over HTTP/3.
func (rc resolverConfig) http3() bool {
	return len(rc.tls.NextProtos) == 1 && rc.tls.NextProtos[0] == "h3"
}

// config checks the options, with the bounds Xray-core has, and returns the
// QUIC config they make.
func (o QUICOptions) config() (*quic.Config, error) {
	switch strings.ToLower(o.Congestion) {
	case "", "reno", "bbr":
	case "brutal", "force-brutal":
		return nil, fmt.Errorf("congestion %q is for a Hysteria server, a resolver takes reno or bbr", o.Congestion)
	default:
		return nil, fmt.Errorf("unknown congestion %q, valid values: reno, bbr", o.Congestion)
	}
	switch strings.ToLower(o.BBRProfile) {
	case "", "conservative", "standard", "aggressive":
	default:
		return nil, fmt.Errorf("unknown bbr-profile %q", o.BBRProfile)
	}
	for name, window := range map[string]int64{
		"init-stream-receive-window":     o.InitStreamReceiveWindow,
		"max-stream-receive-window":      o.MaxStreamReceiveWindow,
		"init-connection-receive-window": o.InitConnectionReceiveWindow,
		"max-connection-receive-window":  o.MaxConnectionReceiveWindow,
	} {
		if window < 0 || (window > 0 && window < 16384) {
			return nil, fmt.Errorf("%s must be at least 16384", name)
		}
	}
	if o.MaxIdleTimeout != 0 && (o.MaxIdleTimeout < 4 || o.MaxIdleTimeout > 120) {
		return nil, errors.New("max-idle-timeout must be between 4 and 120")
	}
	if o.KeepAlivePeriod != 0 && (o.KeepAlivePeriod < 2 || o.KeepAlivePeriod > 60) {
		return nil, errors.New("keep-alive-period must be between 2 and 60")
	}
	if o.MaxIncomingStreams != 0 && o.MaxIncomingStreams < 8 {
		return nil, errors.New("max-incoming-streams must be at least 8")
	}
	// What is 0 is left to the QUIC stack.
	return &quic.Config{
		InitialStreamReceiveWindow:     uint64(o.InitStreamReceiveWindow),
		MaxStreamReceiveWindow:         uint64(o.MaxStreamReceiveWindow),
		InitialConnectionReceiveWindow: uint64(o.InitConnectionReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(o.MaxConnectionReceiveWindow),
		MaxIdleTimeout:                 time.Duration(o.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(o.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        o.DisablePathMTUDiscovery || !probesPathMTU,
		MaxIncomingStreams:             o.MaxIncomingStreams,
	}, nil
}

// DialPacketConn opens the tunnel. dest, the address of the server, is only
// what the returned connection reports as its peer: the packets go to the
// resolvers.
func (m *Mask) DialPacketConn(ctx context.Context, dialer mask.Dialer, dest netip.AddrPort) (net.PacketConn, error) {
	return newConn(ctx, m, dialer, dest)
}
