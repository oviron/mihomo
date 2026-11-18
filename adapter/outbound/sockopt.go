package outbound

import (
	"runtime"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
)

// Sockopt is the `sockopt` block of a proxy: the TCP socket options of the
// connection to the server, named after the sockopt keys of an Xray-core
// outbound. They do not apply to a proxy that dials through a dialer-proxy,
// whose socket belongs to that proxy.
type Sockopt struct {
	TCPKeepAliveIdle     int    `proxy:"tcp-keep-alive-idle,omitempty"`     // seconds, negative turns keep-alive off
	TCPKeepAliveInterval int    `proxy:"tcp-keep-alive-interval,omitempty"` // seconds, negative turns keep-alive off
	TCPUserTimeout       int    `proxy:"tcp-user-timeout,omitempty"`        // milliseconds
	TCPMaxSeg            int    `proxy:"tcp-max-seg,omitempty"`
	TCPWindowClamp       int    `proxy:"tcp-window-clamp,omitempty"`
	TCPCongestion        string `proxy:"tcp-congestion,omitempty"`
	// AddressPortStrategy takes the address and the port of the server from a
	// DNS record of the server name: srvportonly, srvaddressonly,
	// srvportandaddress (server is _service._proto.example.org) or txtportonly,
	// txtaddressonly, txtportandaddress (a TXT record "host:port"). It covers
	// what is dialed by name, the TCP transports and mKCP, not the QUIC ones.
	AddressPortStrategy string `proxy:"address-port-strategy,omitempty"`
}

// quicDialOptions are the dial options of the proxy for a QUIC connection its
// transport opens by itself, with the address-port-strategy of the proxy.
func (b *BasicOption) quicDialOptions(base *Base) []dialer.Option {
	return b.dialSockopt().appendTo(base.DialOptions())
}

// dialSockopt is the sockopt block for the sockets this proxy opens itself:
// none with a dialer-proxy, whose sockets and addresses are that proxy's.
func (b *BasicOption) dialSockopt() Sockopt {
	if b.DialerProxy != "" {
		return Sockopt{}
	}
	return b.Sockopt
}

// appendTo adds the socket options to the options of a dialer.
func (s Sockopt) appendTo(opts []dialer.Option) []dialer.Option {
	if s == (Sockopt{}) {
		return opts
	}
	if !dialer.SockoptSupported && (s.TCPUserTimeout > 0 || s.TCPMaxSeg > 0 || s.TCPWindowClamp > 0 || s.TCPCongestion != "") {
		log.Warnln("sockopt: tcp-user-timeout, tcp-max-seg, tcp-window-clamp and tcp-congestion are Linux socket options, ignored on %s", runtime.GOOS)
	}
	strategy, err := dialer.ParseAddressPortStrategy(s.AddressPortStrategy)
	if err != nil {
		log.Warnln("sockopt: %v, ignored", err)
	}
	return append(opts[:len(opts):len(opts)], dialer.WithSockopt(dialer.Sockopt{
		AddressPortStrategy:  strategy,
		TCPKeepAliveIdle:     s.TCPKeepAliveIdle,
		TCPKeepAliveInterval: s.TCPKeepAliveInterval,
		TCPUserTimeout:       s.TCPUserTimeout,
		TCPMaxSeg:            s.TCPMaxSeg,
		TCPWindowClamp:       s.TCPWindowClamp,
		TCPCongestion:        s.TCPCongestion,
	}))
}
