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
}

// appendTo adds the socket options to the options of a dialer.
func (s Sockopt) appendTo(opts []dialer.Option) []dialer.Option {
	if s == (Sockopt{}) {
		return opts
	}
	if !dialer.SockoptSupported && (s.TCPUserTimeout > 0 || s.TCPMaxSeg > 0 || s.TCPWindowClamp > 0 || s.TCPCongestion != "") {
		log.Warnln("sockopt: tcp-user-timeout, tcp-max-seg, tcp-window-clamp and tcp-congestion are Linux socket options, ignored on %s", runtime.GOOS)
	}
	return append(opts[:len(opts):len(opts)], dialer.WithSockopt(dialer.Sockopt{
		TCPKeepAliveIdle:     s.TCPKeepAliveIdle,
		TCPKeepAliveInterval: s.TCPKeepAliveInterval,
		TCPUserTimeout:       s.TCPUserTimeout,
		TCPMaxSeg:            s.TCPMaxSeg,
		TCPWindowClamp:       s.TCPWindowClamp,
		TCPCongestion:        s.TCPCongestion,
	}))
}
