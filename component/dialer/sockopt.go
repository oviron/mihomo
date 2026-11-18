package dialer

import (
	"net"
	"strings"
)

// Sockopt holds the per-dialer TCP socket options that Xray-core has in the
// sockopt block of an outbound. The zero value changes nothing.
type Sockopt struct {
	// TCPKeepAliveIdle and TCPKeepAliveInterval are in seconds. A positive
	// value overrides the global keep-alive setting, a negative one in either
	// turns keep-alive off for the dialer.
	TCPKeepAliveIdle     int
	TCPKeepAliveInterval int
	// TCPUserTimeout is TCP_USER_TIMEOUT in milliseconds: how long sent data
	// may stay unacknowledged before the connection is dropped.
	TCPUserTimeout int
	// TCPMaxSeg is TCP_MAXSEG, the largest segment the connection sends and
	// announces.
	TCPMaxSeg int
	// TCPWindowClamp is TCP_WINDOW_CLAMP, the bound of the advertised window.
	TCPWindowClamp int
	// TCPCongestion is TCP_CONGESTION, the name of the congestion control.
	TCPCongestion string
	// AddressPortStrategy is one of the AddressPort constants, see address_port.go.
	AddressPortStrategy string
}

// WithSockopt sets the TCP socket options of the dialer.
func WithSockopt(sockopt Sockopt) Option {
	return func(opt *option) {
		opt.sockopt = sockopt
	}
}

// needsControl reports whether an option has to be set on the raw socket.
func (s Sockopt) needsControl() bool {
	return s.TCPUserTimeout > 0 || s.TCPMaxSeg > 0 || s.TCPWindowClamp > 0 || s.TCPCongestion != ""
}

// applyToDialer runs after the global keep-alive setting is in place.
func (s Sockopt) applyToDialer(dialer *net.Dialer, network string) {
	if !strings.HasPrefix(network, "tcp") {
		return
	}
	s.setKeepAlive(dialer)
	if s.needsControl() {
		addControlToDialer(dialer, s.control)
	}
}
