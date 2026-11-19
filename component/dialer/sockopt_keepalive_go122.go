//go:build !go1.23

package dialer

import (
	"net"
	"time"
)

// Before Go 1.23 a dialer has one keep-alive period for both the idle time
// and the interval; the interval is taken when both are set.
func (s Sockopt) setKeepAlive(dialer *net.Dialer) {
	switch {
	case s.TCPKeepAliveIdle < 0 || s.TCPKeepAliveInterval < 0:
		dialer.KeepAlive = -1
	case s.TCPKeepAliveInterval > 0:
		dialer.KeepAlive = time.Duration(s.TCPKeepAliveInterval) * time.Second
	case s.TCPKeepAliveIdle > 0:
		dialer.KeepAlive = time.Duration(s.TCPKeepAliveIdle) * time.Second
	}
}
