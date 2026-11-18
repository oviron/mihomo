//go:build go1.23

package dialer

import (
	"net"
	"time"
)

func (s Sockopt) setKeepAlive(dialer *net.Dialer) {
	switch {
	case s.TCPKeepAliveIdle < 0 || s.TCPKeepAliveInterval < 0:
		dialer.KeepAlive = -1
		dialer.KeepAliveConfig.Enable = false
	case s.TCPKeepAliveIdle > 0 || s.TCPKeepAliveInterval > 0:
		dialer.KeepAlive = 0
		dialer.KeepAliveConfig.Enable = true
		if s.TCPKeepAliveIdle > 0 {
			dialer.KeepAliveConfig.Idle = time.Duration(s.TCPKeepAliveIdle) * time.Second
		}
		if s.TCPKeepAliveInterval > 0 {
			dialer.KeepAliveConfig.Interval = time.Duration(s.TCPKeepAliveInterval) * time.Second
		}
	}
}
