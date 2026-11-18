//go:build linux

package dialer

import (
	"context"
	"syscall"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

// SockoptSupported reports whether the options that are set on the raw
// socket work on this system.
const SockoptSupported = true

// control sets the options on the socket. Like Xray-core it carries on when
// one of them is refused, as TCP_MAXSEG is on an MPTCP socket: an error here
// would fail the dial, or make Go fall back from MPTCP to TCP.
func (s Sockopt) control(ctx context.Context, network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		set := func(name string, err error) {
			if err != nil {
				log.Warnln("[Dialer] sockopt: set %s for %s: %v", name, address, err)
			}
		}
		// the segment size first: it is fixed once the connection is set up
		if s.TCPMaxSeg > 0 {
			set("TCP_MAXSEG", unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, s.TCPMaxSeg))
		}
		if s.TCPWindowClamp > 0 {
			set("TCP_WINDOW_CLAMP", unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, s.TCPWindowClamp))
		}
		if s.TCPUserTimeout > 0 {
			set("TCP_USER_TIMEOUT", unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, s.TCPUserTimeout))
		}
		if s.TCPCongestion != "" {
			set("TCP_CONGESTION", unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, s.TCPCongestion))
		}
	})
}
