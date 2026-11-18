//go:build linux

package dialer

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SockoptSupported reports whether the options that are set on the raw
// socket work on this system.
const SockoptSupported = true

func (s Sockopt) control(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
	controlErr := c.Control(func(fd uintptr) {
		// the segment size first: it is fixed once the connection is set up
		if s.TCPMaxSeg > 0 {
			if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, s.TCPMaxSeg); err != nil {
				err = fmt.Errorf("set TCP_MAXSEG: %w", err)
				return
			}
		}
		if s.TCPWindowClamp > 0 {
			if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, s.TCPWindowClamp); err != nil {
				err = fmt.Errorf("set TCP_WINDOW_CLAMP: %w", err)
				return
			}
		}
		if s.TCPUserTimeout > 0 {
			if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, s.TCPUserTimeout); err != nil {
				err = fmt.Errorf("set TCP_USER_TIMEOUT: %w", err)
				return
			}
		}
		if s.TCPCongestion != "" {
			if err = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, s.TCPCongestion); err != nil {
				err = fmt.Errorf("set TCP_CONGESTION %s: %w", s.TCPCongestion, err)
				return
			}
		}
	})
	if controlErr != nil {
		return controlErr
	}
	return err
}
