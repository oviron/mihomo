//go:build !linux

package dialer

import (
	"context"
	"syscall"
)

// SockoptSupported reports whether the options that are set on the raw
// socket work on this system. They are Linux socket options.
const SockoptSupported = false

func (s Sockopt) control(ctx context.Context, network, address string, c syscall.RawConn) error {
	return nil
}
