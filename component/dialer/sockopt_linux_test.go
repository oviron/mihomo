//go:build linux

package dialer

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func dialWithSockopt(t *testing.T, sockopt Sockopt) (fd func(func(fd int))) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "tcp", l.Addr().String(), WithSockopt(sockopt))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	raw, err := conn.(syscall.Conn).SyscallConn()
	require.NoError(t, err)
	return func(f func(fd int)) {
		require.NoError(t, raw.Control(func(fd uintptr) { f(int(fd)) }))
	}
}

func getInt(t *testing.T, fd, level, opt int) int {
	t.Helper()
	v, err := unix.GetsockoptInt(fd, level, opt)
	require.NoError(t, err)
	return v
}

func TestSockopt(t *testing.T) {
	plain := dialWithSockopt(t, Sockopt{})
	var defaultMSS int
	plain(func(fd int) {
		defaultMSS = getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
		assert.Zero(t, getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT))
	})

	withFd := dialWithSockopt(t, Sockopt{
		TCPKeepAliveIdle:     33,
		TCPKeepAliveInterval: 7,
		TCPUserTimeout:       12345,
		TCPMaxSeg:            1000,
		TCPWindowClamp:       4096,
		TCPCongestion:        "reno",
	})
	withFd(func(fd int) {
		assert.Equal(t, 12345, getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT))
		mss := getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
		assert.LessOrEqual(t, mss, 1000)
		assert.Less(t, mss, defaultMSS)
		assert.Equal(t, 4096, getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP))
		congestion, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
		require.NoError(t, err)
		assert.Equal(t, "reno", congestion)
		assert.Equal(t, 1, getInt(t, fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE))
		assert.Equal(t, 33, getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE))
		assert.Equal(t, 7, getInt(t, fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL))
	})

	off := dialWithSockopt(t, Sockopt{TCPKeepAliveIdle: -1})
	off(func(fd int) {
		assert.Equal(t, 0, getInt(t, fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	})
}

func TestSockoptUnknownCongestion(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = DialContext(ctx, "tcp", l.Addr().String(), WithSockopt(Sockopt{TCPCongestion: "no-such-algorithm"}))
	require.ErrorContains(t, err, "TCP_CONGESTION")
}
