//go:build !linux && !darwin

package xicmp

import (
	"errors"
	"net"
	"syscall"
)

// Only Linux, Android and macOS have ICMP datagram sockets; New rejects the
// dgram setting elsewhere.
const datagramSupported = false

func listenDatagram(bool, func(conn syscall.RawConn) error) (net.PacketConn, error) {
	return nil, errors.New("ICMP datagram sockets are not supported on this system")
}
