//go:build linux || darwin

package xicmp

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const datagramSupported = true

// listenDatagram opens an unprivileged ICMP socket: a datagram socket that
// sends echo requests and receives their replies. The net package has no
// network name for it, so the socket is made by hand and control gets it
// before it is bound, as net.ListenConfig would do.
func listenDatagram(v6 bool, control func(conn syscall.RawConn) error) (net.PacketConn, error) {
	family, proto, local := unix.AF_INET, unix.IPPROTO_ICMP, unix.Sockaddr(&unix.SockaddrInet4{})
	if v6 {
		family, proto, local = unix.AF_INET6, unix.IPPROTO_ICMPV6, &unix.SockaddrInet6{}
	}
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	file := os.NewFile(uintptr(fd), "icmp")
	defer file.Close() // net.FilePacketConn works on a copy of the descriptor

	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err = control(conn); err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, local); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}
	return net.FilePacketConn(file)
}
