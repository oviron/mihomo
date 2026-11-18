// Package mask holds what the finalmask masks share: the interfaces the
// chain is built from, the registry and the helpers for decoding settings.
//
// Finalmask is the Xray-core feature of the same name
// (streamSettings.finalmask, Xray-core v26.11.9): a list of masks that change
// how the connection to the server looks on the wire. This package and its
// siblings implement the client side only.
package mask

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
)

// Dialer opens connections that bypass the masks. It is what the outbound
// would dial with if it had no finalmask.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

// TCPMask wraps the TCP connection to the server.
type TCPMask interface {
	WrapConn(conn net.Conn) (net.Conn, error)
}

// UDPMask wraps the UDP socket that talks to the server. dest is the server
// address, it is invalid when the caller did not name one.
type UDPMask interface {
	WrapPacketConn(conn net.PacketConn, dest netip.AddrPort) (net.PacketConn, error)
}

// UDPCarrier is a UDP mask that opens the underlying socket itself (HandleDial
// in Xray-core). It has to be the last mask of the list.
//
// The returned connection sends to the destination the carrier chose whatever
// address WriteTo is given, and reports dest as the source of every packet, so
// that the masks and the transport above it see one stable peer.
type UDPCarrier interface {
	DialPacketConn(ctx context.Context, dialer Dialer, dest netip.AddrPort) (net.PacketConn, error)
}

// TCPBuilder makes a TCP mask from its settings.
type TCPBuilder func(settings map[string]any) (TCPMask, error)

// UDPBuilder makes a UDP mask from its settings. A carrier is returned as a
// UDPMask that also implements UDPCarrier.
type UDPBuilder func(settings map[string]any) (UDPMask, error)

var (
	registryMu sync.RWMutex
	tcpMasks   = map[string]TCPBuilder{}
	udpMasks   = map[string]UDPBuilder{}
)

// RegisterTCP adds a TCP mask type.
func RegisterTCP(name string, builder TCPBuilder) {
	registryMu.Lock()
	defer registryMu.Unlock()
	tcpMasks[name] = builder
}

// RegisterUDP adds a UDP mask type.
func RegisterUDP(name string, builder UDPBuilder) {
	registryMu.Lock()
	defer registryMu.Unlock()
	udpMasks[name] = builder
}

// BuildTCP makes the TCP mask of the given type.
func BuildTCP(name string, settings map[string]any) (TCPMask, error) {
	registryMu.RLock()
	builder := tcpMasks[name]
	registryMu.RUnlock()
	if builder == nil {
		return nil, fmt.Errorf("unknown tcp mask %q (known: %v)", name, names(true))
	}
	return builder(settings)
}

// BuildUDP makes the UDP mask of the given type.
func BuildUDP(name string, settings map[string]any) (UDPMask, error) {
	registryMu.RLock()
	builder := udpMasks[name]
	registryMu.RUnlock()
	if builder == nil {
		return nil, fmt.Errorf("unknown udp mask %q (known: %v)", name, names(false))
	}
	return builder(settings)
}

func names(tcp bool) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var list []string
	if tcp {
		for name := range tcpMasks {
			list = append(list, name)
		}
	} else {
		for name := range udpMasks {
			list = append(list, name)
		}
	}
	sort.Strings(list)
	return list
}

// CarrierOnly is embedded by carriers to satisfy UDPMask.
type CarrierOnly struct{}

func (CarrierOnly) WrapPacketConn(net.PacketConn, netip.AddrPort) (net.PacketConn, error) {
	return nil, fmt.Errorf("the mask opens the socket itself and must be the last one in the list")
}
