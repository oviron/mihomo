// Package xicmp is the "xicmp" UDP mask of Xray-core's finalmask: it carries
// the datagrams of the transport above it inside ICMP echo ("ping") messages.
//
// The client sends echo requests whose data is an 8 byte random client id
// followed by the datagram. The server answers with echo replies whose data is
// the bare datagram, reusing the identifier and the sequence number of the
// last request it got from that client, so that the reply passes the NAT
// entry the request created. A host that is being pinged also answers by
// itself with a copy of the request; such replies start with the client id
// and are dropped.
//
// The mask opens ICMP sockets instead of a UDP one, so it has to be the last
// of the list. By default these are raw sockets, which need root or
// CAP_NET_RAW (administrator rights on Windows). With dgram they are the
// unprivileged ICMP datagram sockets of Linux, Android and macOS; on Linux the
// group of the process has to be within the net.ipv4.ping_group_range sysctl.
// The sockets are bound to the outbound interface, marked or protected from
// the VPN the same way as the ping sockets of the tun inbound. They are not
// opened by the dialer of the proxy, so the proxy can't have a dialer-proxy,
// an interface-name or a routing-mark of its own.
package xicmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/sing/common/pipe"
)

func init() {
	mask.RegisterUDP("xicmp", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

const (
	headerSize   = 8 // type, code, checksum, identifier, sequence number
	clientIDSize = 8

	// MaxPayload is the largest datagram the mask carries; a larger one is
	// dropped. Xray-core limits the ICMP message of either side to 4096 bytes.
	MaxPayload = 4096 - headerSize - clientIDSize

	typeEchoRequest4 = 8
	typeEchoReply4   = 0
	typeEchoRequest6 = 128
	typeEchoReply6   = 129
)

// kernelOwnsID tells that an ICMP datagram socket has an identifier of its
// own: Linux writes it over the one of every request sent and delivers only
// the replies that carry it. macOS sends the identifier it is given and
// delivers the replies to every ICMP socket, as raw sockets do everywhere.
const kernelOwnsID = runtime.GOOS == "linux" || runtime.GOOS == "android"

// datagramHasIPHeader tells that an IPv4 ICMP datagram socket returns the
// messages together with their IP header, which macOS does.
const datagramHasIPHeader = runtime.GOOS == "darwin" || runtime.GOOS == "ios"

// Options are the settings of the mask.
type Options struct {
	// DGRAM uses the unprivileged ICMP datagram sockets instead of raw ones.
	DGRAM bool `mask:"dgram,omitempty"`
	// IPs are the addresses to send to, one is picked for every packet. The
	// server address is used when the list is empty.
	IPs []string `mask:"ips,omitempty"`
}

// Mask is a parsed xicmp mask.
type Mask struct {
	mask.CarrierOnly
	dgram bool
	ips   []netip.Addr
}

var _ mask.UDPCarrier = (*Mask)(nil)

// DirectOnly: the ICMP sockets are not opened by the dialer of the proxy.
func (*Mask) DirectOnly() {}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	if options.DGRAM && !datagramSupported {
		return nil, fmt.Errorf("dgram: ICMP datagram sockets are not supported on %s", runtime.GOOS)
	}
	m := &Mask{dgram: options.DGRAM}
	for _, text := range options.IPs {
		ip, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("ips: %w", err)
		}
		m.ips = append(m.ips, ip.Unmap())
	}
	return m, nil
}

// DialPacketConn opens the ICMP sockets, one for each address family among
// the addresses to send to. The dialer is not used: it cannot open them.
func (m *Mask) DialPacketConn(ctx context.Context, _ mask.Dialer, dest netip.AddrPort) (net.PacketConn, error) {
	ips := m.ips
	if len(ips) == 0 {
		if !dest.Addr().IsValid() {
			return nil, errors.New("xicmp: no address to send to")
		}
		ips = []netip.Addr{dest.Addr().Unmap()}
	}
	c := &Conn{
		dest:         net.UDPAddrFromAddrPort(dest),
		id:           uint16(mrand.Intn(1 << 16)),
		checkID:      !(m.dgram && kernelOwnsID),
		readCh:       make(chan packet),
		closeCh:      make(chan struct{}),
		readDeadline: pipe.MakeDeadline(),
	}
	_, _ = rand.Read(c.clientID[:])
	for _, ip := range ips {
		family := 0
		if ip.Is6() {
			family = 1
		}
		if c.sockets[family] == nil {
			socket, err := m.listen(ctx, ip)
			if err != nil {
				c.closeSockets()
				return nil, fmt.Errorf("xicmp: open the ICMP socket for %s: %w", ip, err)
			}
			c.sockets[family] = socket
		}
		var addr net.Addr = &net.IPAddr{IP: ip.AsSlice(), Zone: ip.Zone()}
		if m.dgram {
			addr = &net.UDPAddr{IP: ip.AsSlice(), Zone: ip.Zone()}
		}
		c.targets = append(c.targets, target{addr: addr, family: family})
	}
	for family, socket := range c.sockets {
		if socket != nil {
			c.wg.Add(1)
			go c.receive(socket, family == 1, m.dgram && datagramHasIPHeader && family == 0)
		}
	}
	return c, nil
}

// listen opens the socket that reaches ip.
func (m *Mask) listen(ctx context.Context, ip netip.Addr) (net.PacketConn, error) {
	network, listenNetwork, address := "ip4", "ip4:1", "0.0.0.0"
	if ip.Is6() {
		network, listenNetwork, address = "ip6", "ip6:58", "::"
	}
	// The control function gets the network name net.ListenConfig gives for a
	// raw socket and the destination in the form the other sockets of an
	// outbound have it, which is what the interface binding looks at.
	icmpControl := dialer.ICMPControl(ip)
	control := func(conn syscall.RawConn) error {
		return icmpControl(network, netip.AddrPortFrom(ip, 0).String(), conn)
	}
	if m.dgram {
		return listenDatagram(ip.Is6(), control)
	}
	lc := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		return control(conn)
	}}
	return lc.ListenPacket(ctx, listenNetwork, address)
}

type target struct {
	addr   net.Addr // *net.UDPAddr for a datagram socket, *net.IPAddr for a raw one
	family int      // index of the socket: 0 is IPv4, 1 is IPv6
}

type packet struct {
	buf  []byte // from mask.GetBuffer
	data []byte // the datagram, a part of buf
}

// Conn is the tunnel: a packet connection over ICMP echo messages.
type Conn struct {
	dest     net.Addr
	targets  []target
	sockets  [2]net.PacketConn // IPv4 and IPv6, nil when no target needs it
	clientID [clientIDSize]byte
	id       uint16
	checkID  bool
	seq      atomic.Uint32

	readCh       chan packet
	readDeadline pipe.Deadline

	closeOnce sync.Once
	closeCh   chan struct{}
	closeErr  error // set before closeCh is closed
	wg        sync.WaitGroup
}

// receive hands the datagrams of the echo replies a socket gets to ReadFrom.
func (c *Conn) receive(socket net.PacketConn, v6, ipHeader bool) {
	defer c.wg.Done()
	buf := mask.GetBuffer()
	defer func() { mask.PutBuffer(buf) }()
	for {
		n, _, err := socket.ReadFrom(buf)
		if err != nil {
			c.shutdown(err)
			return
		}
		message := buf[:n]
		if ipHeader {
			message = stripIPv4Header(message)
		}
		data, ok := c.accept(message, v6)
		if !ok {
			continue
		}
		select {
		case c.readCh <- packet{buf: buf, data: data}:
			buf = mask.GetBuffer()
		case <-c.closeCh:
			return
		}
	}
}

// accept returns the datagram of an ICMP message if it is an echo reply of
// the server to this client.
func (c *Conn) accept(message []byte, v6 bool) ([]byte, bool) {
	id, data, ok := parseEchoReply(message, v6)
	if !ok || c.checkID && id != c.id {
		return nil, false
	}
	// what the pinged host answered by itself
	if len(data) >= clientIDSize && bytes.Equal(data[:clientIDSize], c.clientID[:]) {
		return nil, false
	}
	return data, true
}

// ReadFrom returns the next datagram of the server. The source is always the
// server address the connection was opened for.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closeCh:
		return 0, nil, c.closeErr
	default:
	}
	select {
	case pkt := <-c.readCh:
		n := copy(p, pkt.data)
		mask.PutBuffer(pkt.buf)
		return n, c.dest, nil
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closeCh:
		return 0, nil, c.closeErr
	}
}

// WriteTo sends p in an echo request to the server address or to one of the
// configured addresses, whatever addr is. A datagram above MaxPayload is an
// error; Xray-core drops it without one.
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > MaxPayload {
		return 0, fmt.Errorf("xicmp: datagram of %d bytes is too large, the limit is %d", len(p), MaxPayload)
	}
	to := c.targets[0]
	if len(c.targets) > 1 {
		to = c.targets[mrand.Intn(len(c.targets))]
	}
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	message := appendEchoRequest(buf[:0], to.family == 1, c.id, uint16(c.seq.Add(1)), c.clientID, p)
	if _, err := c.sockets[to.family].WriteTo(message, to.addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// shutdown closes the sockets, which stops the receivers, and makes ReadFrom
// return err.
func (c *Conn) shutdown(err error) {
	c.closeOnce.Do(func() {
		c.closeErr = err
		close(c.closeCh)
		c.closeSockets()
	})
}

func (c *Conn) closeSockets() {
	for _, socket := range c.sockets {
		if socket != nil {
			_ = socket.Close()
		}
	}
}

func (c *Conn) Close() error {
	c.shutdown(net.ErrClosed)
	c.wg.Wait()
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if socket != nil {
			_ = socket.SetWriteDeadline(t)
		}
	}
	return nil
}

// SetReadBuffer sizes the receive buffer of the sockets. QUIC asks for a
// large one.
func (c *Conn) SetReadBuffer(bytes int) error {
	return c.setBuffer(func(socket socketBuffers) error { return socket.SetReadBuffer(bytes) })
}

// SetWriteBuffer sizes the send buffer of the sockets.
func (c *Conn) SetWriteBuffer(bytes int) error {
	return c.setBuffer(func(socket socketBuffers) error { return socket.SetWriteBuffer(bytes) })
}

type socketBuffers interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

func (c *Conn) setBuffer(set func(socketBuffers) error) error {
	var firstErr error
	for _, socket := range c.sockets {
		if s, ok := socket.(socketBuffers); ok {
			if err := set(s); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// appendEchoRequest appends the echo request that carries payload to b.
//
// The ICMPv4 checksum is filled in: a raw socket and the datagram socket of
// macOS send it as it is, the datagram socket of Linux computes it again. The
// ICMPv6 checksum covers the addresses of the IP header and is left to the
// kernel, which computes it for both kinds of ICMPv6 socket.
func appendEchoRequest(b []byte, v6 bool, id, seq uint16, clientID [clientIDSize]byte, payload []byte) []byte {
	start := len(b)
	typ := byte(typeEchoRequest4)
	if v6 {
		typ = typeEchoRequest6
	}
	b = append(b, typ, 0, 0, 0, byte(id>>8), byte(id), byte(seq>>8), byte(seq))
	b = append(b, clientID[:]...)
	b = append(b, payload...)
	if !v6 {
		binary.BigEndian.PutUint16(b[start+2:], checksum(b[start:]))
	}
	return b
}

// parseEchoReply returns the identifier and the data of an echo reply.
func parseEchoReply(message []byte, v6 bool) (id uint16, data []byte, ok bool) {
	typ := byte(typeEchoReply4)
	if v6 {
		typ = typeEchoReply6
	}
	if len(message) < headerSize || message[0] != typ {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(message[4:]), message[headerSize:], true
}

// checksum is the Internet checksum (RFC 1071) of b.
func checksum(b []byte) uint16 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// stripIPv4Header returns the payload of an IPv4 packet, or b when it does
// not start with an IPv4 header.
func stripIPv4Header(b []byte) []byte {
	if len(b) < 20 || b[0]>>4 != 4 {
		return b
	}
	if l := int(b[0]&0x0f) * 4; l >= 20 && l <= len(b) {
		return b[l:]
	}
	return b
}
