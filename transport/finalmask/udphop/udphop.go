// Package udphop is the "udphop" UDP mask of Xray-core's finalmask: port
// hopping for any UDP transport. The client keeps changing the server port
// and address it sends to, the local socket it sends from, or both. The server
// needs no setting, only to listen on (or be forwarded) all the ports used.
package udphop

import (
	"context"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

func init() {
	mask.RegisterUDP("udphop", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// Mode is a comma separated list of:
	//   perConnRemote   pick the server address once per connection
	//   intervalRemote  pick a new server address every interval
	//   intervalLocal   open a new local socket every interval
	Mode string `mask:"mode,omitempty"`
	// Interval is the time between hops in seconds, 30 by default, 5 at least.
	Interval mask.Range `mask:"interval,omitempty"`
	// RemoteIPs are addresses or prefixes to pick the server address from,
	// RemotePorts ports and port ranges ("20000-30000,443"). An empty list
	// keeps that part of the server address.
	RemoteIPs   []string `mask:"remote-ips,omitempty"`
	RemotePorts string   `mask:"remote-ports,omitempty"`
}

// Mask is a parsed udphop mask.
type Mask struct {
	mask.CarrierOnly
	local       bool
	remote      bool
	remoteOnce  bool
	interval    mask.Range
	remoteIPs   []netip.Prefix
	remotePorts []uint16
	unit        time.Duration // of interval: a second, shorter in tests
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{interval: options.Interval, unit: time.Second}
	for _, mode := range strings.Split(options.Mode, ",") {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "intervallocal":
			m.local = true
		case "intervalremote":
			m.remote = true
		case "perconnremote":
			m.remoteOnce = true
		default:
			return nil, fmt.Errorf("invalid mode %q, want a list of intervalLocal, intervalRemote, perConnRemote", mode)
		}
	}
	if m.interval.From == 0 && m.interval.To == 0 {
		m.interval = mask.Range{From: 30, To: 30}
	}
	if m.interval.From < 5 {
		return nil, fmt.Errorf("interval must be at least 5")
	}
	for _, ip := range options.RemoteIPs {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			m.remoteIPs = append(m.remoteIPs, prefix)
		} else if addr, err := netip.ParseAddr(ip); err == nil {
			m.remoteIPs = append(m.remoteIPs, netip.PrefixFrom(addr, addr.BitLen()))
		} else {
			return nil, fmt.Errorf("invalid ip %q", ip)
		}
	}
	ports, err := parsePorts(options.RemotePorts)
	if err != nil {
		return nil, err
	}
	m.remotePorts = ports
	return m, nil
}

func parsePorts(list string) ([]uint16, error) {
	var ports []uint16
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		from, to := item, item
		if i := strings.Index(item, "-"); i >= 0 {
			from, to = strings.TrimSpace(item[:i]), strings.TrimSpace(item[i+1:])
		}
		first, err := strconv.ParseUint(from, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", item)
		}
		last, err := strconv.ParseUint(to, 10, 16)
		if err != nil || last < first {
			return nil, fmt.Errorf("invalid port range %q", item)
		}
		for port := first; port <= last; port++ {
			ports = append(ports, uint16(port))
		}
	}
	return ports, nil
}

// pick returns a server address: a random one from the lists, falling back to
// the parts of current for a list that is empty.
func (m *Mask) pick(current netip.AddrPort) netip.AddrPort {
	addr, port := current.Addr(), current.Port()
	if len(m.remoteIPs) > 0 {
		addr = randomAddr(m.remoteIPs[mrand.Intn(len(m.remoteIPs))])
	}
	if len(m.remotePorts) > 0 {
		port = m.remotePorts[mrand.Intn(len(m.remotePorts))]
	}
	return netip.AddrPortFrom(addr, port)
}

// randomAddr returns a random address inside the prefix.
func randomAddr(prefix netip.Prefix) netip.Addr {
	if prefix.IsSingleIP() {
		return prefix.Addr()
	}
	b := prefix.Addr().AsSlice()
	random := make([]byte, len(b))
	_, _ = rand.Read(random)
	i, j := prefix.Bits()/8, prefix.Bits()%8
	if i+1 < len(b) {
		copy(b[i+1:], random[i+1:])
	}
	keep := byte(0xff << (8 - j))
	b[i] = (b[i] & keep) | (random[i] &^ keep)
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

func (m *Mask) DialPacketConn(ctx context.Context, dialer mask.Dialer, dest netip.AddrPort) (net.PacketConn, error) {
	remote := dest
	if m.remote || m.remoteOnce {
		remote = m.pick(dest)
	}
	conn, err := dialer.ListenPacket(ctx, "udp", "", remote)
	if err != nil {
		return nil, err
	}
	c := &Conn{
		mask:    m,
		dialer:  dialer,
		logical: net.UDPAddrFromAddrPort(dest),
		cur:     newSocket(conn),
		remote:  remote,
		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}
	c.readDeadline.init()
	c.wg.Add(1)
	go c.recv(c.cur)
	if m.local || m.remote {
		go c.run()
	}
	return c, nil
}

type packet struct {
	buf []byte // from mask.GetBuffer
	n   int
}

// socket is one local socket of the connection. done is closed with it, to
// release its reader when nobody reads the connection.
type socket struct {
	net.PacketConn
	done chan struct{}
}

func newSocket(conn net.PacketConn) *socket {
	return &socket{PacketConn: conn, done: make(chan struct{})}
}

func (s *socket) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.PacketConn.Close()
}

// system tells whether it is a socket of the OS, which can send to any
// address. One that goes through another proxy may be bound to the address
// it was opened for.
func (s *socket) system() bool {
	_, ok := s.PacketConn.(syscall.Conn)
	return ok
}

// Conn is the hopping connection. It sends to the current server address
// whatever address it is given and reports the address it was created for as
// the source of every packet.
type Conn struct {
	mask    *Mask
	dialer  mask.Dialer
	logical *net.UDPAddr

	mu            sync.RWMutex
	pre           *socket // the previous socket, still read for one interval
	cur           *socket
	remote        netip.AddrPort
	writeDeadline time.Time
	readBuffer    int // what the sockets were asked to be sized to
	writeBuffer   int

	readDeadline deadline
	readCh       chan packet
	closeCh      chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
}

func (c *Conn) run() {
	next := func() time.Duration {
		return time.Duration(mask.RandBetween(int64(c.mask.interval.From), int64(c.mask.interval.To)+1)) * c.mask.unit
	}
	timer := time.NewTimer(next())
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-timer.C:
			c.hop()
			timer.Reset(next())
		}
	}
}

func (c *Conn) hop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closeCh:
		return
	default:
	}
	remote := c.remote
	if c.mask.remote {
		remote = c.mask.pick(remote)
	}
	if c.mask.local || (remote != c.remote && !c.cur.system()) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := c.dialer.ListenPacket(ctx, "udp", "", remote)
		cancel()
		if err != nil {
			log.Debugln("[finalmask] udphop: can't open a new socket, staying on the old one: %v", err)
			return
		}
		next := newSocket(conn)
		_ = next.SetWriteDeadline(c.writeDeadline)
		setBuffers(next, c.readBuffer, c.writeBuffer)
		if c.pre != nil {
			_ = c.pre.Close()
		}
		c.pre = c.cur
		c.cur = next
		c.wg.Add(1)
		go c.recv(next)
	}
	c.remote = remote
}

func setBuffers(conn net.PacketConn, read, write int) {
	if s, ok := conn.(interface{ SetReadBuffer(int) error }); ok && read > 0 {
		_ = s.SetReadBuffer(read)
	}
	if s, ok := conn.(interface{ SetWriteBuffer(int) error }); ok && write > 0 {
		_ = s.SetWriteBuffer(write)
	}
}

func (c *Conn) recv(s *socket) {
	defer c.wg.Done()
	for {
		buf := mask.GetBuffer()
		n, _, err := s.ReadFrom(buf)
		if err != nil {
			mask.PutBuffer(buf)
			return // the socket was closed: by a hop or with the connection
		}
		select {
		case c.readCh <- packet{buf: buf, n: n}:
		case <-s.done:
			mask.PutBuffer(buf)
			return
		case <-c.closeCh:
			mask.PutBuffer(buf)
			return
		}
	}
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	expired := c.readDeadline.wait()
	select {
	case <-expired: // also when a packet is ready
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case pkt := <-c.readCh:
		n := copy(p, pkt.buf[:pkt.n])
		mask.PutBuffer(pkt.buf)
		return n, c.logical, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	case <-expired:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	// The lock is not held while writing: Close and SetWriteDeadline must be
	// able to interrupt a write that blocks.
	c.mu.RLock()
	cur, remote := c.cur, c.remote
	c.mu.RUnlock()
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
	}
	if _, err := cur.WriteTo(p, net.UDPAddrFromAddrPort(remote)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		close(c.closeCh)
		if c.pre != nil {
			_ = c.pre.Close()
		}
		_ = c.cur.Close()
		c.mu.Unlock()
		c.wg.Wait()
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cur.LocalAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline is kept by the connection itself: the sockets come and go.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return c.cur.SetWriteDeadline(t)
}

// SetReadBuffer and SetWriteBuffer size the current socket and the ones that
// come after it.
func (c *Conn) SetReadBuffer(bytes int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readBuffer = bytes
	setBuffers(c.cur, bytes, 0)
	return nil
}

func (c *Conn) SetWriteBuffer(bytes int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeBuffer = bytes
	setBuffers(c.cur, 0, bytes)
	return nil
}

// deadline is a read deadline that can be changed while a read waits on it.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // closed when the deadline has passed
}

func (d *deadline) init() {
	d.cancel = make(chan struct{})
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired, wait for it to close the channel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
