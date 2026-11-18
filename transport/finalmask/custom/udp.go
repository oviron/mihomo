package custom

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

const (
	// stateTTL is how long the variables captured with a peer, and in
	// standalone mode the handshake with it, stay valid.
	stateTTL = 5 * time.Second
	// The standalone handshake is sent up to probeCount times, probeInterval
	// apart, before the writes that wait for it fail.
	probeCount    = 6
	probeInterval = 500 * time.Millisecond
	// queueSize is how many datagrams the standalone reader holds for ReadFrom.
	queueSize = 16
)

// UDP is a parsed header-custom UDP mask.
type UDP struct {
	standalone bool
	client     []item
	server     []item
	clientSize int // prefix mode: the size of the header sent
	serverSize int // the size of the header, or of the handshake answer, received

	ttl           time.Duration // stateTTL
	probeInterval time.Duration
}

func (m *UDP) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	if m.standalone {
		return &standaloneConn{
			PacketConn: conn,
			mask:       m,
			done:       make(chan struct{}),
			queue:      make(chan datagram, queueSize),
			wake:       make(chan struct{}, 1),
			readLimit:  deadline.MakePipeDeadline(),
			writeLimit: deadline.MakePipeDeadline(),
			peers:      peers{m: map[string]*peer{}},
		}, nil
	}
	return &prefixConn{PacketConn: conn, mask: m, peers: peers{m: map[string]*peer{}}}, nil
}

// addrKey names a peer by the address datagrams are sent to and come from.
func addrKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// peer is what is kept for one remote address.
type peer struct {
	// vars are the variables the headers captured; in standalone mode, those
	// of the last handshake sent.
	vars map[string][]byte
	// expires is until when vars, and in standalone mode the handshake, are
	// good.
	expires time.Time
	attempt *attempt // standalone: the handshake under way
	// owed is how many answers of the server are still on their way: it
	// answers every datagram of a handshake, and the handshake ends with the
	// first answer.
	owed int
}

// peers holds the state per remote address. Entries that have expired are
// removed when the table is used, at most once per TTL, so that the peers
// that went away do not stay for as long as the socket is open.
type peers struct {
	m    map[string]*peer
	next time.Time // when to look for expired entries again
}

// get returns the entry of a peer, expired or not, or nil.
func (t *peers) get(key string, now time.Time, ttl time.Duration) *peer {
	if !now.Before(t.next) {
		t.next = now.Add(ttl)
		for k, p := range t.m {
			if p.attempt == nil && now.After(p.expires) {
				delete(t.m, k)
			}
		}
	}
	return t.m[key]
}

// prefixConn puts the client header in front of every datagram sent and
// expects the server header in front of every datagram received.
type prefixConn struct {
	net.PacketConn
	mask *UDP

	// writeMu makes the datagrams leave in the order their headers were
	// evaluated: the server answers to the variables of the last one it got.
	writeMu sync.Mutex

	mu    sync.Mutex
	peers peers
	last  map[string][]byte // the variables after the last datagram accepted, from any peer
}

// load returns the variables of a peer, nil when there are none or they are
// too old. The caller holds mu.
func (c *prefixConn) load(key string, now time.Time) map[string][]byte {
	if p := c.peers.get(key, now, c.mask.ttl); p != nil && !now.After(p.expires) {
		return p.vars
	}
	return nil
}

func (c *prefixConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > mask.BufferSize-c.mask.clientSize { // the header fits a datagram, see NewUDP
		return 0, fmt.Errorf("header-custom: a datagram of %d bytes is too large", len(p))
	}
	key, now := addrKey(addr), time.Now()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	vars := c.load(key, now)
	if vars == nil {
		vars = c.last
	}
	s := &scope{vars: cloneVars(vars), local: c.PacketConn.LocalAddr(), remote: addr}
	header, err := evalItems(c.mask.client, s)
	if err == nil && len(header) != c.mask.clientSize {
		err = fmt.Errorf("the header is %d bytes long, not %d", len(header), c.mask.clientSize)
	}
	if err == nil {
		c.peers.m[key] = &peer{vars: s.vars, expires: now.Add(c.mask.ttl)}
	}
	c.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("header-custom: client header: %w", err)
	}

	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	n := copy(buf, header)
	n += copy(buf[n:], p)
	if _, err = c.PacketConn.WriteTo(buf[:n], addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *prefixConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if err = c.accept(buf[:n], addr); err != nil {
			if log.Level() == log.DEBUG {
				log.Debugln("[finalmask] header-custom: drop a datagram of %d bytes from %v: %v", n, addr, err)
			}
			continue
		}
		return copy(p, buf[c.mask.serverSize:n]), addr, nil
	}
}

// accept checks the server header of a datagram against the variables of
// its sender and keeps what the header captured.
func (c *prefixConn) accept(data []byte, addr net.Addr) error {
	if len(data) < c.mask.serverSize {
		return fmt.Errorf("shorter than the server header")
	}
	key, now := addrKey(addr), time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &scope{vars: cloneVars(c.load(key, now))}
	if err := matchItems(c.mask.server, data, s); err != nil {
		return fmt.Errorf("server header: %w", err)
	}
	c.last = s.vars
	c.peers.m[key] = &peer{vars: s.vars, expires: now.Add(c.mask.ttl)}
	return nil
}

// standaloneConn leaves the datagrams as they are and, before data goes to a
// peer it has no fresh handshake with, sends the client header as a datagram
// of its own and waits for the server header to come back the same way.
//
// The socket is read by a goroutine, so that a handshake completes while
// nobody calls ReadFrom. Read deadlines are therefore kept here and never
// reach the socket.
type standaloneConn struct {
	net.PacketConn
	mask *UDP

	startOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{} // closed with the connection, or when the socket is gone
	err       error         // why, set before done is closed

	queue   chan datagram // from the reader to ReadFrom
	probing atomic.Int32  // handshakes under way
	wake    chan struct{} // tells the reader that a handshake has started

	readLimit, writeLimit deadline.PipeDeadline
	deadlineMu            sync.Mutex

	mu    sync.Mutex
	peers peers
}

// datagram is what the reader hands to ReadFrom: a datagram in a buffer of
// mask.GetBuffer, or an error of the socket.
type datagram struct {
	buf  []byte
	n    int
	addr net.Addr
	err  error
}

func (d datagram) release() {
	if d.buf != nil {
		mask.PutBuffer(d.buf)
	}
}

// attempt is one handshake with a peer: up to probeCount datagrams and the
// wait for the answer. All the writers that need the handshake while it runs
// share it and its outcome.
type attempt struct {
	done chan struct{} // closed when it is over
	err  error         // set before done is closed
}

func (c *standaloneConn) start() {
	c.startOnce.Do(func() { go c.readLoop() })
}

func (c *standaloneConn) shutdown(err error) {
	c.doneOnce.Do(func() {
		c.err = err
		close(c.done)
	})
}

func (c *standaloneConn) Close() error {
	c.shutdown(net.ErrClosed)
	c.readLimit.Set(time.Time{})
	c.writeLimit.Set(time.Time{})
	return c.PacketConn.Close()
}

func (c *standaloneConn) SetDeadline(t time.Time) error {
	c.readLimit.Set(t)
	return c.SetWriteDeadline(t)
}

func (c *standaloneConn) SetReadDeadline(t time.Time) error {
	c.readLimit.Set(t)
	return nil
}

// SetWriteDeadline bounds the socket and the wait for a handshake alike.
func (c *standaloneConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock() // the two are set together
	defer c.deadlineMu.Unlock()
	c.writeLimit.Set(t)
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *standaloneConn) readLoop() {
	// Nobody reads the queue once the connection is closed.
	defer func() {
		for {
			select {
			case d := <-c.queue:
				d.release()
			default:
				return
			}
		}
	}()
	for {
		buf := mask.GetBuffer()
		n, addr, err := c.PacketConn.ReadFrom(buf)
		d := datagram{buf: buf, n: n, addr: addr}
		select {
		case <-c.done:
			d.release()
			return
		default:
		}
		if err != nil {
			d.release()
			c.failHandshakes(err)
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				c.shutdown(err)
				return
			}
			// Any other error is handed to the reader like a datagram: on a
			// connected socket it may be an ICMP error that says nothing
			// about the datagrams to come.
			d = datagram{addr: addr, err: err}
		} else if c.answer(addr, buf[:n]) {
			d.release()
			continue
		}
		c.deliver(d)
	}
}

// deliver puts a datagram in the queue of ReadFrom. With the queue full the
// reader waits for room, leaving what comes next to the socket buffer, but
// not while a handshake is under way: its answer must not wait in the socket
// behind data that nobody reads. Then the datagram is dropped, as a full
// socket buffer would drop it.
func (c *standaloneConn) deliver(d datagram) {
	for c.probing.Load() == 0 {
		select {
		case c.queue <- d:
			return
		case <-c.done:
			d.release()
			return
		case <-c.wake:
		}
	}
	select {
	case c.queue <- d:
	default:
		d.release()
	}
}

// answer tells whether a datagram is the server header that answers a
// handshake sent to its sender, and completes the handshake if it is under
// way. The server answers every datagram of a handshake, so after it is
// complete as many more answers may come as there were more datagrams; those
// are not data either. Anything beyond that is, as in Xray-core: a server
// header may be one that every datagram of its size matches.
func (c *standaloneConn) answer(addr net.Addr, data []byte) bool {
	if len(data) != c.mask.serverSize {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.peers.m[addrKey(addr)]
	if p == nil || (p.attempt == nil && (p.owed <= 0 || now.After(p.expires))) {
		return false
	}
	if matchItems(c.mask.server, data, &scope{vars: cloneVars(p.vars)}) != nil {
		return false
	}
	p.owed--
	if p.attempt != nil {
		p.expires = now.Add(c.mask.ttl)
		c.settle(p, p.attempt, nil)
	}
	return true
}

// settle ends the handshake a of a peer, unless it is over already. The
// caller holds mu.
func (c *standaloneConn) settle(p *peer, a *attempt, err error) {
	if p.attempt != a {
		return
	}
	p.attempt = nil
	a.err = err
	close(a.done)
	c.probing.Add(-1)
}

func (c *standaloneConn) failHandshakes(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.peers.m {
		if p.attempt != nil {
			c.settle(p, p.attempt, err)
		}
	}
}

func (c *standaloneConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.start()
	timeout := c.readLimit.Wait()
	select {
	case <-c.done:
		return 0, nil, c.err
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case d := <-c.queue:
		if d.err != nil {
			return 0, d.addr, d.err
		}
		n := copy(p, d.buf[:d.n])
		d.release()
		return n, d.addr, nil
	case <-c.done:
		return 0, nil, c.err
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *standaloneConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.start()
	if err := c.handshake(addr); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

// handshake makes sure there is a fresh handshake with the peer at addr. It
// starts one if none is under way and waits for its outcome, for the write
// deadline or for Close. When the handshake fails, so do all the writes that
// waited for it; the next write starts another one.
func (c *standaloneConn) handshake(addr net.Addr) error {
	key, now := addrKey(addr), time.Now()
	c.mu.Lock()
	p := c.peers.get(key, now, c.mask.ttl)
	if p == nil {
		p = &peer{}
		c.peers.m[key] = p
	}
	a := p.attempt
	if a == nil && !now.After(p.expires) {
		c.mu.Unlock()
		return nil
	}
	timeout := c.writeLimit.Wait()
	if a == nil {
		var probe []byte
		var err error
		select {
		case <-c.done:
			err = c.err
		case <-timeout:
			err = os.ErrDeadlineExceeded
		default:
			s := &scope{vars: map[string][]byte{}, local: c.PacketConn.LocalAddr(), remote: addr}
			if probe, err = evalItems(c.mask.client, s); err == nil && len(probe) > maxDatagram {
				err = fmt.Errorf("it is %d bytes long, more than a UDP datagram carries", len(probe))
			}
			if err != nil {
				err = fmt.Errorf("header-custom: client header: %w", err)
			}
			p.vars = s.vars
		}
		if err != nil {
			c.mu.Unlock()
			return err
		}
		a = &attempt{done: make(chan struct{})}
		p.attempt = a
		p.owed = 0
		c.probing.Add(1)
		select {
		case c.wake <- struct{}{}:
		default:
		}
		go func() {
			err := c.probe(p, a, probe, addr)
			c.mu.Lock()
			c.settle(p, a, err)
			c.mu.Unlock()
		}()
	}
	c.mu.Unlock()

	select {
	case <-a.done:
		if a.err != nil {
			return fmt.Errorf("header-custom: handshake with %v: %w", addr, a.err)
		}
		return nil
	case <-c.done:
		return c.err
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

// probe sends the handshake datagram until the handshake is settled, the
// connection is closed or probeCount datagrams got no answer.
func (c *standaloneConn) probe(p *peer, a *attempt, probe []byte, addr net.Addr) error {
	interval := c.mask.probeInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for sent := 1; ; sent++ {
		// Not after the handshake is over: the datagram could mix with those
		// of the next one.
		c.mu.Lock()
		over := p.attempt != a
		if !over {
			p.owed++
		}
		c.mu.Unlock()
		if over {
			return nil
		}
		if _, err := c.PacketConn.WriteTo(probe, addr); err != nil {
			return err
		}
		select {
		case <-a.done:
			return nil
		case <-c.done:
			return c.err
		case <-timer.C:
		}
		if sent == probeCount {
			return fmt.Errorf("no answer in %v", probeCount*interval)
		}
		timer.Reset(interval)
	}
}
