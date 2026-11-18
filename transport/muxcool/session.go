package muxcool

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/common/pool"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	// A stream session buffers this much unread data before its carrier
	// stops reading; Mux.Cool has no other backpressure.
	streamBuffer = 256 * 1024
	// A UDP session drops packets beyond this many unread ones.
	packetBuffer = 256
)

// Xray-core closes a carrier that had no session for this long.
var idleInterval = 16 * time.Second

// A frame that cannot be written for this long means a dead carrier. The peer
// may stop reading for a while, when one of its sessions cannot get rid of
// its data, but it does not for that long.
var writeTimeout = 60 * time.Second

var (
	// ErrCarrierFull is returned when a carrier takes no more sessions.
	ErrCarrierFull = errors.New("muxcool: carrier is full")
	// ErrSessionClosed is returned by a session the peer has ended with an error.
	ErrSessionClosed = errors.New("muxcool: session closed by peer")
	// ErrPacketTooLarge is returned for a packet longer than MaxPayload.
	ErrPacketTooLarge = errors.New("muxcool: packet too large")
)

// Limits bound the sessions of one carrier.
type Limits struct {
	// MaxConcurrency is the number of sessions open at once, 0 for no limit.
	MaxConcurrency int
	// MaxSessions is the number of sessions over the life of the carrier,
	// 0 for no limit. Xray-core uses 1024.
	MaxSessions int
}

// Carrier runs Mux.Cool over one connection and opens sessions on it.
type Carrier struct {
	conn   net.Conn
	limits Limits

	writeMu sync.Mutex // one frame at a time

	mu       sync.Mutex
	sessions map[uint16]*session
	count    int  // sessions opened so far, the last session ID
	retired  bool // idle, about to close
	err      error
	done     chan struct{}
}

// NewCarrier starts Mux.Cool on conn, which must already be addressed to
// Destination. The carrier owns conn and closes it.
func NewCarrier(conn net.Conn, limits Limits) *Carrier {
	c := &Carrier{
		conn:     conn,
		limits:   limits,
		sessions: make(map[uint16]*session),
		done:     make(chan struct{}),
	}
	go c.readLoop()
	go c.idleLoop()
	return c
}

// Done is closed when the carrier is closed.
func (c *Carrier) Done() <-chan struct{} {
	return c.done
}

// Closed reports whether the carrier is closed.
func (c *Carrier) Closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Sessions returns the number of open sessions.
func (c *Carrier) Sessions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

// Full reports whether the carrier takes no more sessions.
func (c *Carrier) Full() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.full()
}

func (c *Carrier) full() bool {
	return c.err != nil || c.retired ||
		(c.limits.MaxConcurrency > 0 && len(c.sessions) >= c.limits.MaxConcurrency) ||
		(c.limits.MaxSessions > 0 && c.count >= c.limits.MaxSessions) ||
		c.count >= 0xffff
}

// Close closes the carrier and all its sessions.
func (c *Carrier) Close() error {
	c.closeWithError(net.ErrClosed)
	return nil
}

func (c *Carrier) closeWithError(err error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = err
	sessions := c.sessions
	c.sessions = nil
	close(c.done)
	c.mu.Unlock()

	_ = c.conn.Close()
	for _, s := range sessions {
		s.abort(err)
	}
}

func (c *Carrier) open(network Network, destination M.Socksaddr, globalID [8]byte) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.full() {
		if c.err != nil {
			return nil, c.err
		}
		return nil, ErrCarrierFull
	}
	c.count++
	s := &session{
		carrier:     c,
		id:          uint16(c.count),
		network:     network,
		destination: destination,
		globalID:    globalID,
		readable:    make(chan struct{}, 1),
		writable:    make(chan struct{}, 1),
		failed:      make(chan struct{}),
		closed:      make(chan struct{}),
	}
	c.sessions[s.id] = s
	return s, nil
}

// OpenStream opens a TCP session to destination. Nothing is sent before the
// first Write or Read of the connection, so the first Write travels with the
// request.
func (c *Carrier) OpenStream(destination M.Socksaddr) (net.Conn, error) {
	s, err := c.open(NetworkTCP, destination, [8]byte{})
	if err != nil {
		return nil, err
	}
	return &streamConn{session: s, deadline: deadline.MakePipeDeadline()}, nil
}

// OpenPacket opens a UDP session. destination is the address of the first
// packet as far as the peer's routing is concerned; every packet names its
// own address. A non-zero globalID makes it an XUDP session, which the peer
// keeps across carriers.
func (c *Carrier) OpenPacket(destination M.Socksaddr, globalID [8]byte) (net.PacketConn, error) {
	s, err := c.open(NetworkUDP, destination, globalID)
	if err != nil {
		return nil, err
	}
	return &packetConn{session: s, deadline: deadline.MakePipeDeadline()}, nil
}

func (c *Carrier) remove(id uint16) {
	c.mu.Lock()
	delete(c.sessions, id)
	c.mu.Unlock()
}

func (c *Carrier) lookup(id uint16) *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[id]
}

// writeFrame writes one frame: the header of meta and the payload.
func (c *Carrier) writeFrame(meta *Metadata, payload []byte) error {
	frame := pool.Get(2 + maxMetadata + 2 + len(payload))
	defer pool.Put(frame)
	b, err := meta.Append(frame[:0], len(payload))
	if err != nil {
		return err
	}
	b = append(b, payload...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err = c.conn.Write(b); err != nil {
		c.closeWithError(err)
	}
	return err
}

func (c *Carrier) readLoop() {
	reader := bufio.NewReaderSize(c.conn, 16*1024)
	for {
		if err := c.readFrame(reader); err != nil {
			c.closeWithError(err)
			return
		}
	}
}

func (c *Carrier) readFrame(reader *bufio.Reader) error {
	meta, err := ReadMetadata(reader, false)
	if err != nil {
		return err
	}
	if meta.Status < StatusNew || meta.Status > StatusKeepAlive {
		return errors.New("muxcool: unknown session status")
	}

	payloadLen := 0
	if meta.HasData() {
		if payloadLen, err = ReadPayloadLen(reader); err != nil {
			return err
		}
	}
	var s *session
	switch meta.Status {
	case StatusKeep:
		s = c.lookup(meta.SessionID)
	case StatusEnd:
		if s := c.lookup(meta.SessionID); s != nil {
			s.end(meta.HasError())
		}
	}
	if !meta.HasData() {
		return nil
	}
	if s == nil {
		// New and keep-alive frames carry nothing for a client, and so does a
		// frame of a session that is gone.
		if _, err = reader.Discard(payloadLen); err != nil {
			return err
		}
		if meta.Status == StatusKeep {
			// tell the peer to close the session it still feeds
			return c.writeFrame(&Metadata{SessionID: meta.SessionID, Status: StatusEnd}, nil)
		}
		return nil
	}

	if payloadLen == 0 && s.network == NetworkTCP {
		return nil // nothing to deliver, and it must not grow the queue
	}
	payload := pool.Get(payloadLen)
	if _, err = io.ReadFull(reader, payload); err != nil {
		_ = pool.Put(payload)
		return err
	}
	s.deliver(payload, meta.Target)
	return nil
}

// idleLoop closes a carrier that has no session and got none for a while,
// the way Xray-core does.
func (c *Carrier) idleLoop() {
	ticker := time.NewTicker(idleInterval)
	defer ticker.Stop()
	c.mu.Lock()
	size, count := len(c.sessions), c.count
	c.mu.Unlock()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}
		c.mu.Lock()
		idle := len(c.sessions) == 0 && size == 0 && count == c.count
		size, count = len(c.sessions), c.count
		c.retired = idle // no session gets in between the check and the close
		c.mu.Unlock()
		if idle {
			_ = c.Close()
			return
		}
	}
}

// item is a received payload with the address a UDP packet came from.
type item struct {
	payload []byte // from pool
	from    Endpoint
}

// session is one Mux.Cool session of a carrier.
type session struct {
	carrier     *Carrier
	id          uint16
	network     Network
	destination M.Socksaddr
	globalID    [8]byte

	writeMu sync.Mutex  // one Write or WriteTo at a time
	frameMu sync.Mutex  // one frame at a time; a Read may have to open the session
	opened  atomic.Bool // the new frame was sent

	mu       sync.Mutex
	queue    []item
	queued   int           // bytes in queue
	first    M.Socksaddr   // where the first packet of a UDP session went
	err      error         // why reading ends once the queue is empty
	readable chan struct{} // signals data in queue to a reader
	writable chan struct{} // signals room in queue to the carrier
	failed   chan struct{} // closed when err is set

	closeOnce sync.Once
	closed    chan struct{} // closed locally
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// deliver hands a payload to the session. For a stream it blocks while the
// buffer is full; for packets it drops.
func (s *session) deliver(payload []byte, from Endpoint) {
	for {
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			_ = pool.Put(payload)
			return
		}
		full := s.queued >= streamBuffer
		if s.network == NetworkUDP {
			if len(s.queue) >= packetBuffer {
				s.mu.Unlock()
				_ = pool.Put(payload)
				return
			}
			full = false
		}
		if !full {
			s.queue = append(s.queue, item{payload: payload, from: from})
			s.queued += len(payload)
			s.mu.Unlock()
			notify(s.readable)
			return
		}
		s.mu.Unlock()
		select {
		case <-s.writable:
		case <-s.failed:
		}
	}
}

// take returns the next received item, waiting until deadline fires.
func (s *session) take(expired <-chan struct{}) (item, error) {
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			it := s.queue[0]
			s.queue[0] = item{}
			s.queue = s.queue[1:]
			s.queued -= len(it.payload)
			more := len(s.queue) > 0
			s.mu.Unlock()
			notify(s.writable)
			if more {
				notify(s.readable) // for another reader
			}
			return it, nil
		}
		err := s.err
		s.mu.Unlock()
		if err != nil {
			return item{}, err
		}
		select {
		case <-s.readable:
		case <-s.failed:
		case <-expired:
			return item{}, errDeadline
		}
	}
}

// fail ends reading with err after the queued data, and wakes everyone up.
func (s *session) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
		close(s.failed)
	}
	s.mu.Unlock()
}

// end handles the peer's end frame: the session is over in both directions.
func (s *session) end(hasError bool) {
	s.carrier.remove(s.id)
	if hasError {
		s.fail(ErrSessionClosed)
	} else {
		s.fail(io.EOF)
	}
}

// abort ends the session because its carrier is gone.
func (s *session) abort(err error) {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	s.fail(err)
}

// ensureOpened sends the new frame of the session if nothing was sent yet.
func (s *session) ensureOpened() error {
	if s.opened.Load() {
		return nil
	}
	return s.writeFrame(nil, M.Socksaddr{}, false, true)
}

// write sends a payload, cut in frames when it is a stream, and returns how
// much of it was sent. Callers hold writeMu.
func (s *session) write(p []byte, to M.Socksaddr, hasData bool) (n int, err error) {
	for {
		chunk := p[n:]
		if s.network == NetworkTCP && len(chunk) > MaxPayload {
			chunk = chunk[:MaxPayload]
		}
		if err = s.writeFrame(chunk, to, hasData, false); err != nil {
			return n, err
		}
		n += len(chunk)
		if n == len(p) {
			return n, nil
		}
	}
}

// writeFrame sends one frame; the first frame sent is the new frame. With
// openOnly it does nothing if the session is open already.
func (s *session) writeFrame(chunk []byte, to M.Socksaddr, hasData bool, openOnly bool) error {
	s.frameMu.Lock()
	defer s.frameMu.Unlock()
	opened := s.opened.Load()
	if openOnly && opened {
		return nil
	}
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		if err == io.EOF {
			err = io.ErrClosedPipe
		}
		return err
	}

	meta := Metadata{SessionID: s.id, Status: StatusKeep}
	if hasData {
		meta.Option = OptionData
	}
	if !opened {
		meta.Status = StatusNew
		meta.Target = Endpoint{Network: s.network, Addr: s.destination}
		if s.network == NetworkUDP && hasData {
			meta.Target.Addr = to
			meta.GlobalID = s.globalID
			s.mu.Lock()
			s.first = to
			s.mu.Unlock()
		}
	} else if s.network == NetworkUDP {
		meta.Target = Endpoint{Network: NetworkUDP, Addr: to}
	}
	if err = s.carrier.writeFrame(&meta, chunk); err != nil {
		return err
	}
	s.opened.Store(true)
	return nil
}

// source is where a packet without an address of its own came from.
func (s *session) source() M.Socksaddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.first.IsValid() {
		return s.first
	}
	return s.destination
}

// close ends the session locally and tells the peer.
func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.carrier.remove(s.id)
		s.fail(net.ErrClosed)

		s.mu.Lock()
		for _, it := range s.queue {
			_ = pool.Put(it.payload)
		}
		s.queue, s.queued = nil, 0
		s.mu.Unlock()

		// The end frame goes after a frame that may be on its way, which can
		// take as long as the carrier is stuck. Close does not wait for it.
		go func() {
			s.frameMu.Lock()
			opened := s.opened.Load()
			s.frameMu.Unlock()
			if opened {
				_ = s.carrier.writeFrame(&Metadata{SessionID: s.id, Status: StatusEnd}, nil)
			}
		}()
	})
}
