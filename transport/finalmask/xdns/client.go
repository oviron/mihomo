package xdns

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	initPollDelay = 500 * time.Millisecond
	maxPollDelay  = 10 * time.Second
	// pollLimit is how many polls may wait to be sent.
	pollLimit = 16

	// maxDatagram is the largest datagram the tunnel takes, and the largest
	// DNS message it reads.
	maxDatagram = 4096
	// maxFragments is how many queries one datagram may be split over.
	maxFragments = 255
	// readQueue is how many datagrams of the server may wait to be read. More
	// are dropped, as a full socket buffer drops them.
	readQueue = 512

	// A query name carries, in this order: the 8 bytes of the client ID with
	// the record type in the two low bits of the first byte; a byte with the
	// number of random bytes that follow, and flagFragment in its top bits;
	// the random bytes, which keep resolvers from answering out of their
	// cache, 8 in a poll and 3 in front of data; for a piece of a datagram
	// its ID, index and the number of pieces; the data.
	queryHeader    = 8 + 1 + dataRandom
	fragmentHeader = 3
	pollRandom     = 8
	dataRandom     = 3
	flagFragment   = 0xC0
)

// conn is the client end of the tunnel.
type conn struct {
	mask *Mask
	dest net.Addr

	// clientID tells the server which client a query is from: the queries of
	// one client reach it from many resolver addresses.
	clientID   [8]byte
	fragmentID atomic.Uint32

	resolvers []resolver
	// sent are the queries each resolver has not answered yet.
	sent []sentQueries
	// sends counts the queries given to each resolver since its last answer
	// with data, current is the resolver the next query goes to.
	sends   []atomic.Uint32
	current atomic.Uint32

	readCh  chan []byte
	pollCh  chan struct{}
	roomCh  chan struct{} // a resolver has made room for a query
	closeCh chan struct{}

	closeOnce     sync.Once
	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
	wg            sync.WaitGroup
	writeMu       sync.Mutex // keeps the queries of one datagram together
}

func newConn(ctx context.Context, m *Mask, dialer mask.Dialer, dest netip.AddrPort) (*conn, error) {
	c := newBareConn(m, len(m.resolvers))
	c.dest = net.UDPAddrFromAddrPort(dest)
	for i, rc := range m.resolvers {
		i := i
		r, err := rc.open(ctx, dialer, link{receive: func(msg []byte) { c.receive(i, msg) }, room: c.roomCh})
		if err != nil {
			close(c.closeCh)
			for _, r := range c.resolvers {
				r.close()
			}
			return nil, err
		}
		c.resolvers = append(c.resolvers, r)
	}
	c.wg.Add(1)
	go c.poll()
	return c, nil
}

// newBareConn makes a tunnel that has no resolvers yet.
func newBareConn(m *Mask, resolvers int) *conn {
	c := &conn{
		mask:          m,
		sent:          make([]sentQueries, resolvers),
		sends:         make([]atomic.Uint32, resolvers),
		readCh:        make(chan []byte, readQueue),
		pollCh:        make(chan struct{}, pollLimit),
		roomCh:        make(chan struct{}, 1),
		closeCh:       make(chan struct{}),
		readDeadline:  deadline.MakePipeDeadline(),
		writeDeadline: deadline.MakePipeDeadline(),
	}
	_, _ = crand.Read(c.clientID[:])
	c.clientID[0] &= 0xFC
	return c
}

// domain picks the domain for a datagram of the given size at random, among
// those that can carry it when not all can. It returns nil when none can.
func (c *conn) domain(size int) *domain {
	domains := c.mask.domains
	if d := domains[rand.Intn(len(domains))]; size <= d.limit() {
		return d
	}
	var fit []*domain
	for _, d := range domains {
		if size <= d.limit() {
			fit = append(fit, d)
		}
	}
	if len(fit) == 0 {
		return nil
	}
	return fit[rand.Intn(len(fit))]
}

// send puts a datagram into one query, or into several when it is larger
// than a query name. Without a datagram it sends a poll. With wait it waits
// for the resolvers to have room for the queries, and fails when the tunnel
// is closed or the write deadline has passed; without it the queries they
// have no room for are dropped.
func (c *conn) send(p []byte, wait bool) error {
	d := c.domain(len(p))
	if d == nil {
		return c.mask.tooLarge(len(p))
	}
	qtype := d.types[rand.Intn(len(d.types))]

	var data [255]byte
	copy(data[:], c.clientID[:])
	data[0] |= typeCodes[qtype]
	switch {
	case len(p) == 0:
		data[8] = pollRandom
		_, _ = crand.Read(data[9 : 9+pollRandom])
		return c.query(d, qtype, data[:9+pollRandom], wait)
	case len(p) <= d.cap-queryHeader:
		data[8] = dataRandom
		_, _ = crand.Read(data[9:queryHeader])
		n := copy(data[queryHeader:], p)
		return c.query(d, qtype, data[:queryHeader+n], wait)
	}
	data[8] = dataRandom | flagFragment
	_, _ = crand.Read(data[9:queryHeader])
	size := d.fragmentCap()
	count := (len(p) + size - 1) / size
	data[queryHeader] = byte(c.fragmentID.Add(1))
	data[queryHeader+2] = byte(count)
	for i := 0; i < count; i++ {
		data[queryHeader+1] = byte(i)
		n := copy(data[queryHeader+fragmentHeader:d.cap], p)
		if err := c.query(d, qtype, data[:queryHeader+fragmentHeader+n], wait); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// query gives one query to the current resolver, or to the next one that
// has room for it: a resolver that is stuck does not hold up the others.
func (c *conn) query(d *domain, qtype dnsmessage.Type, data []byte, wait bool) error {
	name := d.encode(data)
	msg, err := d.query(name, qtype, make([]byte, 0, 512))
	if err != nil {
		return nil // newDomain has packed the longest query
	}
	_, _ = crand.Read(msg[:2]) // the message ID
	key := queryKey{id: binary.BigEndian.Uint16(msg), qtype: qtype, name: lowerName(name)}

	n := uint32(len(c.resolvers))
	for {
		// also after a wait for room: the connection may be closed by now
		select {
		case <-c.closeCh:
			return net.ErrClosed
		default:
		}
		if wait {
			select {
			case <-c.writeDeadline.Wait():
				return os.ErrDeadlineExceeded
			default:
			}
		}
		first := c.current.Load()
		// The resolvers that are ready come first; one that is not, say a
		// DoH server that asked for a pause, only gets the query when no
		// other takes it.
		for _, readyOnly := range []bool{true, false} {
			for k := uint32(0); k < n; k++ {
				i := (first + k) % n
				if c.resolvers[i].ready() != readyOnly {
					continue
				}
				c.sent[i].add(key, d) // the answer may come before send returns
				if c.resolvers[i].send(msg) {
					c.advance(i)
					return nil
				}
				c.sent[i].take(key)
			}
		}
		if !wait {
			return nil
		}
		select {
		case <-c.roomCh:
		case <-c.closeCh:
			return net.ErrClosed
		case <-c.writeDeadline.Wait():
			return os.ErrDeadlineExceeded
		}
	}
}

// advance counts a query given to resolver i and moves on to the next
// resolver that has fewer queries without an answer. A resolver that stops
// answering is used less and less this way.
func (c *conn) advance(i uint32) {
	sends := c.sends[i].Add(1)
	next := i
	for {
		next++
		if next == uint32(len(c.resolvers)) {
			next = 0
		}
		if next == i || sends > c.sends[next].Load() {
			break
		}
	}
	c.current.Store(next)
}

// receive takes a DNS message that came from resolver i and queues the
// datagrams it carries. Only an answer to a query that resolver was given,
// and has not answered before, counts. It does not wait for a reader.
func (c *conn) receive(i int, buf []byte) {
	var msg dnsmessage.Message
	if err := msg.Unpack(buf); err != nil {
		return
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		return
	}
	question := msg.Questions[0]
	d := c.sent[i].take(queryKey{id: msg.Header.ID, qtype: question.Type, name: lowerName(question.Name)})
	if d == nil {
		return
	}
	datagrams := splitDatagrams(d.payload(&msg))
	for _, datagram := range datagrams {
		select {
		case c.readCh <- datagram:
		default:
		}
	}
	if len(datagrams) > 0 {
		// The server may have more: ask again.
		c.sends[i].Store(0)
		select {
		case c.pollCh <- struct{}{}:
		default:
		}
	}
}

// poll sends the queries the server answers when the client has nothing to
// send. It starts with the first datagram of the server.
func (c *conn) poll() {
	defer c.wg.Done()
	select {
	case <-c.closeCh:
		return
	case <-c.pollCh:
	}
	delay := initPollDelay
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-c.pollCh:
			delay = initPollDelay
		case <-ticker.C:
			delay *= 2
			if delay > maxPollDelay {
				delay = maxPollDelay
			}
		}
		if c.closed() {
			return
		}
		ticker.Reset(delay)
		for i := 0; i <= c.mask.extraPoll; i++ {
			_ = c.send(nil, false)
		}
	}
}

func (c *conn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *conn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case datagram := <-c.readCh:
		return copy(p, datagram), c.dest, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// WriteTo sends p through the tunnel whatever addr is. It returns when the
// resolvers have taken the queries, which is not when they are sent.
func (c *conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(p) == 0 {
		return 0, errors.New("xdns: empty datagram")
	}
	if err := c.send(p, true); err != nil {
		return 0, err
	}
	for i := 0; i < c.mask.extraPoll; i++ {
		if c.send(nil, true) != nil {
			break
		}
	}
	return len(p), nil
}

func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		for _, r := range c.resolvers {
			r.close()
		}
		c.wg.Wait()
	})
	return nil
}

func (c *conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (c *conn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

// SetWriteDeadline bounds how long WriteTo waits for the resolvers to have
// room for its queries.
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

// tooLarge reports a datagram no domain can carry: the transport above the
// mask is set up with too large an MTU, which the user has to learn about.
func (m *Mask) tooLarge(size int) error {
	m.warnTooLarge.Do(func() {
		reason := ""
		if m.limit < maxDatagram {
			reason = fmt.Sprintf(": %d queries of %d bytes under the domain %s", maxFragments, m.widest.fragmentCap(), strings.TrimSuffix(m.widest.name.String(), "."))
		}
		log.Warnln("[finalmask] xdns: dropping a datagram of %d bytes, the tunnel carries %d at most%s. Lower the MTU of the transport that uses the mask",
			size, m.limit, reason)
	})
	return fmt.Errorf("xdns: a datagram of %d bytes is too large, the tunnel carries %d at most", size, m.limit)
}

const (
	// queryTTL is how long an answer to a query is waited for. The server
	// holds a query for a second at most.
	queryTTL = 30 * time.Second
	// maxSentQueries bounds the queries remembered per resolver.
	maxSentQueries = 8192
)

// queryKey is what makes an answer the answer to a query: the message ID
// and the question. The name is in lower case, resolvers may change it.
type queryKey struct {
	id    uint16
	qtype dnsmessage.Type
	name  string
}

func lowerName(name dnsmessage.Name) string {
	b := make([]byte, name.Length)
	for i := range b {
		b[i] = lower(name.Data[i])
	}
	return string(b)
}

// sentQuery is a query that waits for its answer.
type sentQuery struct {
	domain *domain
	at     time.Time
}

// sentQueries are the queries given to one resolver that have no answer yet.
// They are kept in two generations: when the recent one is queryTTL old, or
// full, the older one is forgotten.
type sentQueries struct {
	mu       sync.Mutex
	recent   map[queryKey]sentQuery
	older    map[queryKey]sentQuery
	rotateAt time.Time
}

func (s *sentQueries) add(key queryKey, d *domain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.recent == nil || len(s.recent) >= maxSentQueries || now.After(s.rotateAt) {
		s.older, s.recent = s.recent, make(map[queryKey]sentQuery)
		s.rotateAt = now.Add(queryTTL)
	}
	s.recent[key] = sentQuery{domain: d, at: now}
}

// take returns the domain of a query and forgets the query, so that it is
// answered once. It returns nil for a query that is not known or too old.
func (s *sentQueries) take(key queryKey) *domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	query, ok := s.recent[key]
	if ok {
		delete(s.recent, key)
	} else if query, ok = s.older[key]; ok {
		delete(s.older, key)
	}
	if !ok || time.Since(query.at) > queryTTL {
		return nil
	}
	return query.domain
}
