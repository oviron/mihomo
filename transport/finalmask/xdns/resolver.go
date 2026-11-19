package xdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

const (
	// dialTimeout bounds every connection attempt to a resolver.
	dialTimeout = 10 * time.Second
	// writeTimeout bounds a write to the socket of a resolver. A TCP resolver
	// that has stopped reading is hung up on after that.
	writeTimeout = 5 * time.Second
	// redialDelay is how long a resolver that could not be reached is left
	// alone. Its queries are lost meanwhile.
	redialDelay = 500 * time.Millisecond
	// socketQueue is how many queries may wait for the socket of a resolver.
	socketQueue = 128
)

// resolver carries DNS messages to a recursive resolver and back.
type resolver interface {
	// send takes a query to pass it on and tells whether it had room for it.
	// It does not wait. A query that was taken may still be lost, which is
	// the business of the transport above the tunnel. msg is kept.
	send(msg []byte) bool
	// ready tells whether the resolver can be expected to pass a query on
	// now. One that is not is only used when no other is ready.
	ready() bool
	close()
}

// link is what a resolver has of the tunnel it works for.
type link struct {
	// receive gets every DNS message that comes back. It does not wait and
	// does not keep the message.
	receive func(msg []byte)
	// room is told when the resolver has taken a query off its queue.
	room chan<- struct{}
}

// sendQueue holds the queries a resolver has taken and not sent yet.
type sendQueue struct {
	queries chan []byte
	room    chan<- struct{}
}

func newSendQueue(size int, room chan<- struct{}) sendQueue {
	return sendQueue{queries: make(chan []byte, size), room: room}
}

func (q sendQueue) put(msg []byte) bool {
	select {
	case q.queries <- msg:
		return true
	default:
		return false
	}
}

// get waits for a query. It returns nil when done is closed.
func (q sendQueue) get(done <-chan struct{}) []byte {
	select {
	case <-done:
		return nil
	case msg := <-q.queries:
		select {
		case q.room <- struct{}{}:
		default:
		}
		return msg
	}
}

// open starts the resolver.
func (rc resolverConfig) open(ctx context.Context, dialer mask.Dialer, tunnel link) (resolver, error) {
	if rc.scheme == "https" {
		return newDoHResolver(rc, dialer, tunnel), nil
	}
	r := &socketResolver{
		dialer:       dialer,
		network:      rc.scheme,
		addr:         rc.addr,
		writeTimeout: rc.writeTimeout,
		receive:      tunnel.receive,
		queue:        newSendQueue(socketQueue, tunnel.room),
	}
	if r.writeTimeout == 0 {
		r.writeTimeout = writeTimeout
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	if _, err := r.socket(ctx); err != nil {
		r.close()
		return nil, err
	}
	r.wg.Add(1)
	go r.write()
	return r, nil
}

// socketResolver talks to a resolver over one UDP socket or one TCP
// connection. A socket that failed is replaced for the next query.
type socketResolver struct {
	dialer       mask.Dialer
	network      string // udp or tcp
	addr         string
	writeTimeout time.Duration
	receive      func(msg []byte)
	queue        sendQueue
	ctx          context.Context // ends with close
	cancel       context.CancelFunc

	mu      sync.Mutex // guards the fields below
	conn    net.Conn
	retryAt time.Time // no dialing before
	closed  bool
	wg      sync.WaitGroup
}

var errUnreachable = errors.New("xdns: the resolver could not be reached a moment ago")

// socket returns the socket, opening it when there is none.
func (r *socketResolver) socket(ctx context.Context) (net.Conn, error) {
	r.mu.Lock()
	conn, closed, retryAt := r.conn, r.closed, r.retryAt
	r.mu.Unlock()
	switch {
	case closed:
		return nil, net.ErrClosed
	case conn != nil:
		return conn, nil
	case time.Now().Before(retryAt):
		return nil, errUnreachable
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := r.dialer.DialContext(ctx, r.network, r.addr)
	if err == nil && N.NeedHandshake(conn) {
		// A TCP Fast Open connection is only made by its first write. The
		// reader starts before that, so it is made now, without data.
		if _, err = conn.Write(nil); err != nil {
			_ = conn.Close()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.retryAt = time.Now().Add(redialDelay)
		return nil, err
	}
	if r.closed {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	r.conn = conn
	r.wg.Add(1)
	go r.read(conn)
	return conn, nil
}

// drop closes a socket that is of no use any more.
func (r *socketResolver) drop(conn net.Conn) {
	_ = conn.Close()
	r.mu.Lock()
	if r.conn == conn {
		r.conn = nil
	}
	r.mu.Unlock()
}

func (r *socketResolver) read(conn net.Conn) {
	defer r.wg.Done()
	defer r.drop(conn)
	buf := make([]byte, maxDatagram)
	for {
		var n int
		var err error
		if r.network == "tcp" {
			n, err = readFramed(conn, buf)
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil {
			return
		}
		if n > 0 {
			r.receive(buf[:n])
		}
	}
}

// readFramed reads one DNS message of a TCP connection: a two byte length
// and the message. It returns 0 for a message that does not fit into buf.
func readFramed(conn net.Conn, buf []byte) (int, error) {
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(buf))
	if n > len(buf) {
		_, err := io.CopyN(io.Discard, conn, int64(n))
		return 0, err
	}
	_, err := io.ReadFull(conn, buf[:n])
	return n, err
}

// write sends the queued queries, one write each. After a write that failed
// or took too long the socket is dropped: a TCP connection may have a part
// of the message in it, and nothing more can be sent on it.
func (r *socketResolver) write() {
	defer r.wg.Done()
	var frame []byte
	for {
		msg := r.queue.get(r.ctx.Done())
		if msg == nil {
			return
		}
		conn, err := r.socket(r.ctx)
		if err != nil {
			continue
		}
		if r.network == "tcp" {
			frame = append(append(frame[:0], byte(len(msg)>>8), byte(len(msg))), msg...)
			msg = frame
		}
		_ = conn.SetWriteDeadline(time.Now().Add(r.writeTimeout))
		if _, err := conn.Write(msg); err != nil {
			r.drop(conn)
		}
	}
}

func (r *socketResolver) ready() bool {
	return true
}

func (r *socketResolver) send(msg []byte) bool {
	return r.queue.put(msg)
}

func (r *socketResolver) close() {
	r.cancel()
	r.mu.Lock()
	r.closed = true
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	r.wg.Wait()
}
