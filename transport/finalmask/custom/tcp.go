package custom

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

// TCP is a parsed header-custom TCP mask.
type TCP struct {
	steps []step // the handshake, in the order it runs
}

// step is one list of items the client sends, or reads and checks.
type step struct {
	read  bool
	name  string
	items []item
}

func (m *TCP) WrapConn(conn net.Conn) (net.Conn, error) {
	return &Conn{
		Conn:       conn,
		mask:       m,
		done:       make(chan struct{}),
		closed:     make(chan struct{}),
		pending:    true,
		readLimit:  deadline.MakePipeDeadline(),
		writeLimit: deadline.MakePipeDeadline(),
	}, nil
}

// Conn runs the handshake when the connection is first read or written and
// passes the data through afterwards.
//
// The handshake runs once, on its own: a Read waits for it until the read
// deadline and a Write until the write deadline, and one of them giving up
// does not take the handshake from the other. Close ends it.
type Conn struct {
	net.Conn
	mask *TCP

	once      sync.Once
	done      chan struct{} // closed when the handshake is over
	err       error         // why it failed, set before done is closed
	ready     atomic.Bool   // the handshake is over and went well
	closeOnce sync.Once
	closed    chan struct{} // closed by Close

	// Until the handshake is over the deadlines are kept here and not given
	// to the connection, where they would cut the handshake short.
	mu                    sync.Mutex
	pending               bool
	readUntil, writeUntil time.Time
	readLimit, writeLimit deadline.PipeDeadline
}

// Upstream, ReaderReplaceable and WriterReplaceable let the relay drop the
// wrapper once the handshake is over.
func (c *Conn) Upstream() any {
	if !c.ready.Load() {
		return nil // nothing is to reach under the mask before the handshake
	}
	return c.Conn
}

func (c *Conn) ReaderReplaceable() bool {
	return c.ready.Load()
}

func (c *Conn) WriterReplaceable() bool {
	return c.ready.Load()
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.handshake(&c.readLimit); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.handshake(&c.writeLimit); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	// the timers of deadlines set before a handshake that never started
	c.readLimit.Set(time.Time{})
	c.writeLimit.Set(time.Time{})
	return c.Conn.Close()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.setDeadlines(t, true, true)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.setDeadlines(t, true, false)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlines(t, false, true)
}

func (c *Conn) setDeadlines(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pending {
		switch {
		case read && write:
			return c.Conn.SetDeadline(t)
		case read:
			return c.Conn.SetReadDeadline(t)
		default:
			return c.Conn.SetWriteDeadline(t)
		}
	}
	if read {
		c.readUntil = t
		c.readLimit.Set(t)
	}
	if write {
		c.writeUntil = t
		c.writeLimit.Set(t)
	}
	return nil
}

// handshake starts the handshake if nobody has yet and waits for it to end,
// for the deadline of the caller or for Close. Once it has failed every
// caller gets its error.
func (c *Conn) handshake(limit *deadline.PipeDeadline) error {
	if c.ready.Load() {
		return nil
	}
	c.once.Do(func() { go c.run() })
	select {
	case <-c.done:
		return c.err
	default:
	}
	select {
	case <-c.done:
		return c.err
	case <-c.closed:
		return net.ErrClosed
	case <-limit.Wait():
		return os.ErrDeadlineExceeded
	}
}

func (c *Conn) run() {
	s := &scope{vars: map[string][]byte{}, local: c.Conn.LocalAddr(), remote: c.Conn.RemoteAddr()}
	var err error
	for _, st := range c.mask.steps {
		if st.read {
			err = readItems(c.Conn, st.items, s)
		} else {
			err = writeItems(c.Conn, st.items, s, c.closed)
		}
		if err != nil {
			err = fmt.Errorf("header-custom: handshake failed at %s: %w", st.name, err)
			break
		}
	}

	c.mu.Lock()
	c.pending = false
	if err == nil {
		// From now on the deadlines are those of the connection.
		if !c.readUntil.IsZero() {
			_ = c.Conn.SetReadDeadline(c.readUntil)
		}
		if !c.writeUntil.IsZero() {
			_ = c.Conn.SetWriteDeadline(c.writeUntil)
		}
	}
	c.readLimit.Set(time.Time{})
	c.writeLimit.Set(time.Time{})
	c.mu.Unlock()

	c.err = err
	c.ready.Store(err == nil)
	close(c.done)
}

// writeItems sends the items in one write, or in several when an item has a
// delay: what is gathered by then goes out before the pause. Closing cancel
// ends a pause.
func writeItems(w io.Writer, items []item, s *scope, cancel <-chan struct{}) error {
	var merged []byte
	var total int64 // of the whole sequence, across the pauses
	for i := range items {
		it := &items[i]
		if it.delay.To > 0 {
			if len(merged) > 0 {
				if _, err := w.Write(merged); err != nil {
					return err
				}
				merged = nil
			}
			if pause := time.Duration(it.delay.Rand()) * time.Millisecond; pause > 0 {
				timer := time.NewTimer(pause)
				select {
				case <-timer.C:
				case <-cancel:
					timer.Stop()
					return net.ErrClosed
				}
			}
		}
		b, err := it.eval(s)
		if err == nil {
			if total += int64(len(b)); total > maxSize {
				err = errTooLarge
			} else {
				merged, err = appendBytes(merged, b)
			}
		}
		if err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	if len(merged) > 0 {
		if _, err := w.Write(merged); err != nil {
			return err
		}
	}
	return nil
}

// readItems reads what the items say the server sends and checks it.
func readItems(r io.Reader, items []item, s *scope) error {
	var total int64
	for i := range items {
		it := &items[i]
		n, err := it.size(s.varSize)
		if err == nil {
			if total += int64(n); total > maxSize {
				err = errTooLarge
			}
		}
		if err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		buf := make([]byte, n)
		if _, err = io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		if err = it.match(buf, s); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}
