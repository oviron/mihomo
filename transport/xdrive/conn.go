package xdrive

import (
	"context"
	"net"
	"os"
	"sync"
	"time"
)

var placeholderAddr = &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0}

// Conn is a session: a writer of segments and a reader of them.
type Conn struct {
	cancel context.CancelFunc
	writer *walWriter
	reader *walReader

	readMu  sync.Mutex
	readBuf []byte

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
	closeErr  error
}

func newConn(ctx context.Context, storage Storage, writePrefix, readPrefix string, p params) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	return &Conn{
		cancel: cancel,
		writer: newWALWriter(ctx, storage, writePrefix, p),
		reader: newWALReader(ctx, storage, readPrefix, p),
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuf) == 0 {
		data, err := c.receive()
		if err != nil {
			return 0, err
		}
		c.readBuf = data
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) receive() ([]byte, error) {
	deadline := c.getDeadline(true)
	if deadline.IsZero() {
		data, ok := <-c.reader.ch
		if !ok {
			return nil, c.reader.Err()
		}
		return data, nil
	}
	if !time.Now().Before(deadline) {
		return nil, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case data, ok := <-c.reader.ch:
		if !ok {
			return nil, c.reader.Err()
		}
		return data, nil
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if deadline := c.getDeadline(false); !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.writer.Write(b)
	if err == nil {
		c.reader.Wake() // an answer is likely to follow
	}
	return n, err
}

// closeWait bounds how long Close keeps storing what is still buffered.
const closeWait = 10 * time.Second

// Close stores what is still buffered and the end mark, then stops reading.
// A storage that does not keep up is given closeWait; after that the session
// is dropped as it is and the server ends it by its own timeout.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		done := make(chan error, 1)
		go func() { done <- c.writer.Close() }()
		select {
		case c.closeErr = <-done:
		case <-time.After(closeWait):
			c.closeErr = os.ErrDeadlineExceeded
		}
		c.cancel()
	})
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr  { return placeholderAddr }
func (c *Conn) RemoteAddr() net.Addr { return placeholderAddr }

func (c *Conn) getDeadline(read bool) time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if read {
		return c.readDeadline
	}
	return c.writeDeadline
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return nil
}
