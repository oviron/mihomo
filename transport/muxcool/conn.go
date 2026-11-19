package muxcool

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/common/pool"

	M "github.com/metacubex/sing/common/metadata"
)

var errDeadline error = os.ErrDeadlineExceeded

type addr struct {
	network string
}

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return Destination }

// streamConn is a TCP session.
type streamConn struct {
	session  *session
	deadline deadline.PipeDeadline
	readMu   sync.Mutex
	head     []byte // unread rest of a payload
	headBuf  []byte // its pool buffer
}

func (c *streamConn) Read(b []byte) (int, error) {
	if err := c.session.ensureOpened(); err != nil {
		return 0, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.head) == 0 {
		if c.headBuf != nil {
			_ = pool.Put(c.headBuf)
			c.headBuf = nil
		}
		it, err := c.session.take(c.deadline.Wait())
		if err != nil {
			return 0, err
		}
		c.head, c.headBuf = it.payload, it.payload
	}
	n := copy(b, c.head)
	c.head = c.head[n:]
	return n, nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	c.session.writeMu.Lock()
	defer c.session.writeMu.Unlock()
	if len(b) == 0 && c.session.opened.Load() {
		return 0, nil
	}
	// an empty first write opens the session without data
	return c.session.write(b, M.Socksaddr{}, len(b) > 0)
}

// NeedHandshake lets the caller put its first payload into the first Write,
// which then travels in the frame that opens the session.
func (c *streamConn) NeedHandshake() bool {
	return !c.session.opened.Load()
}

func (c *streamConn) Close() error {
	c.session.close()
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return addr{"tcp"} }
func (c *streamConn) RemoteAddr() net.Addr { return c.session.destination }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

// SetWriteDeadline does nothing: a write is a write to the shared carrier,
// which gives up on its own when the peer stops reading for too long.
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

// packetConn is a UDP session.
type packetConn struct {
	session  *session
	deadline deadline.PipeDeadline
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	it, err := c.session.take(c.deadline.Wait())
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, it.payload)
	_ = pool.Put(it.payload)
	from := it.from.Addr
	if it.from.Network != NetworkUDP {
		from = c.session.source()
	}
	if from.IsFqdn() {
		return n, from, nil
	}
	return n, from.UDPAddr(), nil
}

func (c *packetConn) WriteTo(b []byte, to net.Addr) (int, error) {
	if len(b) > MaxPayload {
		return 0, ErrPacketTooLarge // Xray-core would close the carrier on it
	}
	c.session.writeMu.Lock()
	defer c.session.writeMu.Unlock()
	return c.session.write(b, M.SocksaddrFromNet(to), true)
}

func (c *packetConn) Close() error {
	c.session.close()
	return nil
}

func (c *packetConn) LocalAddr() net.Addr { return addr{"udp"} }

func (c *packetConn) SetDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

// SetWriteDeadline does nothing: a write is a write to the shared carrier.
func (c *packetConn) SetWriteDeadline(time.Time) error { return nil }
