package sudoku

import (
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/pool"

	"github.com/metacubex/randv2"
	"github.com/metacubex/sing/common"
)

const (
	// smallRead is the size of the buffer that serves callers reading into a
	// smaller one.
	smallRead = 512
	// maxWireWrite bounds one write to the wrapped connection.
	maxWireWrite = 64 * 1024
	// maxDatagram is the largest payload of a UDP datagram.
	maxDatagram = 65507
	// datagramBuffer holds any datagram a socket can return, with room to
	// tell that one was cut.
	datagramBuffer = 65535
)

// Conn is a masked TCP connection: writes leave as puzzles, reads decode the
// packed stream of the server.
//
// Every byte is changed for as long as the connection lives, so unlike the
// masks that only shape the first writes it offers no way to reach the wrapped
// connection: a relay or XTLS Vision that wrote to it directly would send
// bytes the server cannot decode.
type Conn struct {
	net.Conn

	rmu   sync.Mutex
	dec   unpacker
	small []byte // read buffer for callers with a tiny one
	wire  []byte // the part of small that is not decoded yet
	rerr  error  // came with data that had to be returned first

	wmu  sync.Mutex
	enc  encoder
	werr error // a failed write, the stream cannot continue after it
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if len(c.wire) > 0 {
			n, used := c.dec.decode(p, c.wire)
			c.wire = c.wire[used:]
			if n > 0 {
				return n, nil
			}
			continue
		}
		// The wrapped connection may report an error only once: the one that
		// arrived with data is returned as soon as the data is handed out.
		if err := c.rerr; err != nil {
			c.rerr = nil
			return 0, err
		}
		if len(p) >= smallRead {
			// Decoding never grows the data: receive into p and decode in place.
			nr, err := c.Conn.Read(p)
			if n, _ := c.dec.decode(p, p[:nr]); n > 0 {
				c.rerr = err
				return n, nil
			}
			if err != nil {
				return 0, err
			}
			continue
		}
		if c.small == nil {
			c.small = make([]byte, smallRead)
		}
		nr, err := c.Conn.Read(c.small)
		c.wire, c.rerr = c.small[:nr], err
	}
}

// Write sends p as puzzles. Once a write to the wrapped connection fails
// every later Write returns that error: the server cannot tell how much of
// the failed piece arrived, and the tables of the two sides no longer agree.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}

	expansion := maxExpansion
	if c.enc.chance <= 0 {
		expansion = 4
	}
	size := maxWireWrite
	if len(p) < maxWireWrite/expansion { // compared before multiplying: no overflow of a 32-bit int
		size = len(p)*expansion + 1
	}
	buf := pool.Get(size)
	defer pool.Put(buf)
	// A large write leaves in pieces that fit the buffer.
	for written := 0; written < len(p); {
		end := written + (size-1)/expansion
		if end > len(p) {
			end = len(p)
		}
		out := c.enc.encode(buf[:0], p[written:end])
		if end == len(p) {
			out = c.enc.finish(out)
		}
		if _, err := c.Conn.Write(out); err != nil {
			c.werr = err
			return written, err
		}
		written = end
	}
	return len(p), nil
}

// CloseWrite half-closes the connection below. The encoder holds nothing
// back, there is nothing to flush first. Other masks may sit between this one
// and the socket; they are looked through for this method only.
func (c *Conn) CloseWrite() error {
	if cw, ok := common.Cast[interface{ CloseWrite() error }](c.Conn); ok {
		return cw.CloseWrite()
	}
	return net.ErrClosed
}

// PacketConn is a masked UDP socket: every datagram is a sequence of puzzles
// that starts with the first layout, in both directions.
type PacketConn struct {
	net.PacketConn
	mask *Mask

	wmu sync.Mutex
	rng *randv2.Rand
}

// ReadFrom returns the next datagram that decodes. Others are dropped: they
// are damaged, not from the server, or larger than p.
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := pool.Get(datagramBuffer)
	defer pool.Put(buf)
	for {
		nr, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if nr == len(buf) {
			continue // cut by the buffer, the rest of it is lost
		}
		if n, ok := c.mask.decodeDatagram(p, buf[:nr]); ok {
			return n, addr, nil
		}
	}
}

// WriteTo sends p as one datagram, four to nine times its size. It fails when
// that is more than a UDP datagram can carry.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > maxDatagram/4 {
		return 0, tooLarge(len(p))
	}
	c.wmu.Lock()
	enc := encoder{tables: c.mask.tables, rng: c.rng, chance: c.mask.paddingChance(c.rng)}
	size := len(p) * 4
	if enc.chance > 0 {
		size = len(p)*maxExpansion + 1
	}
	buf := pool.Get(size)
	defer pool.Put(buf)
	out := buf[:0]
	if len(p) > 0 {
		out = enc.finish(enc.encode(out, p))
	}
	c.wmu.Unlock()
	if len(out) > maxDatagram { // the padding made it too large
		return 0, tooLarge(len(p))
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func tooLarge(size int) error {
	return fmt.Errorf("sudoku: a datagram of %d bytes does not fit %d bytes once masked", size, maxDatagram)
}
