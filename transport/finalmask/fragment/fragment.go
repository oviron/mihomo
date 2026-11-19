// Package fragment is the "fragment" TCP mask of Xray-core's finalmask: it
// splits what the client writes into small pieces, either the TLS ClientHello
// into several TLS records or the chosen writes into TCP segments. The server
// needs no matching setting.
package fragment

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

func init() {
	mask.RegisterTCP("fragment", func(settings map[string]any) (mask.TCPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// Packets is "tlshello", a range of write numbers such as "1-3", or empty
	// for every write.
	Packets string `mask:"packets,omitempty"`
	// Length and Delay (milliseconds) apply to every piece; Lengths and Delays
	// give them per piece and take precedence, their last entry repeats.
	Length  mask.Range   `mask:"length,omitempty"`
	Delay   mask.Range   `mask:"delay,omitempty"`
	Lengths []mask.Range `mask:"lengths,omitempty"`
	Delays  []mask.Range `mask:"delays,omitempty"`
	// MaxSplit caps the number of pieces of one write, 0 is no cap.
	MaxSplit mask.Range `mask:"max-split,omitempty"`
}

// Mask is a parsed fragment mask.
type Mask struct {
	packetsFrom int64
	packetsTo   int64
	lengths     []mask.Range
	delays      []mask.Range
	maxSplit    mask.Range
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{maxSplit: options.MaxSplit}
	switch strings.ToLower(options.Packets) {
	case "tlshello":
		m.packetsFrom, m.packetsTo = 0, 1
	case "":
	default:
		from, to, err := mask.ParseRange(options.Packets)
		if err != nil {
			return nil, fmt.Errorf("packets: %w", err)
		}
		if from == 0 {
			return nil, fmt.Errorf("packets can't start from 0")
		}
		m.packetsFrom, m.packetsTo = int64(from), int64(to)
	}
	m.lengths = options.Lengths
	if len(m.lengths) == 0 {
		m.lengths = []mask.Range{options.Length}
	}
	if m.lengths[len(m.lengths)-1].From == 0 {
		return nil, fmt.Errorf("the minimum of the last length can't be 0")
	}
	m.delays = options.Delays
	if len(m.delays) == 0 {
		m.delays = []mask.Range{options.Delay}
	}
	for _, r := range append(append([]mask.Range{m.maxSplit}, m.lengths...), m.delays...) {
		if r.From < 0 {
			return nil, fmt.Errorf("negative value %s", r)
		}
	}
	if m.packetsFrom < 0 || m.packetsTo < m.packetsFrom {
		return nil, fmt.Errorf("invalid packets %q", options.Packets)
	}
	return m, nil
}

func (m *Mask) WrapConn(conn net.Conn) (net.Conn, error) {
	return &Conn{Conn: conn, mask: m}, nil
}

func (m *Mask) tlsHello() bool {
	return m.packetsFrom == 0 && m.packetsTo == 1
}

func (m *Mask) length(piece int64) mask.Range {
	if piece >= int64(len(m.lengths)) {
		piece = int64(len(m.lengths)) - 1
	}
	return m.lengths[piece]
}

func (m *Mask) delay(piece int64) mask.Range {
	if piece >= int64(len(m.delays)) {
		piece = int64(len(m.delays)) - 1
	}
	return m.delays[piece]
}

// Conn fragments the writes of the wrapped connection.
type Conn struct {
	net.Conn
	mask *Mask

	mu    sync.Mutex // keeps the pieces of concurrent writes apart
	count uint64
	done  atomic.Bool // no write will be fragmented any more
}

// Upstream, ReaderReplaceable and WriterReplaceable let the relay drop the
// wrapper: reads are never changed, writes are not once the mask is done.
func (c *Conn) Upstream() any {
	return c.Conn
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.done.Load()
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	m := c.mask
	c.count++
	count := c.count
	if m.tlsHello() || (m.packetsFrom != 0 && count >= uint64(m.packetsTo)) {
		// the last write the mask looks at
		defer c.done.Store(true)
	}

	if m.tlsHello() {
		return c.writeTLSHello(p, count)
	}

	if m.packetsFrom != 0 && (count < uint64(m.packetsFrom) || count > uint64(m.packetsTo)) {
		return c.Conn.Write(p)
	}
	maxSplit := m.maxSplit.Rand()
	var piece int64
	for from := 0; ; {
		to := from + int(m.length(piece).Rand())
		if to > len(p) || (maxSplit > 0 && piece+1 >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		if delay := m.delay(piece); delay.To > 0 {
			time.Sleep(time.Duration(delay.Rand()) * time.Millisecond)
		}
		piece++
		if from >= len(p) {
			return from, nil
		}
	}
}

// writeTLSHello splits the first TLS record of the first write, the
// ClientHello, into several records. With a single zero delay they leave in
// one write, otherwise each record is written on its own.
func (c *Conn) writeTLSHello(p []byte, count uint64) (int, error) {
	m := c.mask
	if count != 1 || len(p) <= 5 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	recordLen := 5 + (int(p[3])<<8 | int(p[4]))
	if len(p) < recordLen {
		return c.Conn.Write(p)
	}
	data := p[5:recordLen]
	merge := len(m.delays) == 1 && m.delays[0].To == 0
	var merged []byte
	maxSplit := m.maxSplit.Rand()
	var piece int64
	for from := 0; ; {
		to := from + int(m.length(piece).Rand())
		if to > len(data) || (maxSplit > 0 && piece+1 >= maxSplit) {
			to = len(data)
		}
		l := to - from
		record := make([]byte, 5+l)
		copy(record[:3], p)
		record[3] = byte(l >> 8)
		record[4] = byte(l)
		copy(record[5:], data[from:to])
		from = to
		if merge {
			merged = append(merged, record...)
		} else {
			_, err := c.Conn.Write(record)
			if delay := m.delay(piece); delay.To > 0 {
				time.Sleep(time.Duration(delay.Rand()) * time.Millisecond)
			}
			if err != nil {
				return 0, err
			}
		}
		piece++
		if from == len(data) {
			if len(merged) > 0 {
				if _, err := c.Conn.Write(merged); err != nil {
					return 0, err
				}
			}
			if len(p) > recordLen {
				n, err := c.Conn.Write(p[recordLen:])
				if err != nil {
					return recordLen + n, err
				}
			}
			return len(p), nil
		}
	}
}
