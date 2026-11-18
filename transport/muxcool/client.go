package muxcool

import (
	"context"
	"net"
	"sync"

	M "github.com/metacubex/sing/common/metadata"
)

// DefaultConcurrency is the number of sessions Xray-core v26.11.9 puts on one
// carrier: it raises every "concurrency" from 0 to 128 to 128.
const DefaultConcurrency = 128

// xrayMaxSessions is how many sessions Xray-core opens on a carrier over its
// life before it lets the carrier drain.
const xrayMaxSessions = 1024

// DialFunc opens a carrier connection: a stream to Destination through the
// proxy the sessions are multiplexed over.
type DialFunc func(ctx context.Context) (net.Conn, error)

// Client spreads sessions over carriers, which it opens on demand.
type Client struct {
	dial   DialFunc
	limits Limits

	dialing chan struct{} // one new carrier at a time

	mu       sync.Mutex
	carriers []*Carrier
	closed   bool
}

// NewClient creates a client that puts up to concurrency sessions on a
// carrier; 0 or less means DefaultConcurrency.
func NewClient(dial DialFunc, concurrency int) *Client {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	return &Client{
		dial:    dial,
		limits:  Limits{MaxConcurrency: concurrency, MaxSessions: xrayMaxSessions},
		dialing: make(chan struct{}, 1),
	}
}

// DialContext opens a TCP session to destination.
func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var conn net.Conn
	err := c.open(ctx, func(carrier *Carrier) (err error) {
		conn, err = carrier.OpenStream(destination)
		return
	})
	return conn, err
}

// ListenPacket opens a UDP session, see Carrier.OpenPacket.
func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr, globalID [8]byte) (net.PacketConn, error) {
	var conn net.PacketConn
	err := c.open(ctx, func(carrier *Carrier) (err error) {
		conn, err = carrier.OpenPacket(destination, globalID)
		return
	})
	return conn, err
}

// open runs fn on a carrier that has room, dialing a new one if none has.
func (c *Client) open(ctx context.Context, fn func(*Carrier) error) error {
	if done, err := c.tryOpen(fn); done {
		return err
	}
	// Dial one carrier at a time, so that a burst of sessions shares it.
	select {
	case c.dialing <- struct{}{}:
		defer func() { <-c.dialing }()
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		if done, err := c.tryOpen(fn); done {
			return err
		}
		conn, err := c.dial(ctx)
		if err != nil {
			return err
		}
		carrier := NewCarrier(conn, c.limits)
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = carrier.Close()
			return net.ErrClosed
		}
		c.carriers = append(c.carriers, carrier)
		c.mu.Unlock()
	}
}

// tryOpen runs fn on the first carrier that takes a session.
func (c *Client) tryOpen(fn func(*Carrier) error) (done bool, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return true, net.ErrClosed
	}
	alive := c.carriers[:0]
	for _, carrier := range c.carriers {
		if !carrier.Closed() {
			alive = append(alive, carrier)
		}
	}
	for i := len(alive); i < len(c.carriers); i++ {
		c.carriers[i] = nil
	}
	c.carriers = alive
	carriers := append([]*Carrier(nil), alive...)
	c.mu.Unlock()

	for _, carrier := range carriers {
		if carrier.Full() {
			continue
		}
		err = fn(carrier)
		if err == nil {
			return true, nil
		}
		// the carrier filled up or died meanwhile, try the next one
	}
	return false, nil
}

// Carriers returns the number of open carriers.
func (c *Client) Carriers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, carrier := range c.carriers {
		if !carrier.Closed() {
			n++
		}
	}
	return n
}

// Close closes all carriers.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	carriers := c.carriers
	c.carriers = nil
	c.mu.Unlock()
	for _, carrier := range carriers {
		_ = carrier.Close()
	}
	return nil
}
