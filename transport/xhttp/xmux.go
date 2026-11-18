package xhttp

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/metacubex/http"
)

// This file gives the connection pool the meaning the xmux block has in
// Xray-core. It is used when ReuseConfig.XraySemantics is set, which the
// `xmux` key does; `reuse-settings` keeps the behaviour it always had.
//
// The differences:
//   - an empty block means the defaults of Xray;
//   - hMaxRequestTimes counts HTTP requests, not dials, and a connection that
//     ran out of them hands the following requests of a stream over to another
//     one, which is what keeps a long packet-up upload under the request limit
//     of a CDN or a web server. A connection serves exactly that many requests;
//     Xray moves a stream on one request earlier or later depending on where
//     in the stream the limit falls;
//   - cMaxReuseTimes counts the first use of a connection too;
//   - a connection that is used up, or past hMaxReusableSecs, leaves the pool
//     at once and makes room for a new one, while the streams that still run
//     on it keep it open.

// applyXmuxDefaults mirrors SplitHTTPConfig.Build of Xray-core.
func (c *ReuseConfig) applyXmuxDefaults() error {
	if c == nil || !c.XraySemantics {
		return nil
	}
	maxConcurrency, maxConnections, err := c.ResolveManagerConfig()
	if err != nil {
		return err
	}
	if maxConcurrency.Max > 0 && maxConnections.Max > 0 {
		return errors.New("max-connections cannot be specified together with max-concurrency")
	}
	cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, err := c.ResolveEntryConfig()
	if err != nil {
		return err
	}
	// Xray compares the parsed block with the zero one, so "0" is not set
	if maxConcurrency.Max == 0 && maxConnections.Max == 0 && cMaxReuseTimes.Max == 0 &&
		hMaxRequestTimes.Max == 0 && hMaxReusableSecs.Max == 0 && c.HKeepAlivePeriod == 0 {
		c.MaxConnections = "3"
		c.HMaxRequestTimes = "600-900"
		c.HMaxReusableSecs = "1800-3000"
	}
	return nil
}

func (entry *reuseEntry) expired(now time.Time) bool {
	return !entry.unreusableAt.IsZero() && now.After(entry.unreusableAt)
}

// usedUp reports whether the entry takes no new stream and no new request.
func (entry *reuseEntry) usedUp(now time.Time) bool {
	return entry.leftRequests.Load() <= 0 || entry.expired(now) ||
		(entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes)
}

// releaseEntry is reuseEntry.release under the lock of the pool, so that an
// entry is not closed while GetTransport hands it to another stream.
func (m *ReuseManager) releaseEntry(entry *reuseEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.release()
}

// acquireEntry takes a usage of a pooled entry for a stream that already runs.
func (m *ReuseManager) acquireEntry() (*reuseEntry, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, io.ErrClosedPipe
	}
	return m.GetTransport().(*ReuseTransport).entry, nil
}

// xmuxHeld is a pooled connection a stream holds: the current one, or an
// earlier one that still has requests of the stream in flight.
type xmuxHeld struct {
	entry    *reuseEntry
	inflight int
}

// xmuxState is the part of a ReuseTransport that follows Xray.
type xmuxState struct {
	manager *ReuseManager

	mu     sync.Mutex
	held   []*xmuxHeld // the last one takes the new requests
	closed bool
}

func newXmuxState(manager *ReuseManager, entry *reuseEntry) *xmuxState {
	return &xmuxState{manager: manager, held: []*xmuxHeld{{entry: entry}}}
}

// acquire returns the connection for the next request and counts the request
// against it, moving on to another connection when this one is used up.
func (x *xmuxState) acquire() (*xmuxHeld, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil, io.ErrClosedPipe
	}
	current := x.held[len(x.held)-1]
	// Other streams take requests of the same entries, so a fresh one may be
	// used up before this request gets to it: try again, a few times.
	for attempt := 0; ; attempt++ {
		entry := current.entry
		if entry.leftRequests.Add(-1) >= 0 && !entry.expired(time.Now()) && !entry.isClosed() {
			break
		}
		if attempt == 8 {
			if entry.isClosed() {
				return nil, io.ErrClosedPipe
			}
			break
		}
		nextEntry, err := x.manager.acquireEntry()
		if err != nil {
			return nil, err
		}
		next := &xmuxHeld{entry: nextEntry}
		x.held = append(x.held, next)
		if current.inflight == 0 {
			x.dropLocked(current)
		}
		current = next
	}
	current.inflight++
	return current, nil
}

// done is called when a request and its response body are finished.
func (x *xmuxState) done(held *xmuxHeld) {
	x.mu.Lock()
	defer x.mu.Unlock()
	held.inflight--
	if x.closed || held.inflight > 0 || held == x.held[len(x.held)-1] {
		return
	}
	x.dropLocked(held)
}

func (x *xmuxState) dropLocked(held *xmuxHeld) {
	for i, h := range x.held {
		if h == held {
			x.held = append(x.held[:i], x.held[i+1:]...)
			x.manager.releaseEntry(held.entry)
			return
		}
	}
}

func (x *xmuxState) close() {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return
	}
	x.closed = true
	for _, held := range x.held {
		x.manager.releaseEntry(held.entry)
	}
}

func (x *xmuxState) roundTrip(req *http.Request) (*http.Response, error) {
	held, err := x.acquire()
	if err != nil {
		return nil, err
	}
	resp, err := held.entry.transport.RoundTrip(req)
	if err != nil {
		x.done(held)
		return nil, err
	}
	resp.Body = &xmuxBody{ReadCloser: resp.Body, done: func() { x.done(held) }}
	return resp, nil
}

// xmuxBody reports the end of a response to the pool.
type xmuxBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *xmuxBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}
