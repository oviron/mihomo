package xhttp

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

// pipelineMaxInFlight bounds the POSTs sent ahead of their responses. The
// server puts packets that overtake each other back in order in a queue of
// scMaxBufferedPosts, 30 by default; staying well below keeps it from
// overflowing when requests travel over different connections.
const pipelineMaxInFlight = 16

// pipelinedWriter is the packet-up uploader of Xray-core (splithttp/dialer.go):
// what is written while a POST is on its way is batched into the next one, and
// the next one goes out as soon as the previous request is written, not when
// its response is back. PacketUpWriter waits for every response, which costs a
// round trip per POST, and delays the first byte by the posts interval.
//
// HTTP/1.1 has no multiplexing, so there the POSTs stay one at a time.
type pipelinedWriter struct {
	ctx       context.Context
	cancel    context.CancelFunc
	cfg       *Config
	maxSize   int
	interval  Range
	sessionID string
	transport http.RoundTripper

	multiplexed atomic.Bool // a response came over HTTP/2 or HTTP/3
	inFlight    chan struct{}
	posts       sync.WaitGroup
	loopDone    chan struct{}

	mu     sync.Mutex
	cond   sync.Cond
	buf    []byte
	err    error
	closed bool
}

func newPipelinedWriter(w *PacketUpWriter) *pipelinedWriter {
	p := &pipelinedWriter{
		ctx:       w.ctx,
		cancel:    w.cancel,
		cfg:       w.cfg,
		maxSize:   w.scMaxEachPostBytes,
		interval:  w.scMinPostsIntervalMs,
		sessionID: w.sessionID,
		transport: w.transport,
		inFlight:  make(chan struct{}, pipelineMaxInFlight),
		loopDone:  make(chan struct{}),
	}
	p.cond.L = &p.mu
	go p.loop()
	return p
}

func (p *pipelinedWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for len(b) > 0 {
		for len(p.buf) >= p.maxSize && p.err == nil && !p.closed {
			p.cond.Wait()
		}
		if p.err != nil {
			return written, p.err
		}
		if p.closed {
			return written, io.ErrClosedPipe
		}
		n := p.maxSize - len(p.buf)
		if n > len(b) {
			n = len(b)
		}
		p.buf = append(p.buf, b[:n]...)
		b = b[n:]
		written += n
		p.cond.Broadcast()
	}
	return written, nil
}

func (p *pipelinedWriter) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.cond.Broadcast()
}

// next waits for data and takes all of it, at most maxSize.
func (p *pipelinedWriter) next() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && p.err == nil && !p.closed {
		p.cond.Wait()
	}
	if p.err != nil || len(p.buf) == 0 {
		return nil
	}
	chunk := p.buf
	p.buf = nil
	p.cond.Broadcast()
	return chunk
}

func (p *pipelinedWriter) loop() {
	defer close(p.loopDone)
	var seq uint64
	var lastPost time.Time
	for {
		chunk := p.next()
		if chunk == nil {
			return
		}
		if wait := time.Duration(p.interval.Rand())*time.Millisecond - time.Since(lastPost); wait > 0 {
			select {
			case <-time.After(wait):
			case <-p.ctx.Done():
				return
			}
		}
		lastPost = time.Now()

		select {
		case p.inFlight <- struct{}{}:
		case <-p.ctx.Done():
			return
		}
		wrote := make(chan struct{})
		var wroteOnce sync.Once
		signal := func() { wroteOnce.Do(func() { close(wrote) }) }
		pipelined := p.multiplexed.Load()
		p.posts.Add(1)
		go func(seq uint64) {
			defer p.posts.Done()
			defer func() { <-p.inFlight }()
			defer signal()
			ctx := p.ctx
			if pipelined { // otherwise the next POST waits for this response
				ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
					WroteRequest: func(httptrace.WroteRequestInfo) { signal() },
				})
			}
			if err := p.post(ctx, seq, chunk); err != nil {
				p.fail(err)
			}
		}(seq)
		seq++
		select {
		case <-wrote:
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *pipelinedWriter) post(ctx context.Context, seq uint64, data []byte) error {
	u := url.URL{
		Scheme:   "https",
		Host:     p.cfg.Host,
		Path:     p.cfg.NormalizedPath(),
		RawQuery: p.cfg.NormalizedQuery(),
	}
	req, err := http.NewRequestWithContext(ctx, p.cfg.GetNormalizedUplinkHTTPMethod(), u.String(), nil)
	if err != nil {
		return err
	}
	if err := p.cfg.FillPacketRequest(req, p.sessionID, strconv.FormatUint(seq, 10), data); err != nil {
		return err
	}
	req.Host = p.cfg.Host

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}
	if resp.ProtoMajor >= 2 {
		p.multiplexed.Store(true)
	}
	return nil
}

// Close sends what is still buffered, waits a moment for the POSTs under way
// and lets go of the transport, like PacketUpWriter.Close.
func (p *pipelinedWriter) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cond.Broadcast()

	flushed := make(chan struct{})
	go func() {
		<-p.loopDone
		p.posts.Wait()
		close(flushed)
	}()
	select {
	case <-flushed:
	case <-time.After(time.Second):
	}
	p.cancel()
	httputils.CloseTransport(p.transport)
	return nil
}
