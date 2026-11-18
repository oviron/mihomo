package xdns

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"

	hostResolver "github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/transport/finalmask/mask"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// requestTimeout bounds one DNS over HTTPS request. The tunnel server keeps
// a query for a second at most, a resolver gives up within a few seconds.
const (
	requestTimeout  = 10 * time.Second
	idleConnTimeout = 30 * time.Second
)

// probesPathMTU tells whether QUIC looks for a larger packet size on this
// system. Xray-core does it on the same three.
var probesPathMTU = runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// dohResolver sends every query as a DNS over HTTPS request (RFC 8484, POST)
// over HTTP/2, HTTP/1.1 or HTTP/3.
type dohResolver struct {
	url     string
	client  *http.Client
	receive func(msg []byte)
	ctx     context.Context // ends with close
	cancel  context.CancelFunc

	// queue feeds the workers, each of which has one request under way at a
	// time. It holds one query per worker.
	queue sendQueue
	wg    sync.WaitGroup

	mu sync.Mutex
	// cooldown is the time before which the server asked not to be queried.
	cooldown time.Time
}

func newDoHResolver(rc resolverConfig, dialer mask.Dialer, tunnel link) *dohResolver {
	r := &dohResolver{
		url:     rc.addr,
		receive: tunnel.receive,
		queue:   newSendQueue(rc.worker, tunnel.room),
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	var transport http.RoundTripper
	if rc.http3() {
		transport = &http3.Transport{
			TLSClientConfig: rc.tls.Clone(),
			QUICConfig:      rc.quic.Clone(),
			Dial: func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
				conn, err := dialQUIC(ctx, dialer, addr, tlsConfig, config)
				if err == nil && rc.congestion == "bbr" { // New Reno is what QUIC starts with
					common.SetCongestionController(conn, "bbr", 0, rc.bbrProfile)
				}
				return conn, err
			},
		}
	} else {
		tlsConfig := rc.tls.Clone()
		transport = &http.Transport{
			// The handshake is made here and not by the transport, which
			// would add h2 and http/1.1 to the protocols the config offers.
			// Which of the two the connection speaks is up to the server.
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(ctx, dialTimeout)
				defer cancel()
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			ForceAttemptHTTP2: true,
			// also closes a connection that was busy when the resolver was closed
			IdleConnTimeout: idleConnTimeout,
			// HTTP/1.1 takes a connection per worker; the default keeps two
			// of them and sets up a new one for nearly every request
			MaxIdleConnsPerHost: rc.worker,
		}
	}
	r.client = &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		// A redirect is not followed: it could take the queries, which carry
		// the data of the tunnel, to another server, or out of HTTPS.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for i := 0; i < rc.worker; i++ {
		r.wg.Add(1)
		go r.work()
	}
	return r
}

// dialQUIC opens a QUIC connection to addr on a socket of its own, which is
// closed together with the connection.
func dialQUIC(ctx context.Context, dialer mask.Dialer, addr string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	ip, err := hostResolver.ResolveIPWithResolver(ctx, host, hostResolver.ProxyServerHostResolver)
	if err != nil {
		return nil, err
	}
	dest := netip.AddrPortFrom(ip.Unmap(), uint16(port))
	pc, err := dialer.ListenPacket(ctx, "udp", "", dest)
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{Conn: pc}
	transport.SetCreatedConn(true) // closes the socket with the transport
	transport.SetSingleUse(true)   // closes the transport with the connection
	conn, err := transport.DialEarly(ctx, net.UDPAddrFromAddrPort(dest), tlsConfig, config)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return conn, nil
}

func (r *dohResolver) work() {
	defer r.wg.Done()
	for {
		msg := r.queue.get(r.ctx.Done())
		if msg == nil {
			return
		}
		if !r.coolingDown() {
			r.exchange(msg)
		}
	}
}

func (r *dohResolver) coolingDown() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().Before(r.cooldown)
}

// exchange posts a query and passes on the answer.
func (r *dohResolver) exchange(msg []byte) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.url, bytes.NewReader(msg))
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "") // none
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		answer, err := io.ReadAll(io.LimitReader(resp.Body, maxDatagram+1))
		if err == nil && len(answer) >= 2 && len(answer) <= maxDatagram {
			// The answer is the one to this request, whatever message ID
			// an HTTP server or a cache on the way has left in it.
			copy(answer, msg[:2])
			r.receive(answer)
		}
	case http.StatusTooManyRequests:
		// The queries until Retry-After are dropped instead of sent.
		var until time.Time
		value := resp.Header.Get("Retry-After")
		if t, err := http.ParseTime(value); err == nil {
			until = t
		} else if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
			until = time.Now().Add(time.Duration(seconds) * time.Second)
		}
		r.mu.Lock()
		if until.After(r.cooldown) {
			r.cooldown = until
		}
		r.mu.Unlock()
	}
}

func (r *dohResolver) send(msg []byte) bool {
	return r.queue.put(msg)
}

// ready is false while the server asked not to be queried (Retry-After).
func (r *dohResolver) ready() bool {
	return !r.coolingDown()
}

func (r *dohResolver) close() {
	r.cancel()
	r.wg.Wait()
	if closer, ok := r.client.Transport.(io.Closer); ok {
		_ = closer.Close() // HTTP/3
	}
	r.client.CloseIdleConnections()
}
