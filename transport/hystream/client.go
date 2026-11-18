// Package hystream is the client of the "hysteria" stream transport of
// Xray-core: a Hysteria 2 QUIC connection that carries the streams of any
// proxy protocol.
//
// The connection is set up and authenticated exactly like Hysteria 2 (HTTP/3
// POST to https://hysteria/auth). A stream then starts with the TCP request
// frame type 0x401 and nothing else of the Hysteria 2 proxy protocol: no
// address, no padding, no response. What follows is the payload of the proxy
// protocol, for instance VLESS. The hysteria2 outbound is the other use of
// the same connection, with the Hysteria 2 proxy protocol on top.
//
// On the server side this is an inbound of any protocol with
// streamSettings.network "hysteria" (Xray-core transport/internet/hysteria).
package hystream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/randv2"
	"github.com/metacubex/tls"
)

const (
	urlHost             = "hysteria"
	urlPath             = "/auth"
	headerAuth          = "Hysteria-Auth"
	headerCCRX          = "Hysteria-CC-RX"
	headerPadding       = "Hysteria-Padding"
	statusAuthOK        = 233
	frameTypeTCPRequest = 0x401

	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError

	streamReceiveWindow = 8388608                     // 8 MB, as Hysteria 2
	connReceiveWindow   = streamReceiveWindow * 5 / 2 // 20 MB
	maxIdleTimeout      = 30 * time.Second
	keepAlivePeriod     = 10 * time.Second
)

const paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// authPadding is the Hysteria-Padding of an auth request, 256 to 2047 characters.
func authPadding() string {
	bs := make([]byte, 256+randv2.IntN(2048-256))
	for i := range bs {
		bs[i] = paddingChars[randv2.IntN(len(paddingChars))]
	}
	return string(bs)
}

// DialFunc opens the QUIC connection to the server. The packet conn is closed
// together with the connection.
type DialFunc func(ctx context.Context, cfg *quic.Config) (net.PacketConn, *quic.Conn, error)

type Config struct {
	// Auth is hysteriaSettings.auth of the server.
	Auth string
	// ReceiveBPS is told to the server as the rate it may send at, in bytes
	// per second. Zero leaves the choice to the congestion control of the server.
	ReceiveBPS uint64
	Dial       DialFunc
	// OnConnected, when set, is called once the server has accepted the auth,
	// with the rate the server says it can receive at (zero when it did not
	// say). It is the place to set the congestion control of the connection.
	OnConnected func(conn *quic.Conn, serverReceiveBPS uint64)
}

// Client keeps one authenticated connection and opens streams on it.
type Client struct {
	cfg Config

	lock   chan struct{} // guards the fields below; a channel so that waiting for it ends with a context
	conn   *quic.Conn
	pc     net.PacketConn
	closed bool
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Dial == nil {
		return nil, errors.New("hysteria transport: no dialer")
	}
	return &Client{cfg: cfg, lock: make(chan struct{}, 1)}, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     streamReceiveWindow,
		MaxStreamReceiveWindow:         streamReceiveWindow,
		InitialConnectionReceiveWindow: connReceiveWindow,
		MaxConnectionReceiveWindow:     connReceiveWindow,
		MaxIdleTimeout:                 maxIdleTimeout,
		KeepAlivePeriod:                keepAlivePeriod,
	}
}

// connect returns the authenticated connection, opening a new one when there
// is none or the last one has ended.
func (c *Client) connect(ctx context.Context) (*quic.Conn, error) {
	select {
	case c.lock <- struct{}{}:
		defer func() { <-c.lock }()
	case <-ctx.Done(): // another stream is still dialing or authenticating
		return nil, ctx.Err()
	}
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.closeConnLocked(closeErrCodeOK)
		default:
			return c.conn, nil
		}
	}

	cfg := quicConfig()
	pc, conn, err := c.cfg.Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	serverRx, err := c.authenticate(ctx, conn, cfg)
	if err != nil {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pc.Close()
		return nil, err
	}
	if c.cfg.OnConnected != nil {
		c.cfg.OnConnected(conn, serverRx)
	}
	c.conn, c.pc = conn, pc
	return conn, nil
}

func (c *Client) authenticate(ctx context.Context, conn *quic.Conn, cfg *quic.Config) (uint64, error) {
	transport := &http3.Transport{
		QUICConfig: cfg,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: urlHost, Path: urlPath},
		Header: http.Header{
			headerAuth:    []string{c.cfg.Auth},
			headerCCRX:    []string{strconv.FormatUint(c.cfg.ReceiveBPS, 10)},
			headerPadding: []string{authPadding()},
		},
	}
	response, err := transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	_ = response.Body.Close()
	if response.StatusCode != statusAuthOK {
		return 0, fmt.Errorf("hysteria transport: auth failed, status code %d", response.StatusCode)
	}
	serverRx, _ := strconv.ParseUint(response.Header.Get(headerCCRX), 10, 64)
	return serverRx, nil
}

// Dial opens a stream.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		conn, err := c.connect(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := conn.OpenStream()
		if err != nil {
			// only a connection that has ended is replaced: when the server
			// has no stream to give, the streams that run keep running
			if conn.Context().Err() != nil && attempt == 0 && c.drop(ctx, conn) {
				continue
			}
			return nil, err
		}
		return &streamConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
	}
}

// drop forgets conn so that the next stream opens a new connection.
func (c *Client) drop(ctx context.Context, conn *quic.Conn) bool {
	select {
	case c.lock <- struct{}{}:
		defer func() { <-c.lock }()
	case <-ctx.Done():
		return false
	}
	if c.conn == conn {
		c.closeConnLocked(closeErrCodeOK)
	}
	return true
}

func (c *Client) closeConnLocked(code quic.ApplicationErrorCode) {
	if c.conn != nil {
		_ = c.conn.CloseWithError(code, "")
		_ = c.pc.Close()
		c.conn, c.pc = nil, nil
	}
}

func (c *Client) Close() error {
	c.lock <- struct{}{}
	defer func() { <-c.lock }()
	c.closed = true
	c.closeConnLocked(closeErrCodeOK)
	return nil
}

// streamConn is a stream of the connection. Its first write carries the frame
// type that tells the server what the stream is.
type streamConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr

	writeMu sync.Mutex
	started bool
}

func (c *streamConn) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *streamConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.started {
		return c.stream.Write(b)
	}
	// in one write, so that the frame type and the first bytes of the proxy
	// protocol leave together; and once only: when any of it has gone out, a
	// later write must not repeat the frame type
	prefix := quicvarint.Len(frameTypeTCPRequest)
	first := quicvarint.Append(make([]byte, 0, prefix+len(b)), frameTypeTCPRequest)
	n, err := c.stream.Write(append(first, b...))
	if n > 0 {
		c.started = true
	}
	if n -= prefix; n < 0 {
		n = 0
	}
	if err != nil {
		if c.started && n == 0 && len(b) > 0 {
			// the frame type went out in part: the stream cannot be continued
			c.stream.CancelWrite(0)
		}
		return n, err
	}
	return len(b), nil
}

// Close ends the stream. A write that is still under way, waiting for the
// peer to take data, is cancelled rather than waited for.
func (c *streamConn) Close() error {
	c.stream.CancelRead(0)
	if !c.writeMu.TryLock() {
		c.stream.CancelWrite(0)
		return nil
	}
	defer c.writeMu.Unlock()
	return c.stream.Close()
}

func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
