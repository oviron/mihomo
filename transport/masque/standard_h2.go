package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	// maxH2Datagram bounds a DATAGRAM capsule: an IP packet with its context
	// ID. A longer one is skipped.
	maxH2Datagram = 1 << 16
	// h2DatagramQueue is how many received packets wait for the reader
	// before the next ones are dropped, as packets are on any full queue.
	h2DatagramQueue = 256
	// h2WriteTimeout is how long the peer may leave a write unread before
	// the tunnel is given up.
	h2WriteTimeout = 30 * time.Second
)

// ConnectTunnelStandardH2 is ConnectTunnelStandard over HTTP/2: an extended
// CONNECT whose request and response bodies carry capsules (RFC 9297). IP
// packets travel in DATAGRAM capsules next to the control capsules, so the
// tunnel works where UDP does not.
//
// conn is a connection that has negotiated HTTP/2. The returned closer ends
// the HTTP/2 connection and conn.
func ConnectTunnelStandardH2(ctx context.Context, conn net.Conn, connectUri string, header map[string][]string) (io.Closer, *connectip.Conn, error) {
	template, err := uritemplate.New(connectUri)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: invalid URI: %w", err)
	}
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ip: IP flow forwarding not supported")
	}
	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	// The HTTP library of this repository does not send extended CONNECT;
	// golang.org/x/net/http2 does.
	transport := &http2.Transport{
		ReadIdleTimeout: 30 * time.Second, // ping an idle connection
		PingTimeout:     15 * time.Second,
	}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to start HTTP/2: %w", err)
	}

	// The request outlives ctx, which only bounds the handshake.
	reqCtx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	fail := func(err error) (io.Closer, *connectip.Conn, error) {
		cancel()
		_ = pr.Close()
		_ = pw.Close()
		_ = cc.Close()
		return nil, nil, err
	}
	req, err := stdhttp.NewRequestWithContext(reqCtx, stdhttp.MethodConnect, u.String(), pr)
	if err != nil {
		return fail(fmt.Errorf("connect-ip: failed to create request: %w", err))
	}
	req.ContentLength = -1
	req.Header = make(stdhttp.Header)
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header[":protocol"] = []string{"connect-ip"}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")

	stop := contextutils.AfterFunc(ctx, cancel)
	rsp, err := cc.RoundTrip(req)
	stop()
	if err != nil {
		return fail(fmt.Errorf("connect-ip: failed to send request: %w", err))
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		_ = rsp.Body.Close()
		return fail(fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode))
	}

	stream := &h2CapsuleStream{
		requestBody:  pw,
		responseBody: rsp.Body,
		cancel:       cancel,
		datagrams:    make(chan []byte, h2DatagramQueue),
		done:         make(chan struct{}),
	}
	stream.control, stream.controlWriter = io.Pipe()
	go stream.run()
	go stream.watch()
	return h2Closer{cc, conn}, connectip.NewProxiedConn(stream), nil
}

type h2Closer struct {
	cc   *http2.ClientConn
	conn net.Conn
}

func (c h2Closer) Close() error {
	_ = c.cc.Close()
	return c.conn.Close()
}

// h2CapsuleStream gives connect-ip-go the stream it expects from HTTP/3: the
// control capsules as a byte stream, the IP packets as datagrams. Over HTTP/2
// both arrive as capsules in the response body and leave in the request body.
type h2CapsuleStream struct {
	requestBody  *io.PipeWriter
	responseBody io.ReadCloser
	cancel       context.CancelFunc

	writeMu    sync.Mutex
	writeSince atomic.Int64 // when the write in progress began, in unix nanoseconds; 0 if none

	datagrams     chan []byte    // payloads of DATAGRAM capsules
	control       *io.PipeReader // the other capsules, as they came
	controlWriter *io.PipeWriter

	closeOnce sync.Once
	done      chan struct{}
	err       error // set before done is closed
}

var _ connectip.Http3Stream = (*h2CapsuleStream)(nil)

// run splits the response body into datagrams and control capsules.
func (s *h2CapsuleStream) run() {
	err := s.split()
	if err == nil {
		err = io.EOF
	}
	s.shutdown(err)
}

func (s *h2CapsuleStream) split() error {
	reader := quicvarint.NewReader(s.responseBody)
	for {
		capsuleType, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		length, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		if capsuleType != h2DatagramCapsuleType {
			// Passed on as it came; connect-ip-go skips the types it does not know.
			head := quicvarint.Append(quicvarint.Append(nil, capsuleType), length)
			if _, err = s.controlWriter.Write(head); err != nil {
				return err
			}
			if _, err = io.CopyN(s.controlWriter, reader, int64(length)); err != nil {
				return err
			}
			continue
		}
		if length > maxH2Datagram {
			if _, err = io.CopyN(io.Discard, reader, int64(length)); err != nil {
				return err
			}
			continue
		}
		payload := make([]byte, length)
		if _, err = io.ReadFull(reader, payload); err != nil {
			return err
		}
		select {
		case s.datagrams <- payload:
		default: // nobody reads fast enough; the control capsules must not wait for that
		}
	}
}

// watch gives the tunnel up when the peer stops taking what is written: an
// exhausted HTTP/2 window would block the sender for ever.
func (s *h2CapsuleStream) watch() {
	ticker := time.NewTicker(h2WriteTimeout / 6)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		if since := s.writeSince.Load(); since != 0 && time.Since(time.Unix(0, since)) > h2WriteTimeout {
			s.shutdown(errors.New("connect-ip: the peer stopped reading"))
			return
		}
	}
}

func (s *h2CapsuleStream) shutdown(err error) {
	s.closeOnce.Do(func() {
		s.err = err
		close(s.done)
		s.cancel() // first: it resets the stream, which lets go of a stuck write
		_ = s.controlWriter.CloseWithError(err)
		_ = s.requestBody.Close()
		go s.responseBody.Close() // may wait for the transport
	})
}

// Read returns the control capsules.
func (s *h2CapsuleStream) Read(p []byte) (int, error) {
	return s.control.Read(p)
}

// Write sends control capsules.
func (s *h2CapsuleStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.writeSince.Store(time.Now().UnixNano())
	defer s.writeSince.Store(0)
	return s.requestBody.Write(p)
}

func (s *h2CapsuleStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-s.datagrams:
		return payload, nil
	default:
	}
	select {
	case payload := <-s.datagrams:
		return payload, nil
	case <-s.done:
		return nil, s.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *h2CapsuleStream) SendDatagram(data []byte) error {
	frame := make([]byte, 0, 1+quicvarint.Len(uint64(len(data)))+len(data))
	frame = quicvarint.Append(frame, h2DatagramCapsuleType)
	frame = quicvarint.Append(frame, uint64(len(data)))
	frame = append(frame, data...)
	_, err := s.Write(frame)
	return err
}

func (s *h2CapsuleStream) CancelRead(quic.StreamErrorCode) {
	s.shutdown(io.ErrClosedPipe)
}

func (s *h2CapsuleStream) Close() error {
	s.shutdown(io.ErrClosedPipe)
	return nil
}
