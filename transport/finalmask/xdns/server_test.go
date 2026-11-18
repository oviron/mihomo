package xdns

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// testDialer opens the sockets of the resolvers without any mask.
type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (testDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// testQuery is a query as the server saw it.
type testQuery struct {
	msg  dnsmessage.Message
	wire int    // length of the query name on the wire
	data []byte // what the name carries
	at   time.Time
}

// testServer is the server end of the tunnel reduced to what the tests need:
// it takes the queries apart the way Xray-core's server does, and answers
// each at once with all the datagrams that wait for the client. With echo
// set, the datagrams of the client are the ones sent back.
type testServer struct {
	domains []*domain
	echo    bool

	mu        sync.Mutex
	queries   []testQuery
	fragments map[byte]map[byte][]byte
	pending   [][]byte
	received  chan []byte
	tcpConns  int // TCP connections taken
	badFrames int // messages of TCP connections that are no queries
}

func newTestServer(t *testing.T, names ...string) *testServer {
	s := &testServer{fragments: map[byte]map[byte][]byte{}, received: make(chan []byte, 1024)}
	for _, name := range names {
		d, err := newDomain(name, 0, 0, []int{1, 5, 16, 28}, 0)
		require.NoError(t, err)
		s.domains = append(s.domains, d)
	}
	return s
}

// push queues a datagram for the client.
func (s *testServer) push(datagram []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, datagram)
}

// seen returns the queries so far that are (polls) or are not polls.
func (s *testServer) seen(polls bool) []testQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []testQuery
	for _, q := range s.queries {
		if (len(q.data) > 8 && q.data[8] == pollRandom) == polls {
			out = append(out, q)
		}
	}
	return out
}

// serve answers one query. It returns nil for what the server ignores.
func (s *testServer) serve(raw []byte) []byte {
	var msg dnsmessage.Message
	if msg.Unpack(raw) != nil || msg.Header.Response || len(msg.Questions) != 1 {
		return nil
	}
	question := msg.Questions[0]
	query := testQuery{msg: msg, at: time.Now()}
	var d *domain
	for _, own := range s.domains {
		if own.contains(question.Name) {
			d = own
		}
	}
	msg.Header = dnsmessage.Header{ID: msg.Header.ID, Response: true, Authoritative: true}
	msg.Additionals = nil
	if d == nil {
		msg.Header.RCode = dnsmessage.RCodeNameError
		out, _ := msg.Pack()
		return out
	}
	data := d.decode(question.Name)

	s.mu.Lock()
	defer s.mu.Unlock()
	query.wire, query.data = 1, data
	for _, label := range splitLabels(question.Name) {
		query.wire += 1 + len(label)
	}
	s.queries = append(s.queries, query)
	if len(data) > queryHeader && data[8]&0x3F == dataRandom {
		var datagram []byte
		if data[8]&flagFragment == flagFragment {
			id, index, count := data[12], data[13], data[14]
			if s.fragments[id] == nil {
				s.fragments[id] = map[byte][]byte{}
			}
			s.fragments[id][index] = data[15:]
			if len(s.fragments[id]) == int(count) {
				for i := 0; i < int(count); i++ {
					datagram = append(datagram, s.fragments[id][byte(i)]...)
				}
				delete(s.fragments, id)
			}
		} else {
			datagram = data[12:]
		}
		if datagram != nil {
			select {
			case s.received <- datagram:
			default:
			}
			if s.echo {
				s.pending = append(s.pending, datagram)
			}
		}
	}

	var payload []byte
	for i, datagram := range s.pending {
		length := uint16(len(datagram))
		if i == len(s.pending)-1 {
			length |= 0xC000
		}
		payload = binary.BigEndian.AppendUint16(payload, length)
		payload = append(payload, datagram...)
	}
	s.pending = nil
	msg.Answers = testAnswers(d, question, payload)
	out, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return out
}

func splitLabels(name dnsmessage.Name) [][]byte {
	var labels [][]byte
	begin := 0
	for i := 0; i < int(name.Length); i++ {
		if name.Data[i] == '.' {
			labels = append(labels, name.Data[begin:i])
			begin = i + 1
		}
	}
	return labels
}

// testAnswers puts payload into records of the type the question asks for,
// as Xray-core's server does: TXT is one record of strings; the other types
// take one record per piece, a piece starting with its index and the first
// one having the number of pieces after that.
func testAnswers(d *domain, question dnsmessage.Question, payload []byte) []dnsmessage.Resource {
	header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
	if question.Type == dnsmessage.TypeTXT {
		txt := &dnsmessage.TXTResource{}
		for len(payload) > 0 {
			size := 255
			if size > len(payload) {
				size = len(payload)
			}
			txt.TXT = append(txt.TXT, string(payload[:size]))
			payload = payload[size:]
		}
		return []dnsmessage.Resource{{Header: header, Body: txt}}
	}
	size := map[dnsmessage.Type]int{dnsmessage.TypeA: 4, dnsmessage.TypeAAAA: 16, dnsmessage.TypeCNAME: d.cap}[question.Type]
	var pieces [][]byte
	for len(payload) > 0 {
		piece := []byte{byte(len(pieces))}
		if len(pieces) == 0 {
			piece = append(piece, 0)
		}
		n := size - len(piece)
		if n > len(payload) {
			n = len(payload)
		}
		pieces = append(pieces, append(piece, payload[:n]...))
		payload = payload[n:]
	}
	var answers []dnsmessage.Resource
	for _, piece := range pieces {
		if piece[0] == 0 {
			piece[1] = byte(len(pieces))
		}
		var body dnsmessage.ResourceBody
		switch question.Type {
		case dnsmessage.TypeA:
			a := &dnsmessage.AResource{}
			copy(a.A[:], piece)
			body = a
		case dnsmessage.TypeAAAA:
			aaaa := &dnsmessage.AAAAResource{}
			copy(aaaa.AAAA[:], piece)
			body = aaaa
		case dnsmessage.TypeCNAME:
			body = &dnsmessage.CNAMEResource{CNAME: d.encode(piece)}
		}
		answers = append(answers, dnsmessage.Resource{Header: header, Body: body})
	}
	return answers
}

// listenUDP serves the queries that come as datagrams.
func (s *testServer) listenUDP(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	_ = pc.(*net.UDPConn).SetReadBuffer(4 << 20) // the client sends in bursts
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer := s.serve(buf[:n]); answer != nil {
				_, _ = pc.WriteTo(answer, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// listenTCP serves the queries that come over TCP, each behind a two byte
// length. closeAfter, if not 0, closes every connection after that many
// queries.
func (s *testServer) listenTCP(t *testing.T, closeAfter int) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
			s.mu.Lock()
			s.tcpConns++
			s.mu.Unlock()
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for i := 0; closeAfter == 0 || i < closeAfter; i++ {
					if _, err := io.ReadFull(conn, buf[:2]); err != nil {
						return
					}
					n := binary.BigEndian.Uint16(buf)
					if _, err := io.ReadFull(conn, buf[:n]); err != nil {
						return
					}
					answer := s.serve(buf[:n])
					if answer == nil {
						s.mu.Lock()
						s.badFrames++
						s.mu.Unlock()
						continue
					}
					if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "tcp://" + l.Addr().String()
}

// testStalled is a TCP resolver that takes connections and never reads.
type testStalled struct {
	addr string

	mu    sync.Mutex
	conns []net.Conn
}

func listenStalled(t *testing.T) *testStalled {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &testStalled{addr: "tcp://" + l.Addr().String()}
	t.Cleanup(func() {
		_ = l.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, conn := range s.conns {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
		}
	}()
	return s
}

// accepted returns the number of connections so far.
func (s *testStalled) accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// testDoH is a DNS over HTTPS front of the server.
type testDoH struct {
	server *testServer
	url    string
	// fingerprint is the SHA-256 of the certificate, in hex.
	fingerprint string
	// status, if it returns one, is what a request is answered with, along
	// with a Retry-After header.
	status func() (int, string)

	mu         sync.Mutex
	protos     map[string]int
	offered    [][]string // the ALPN lists of the TLS connections
	conns      int        // QUIC connections
	badRequest string
}

func (h *testDoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.protos[r.Proto]++
	switch {
	case r.Method != http.MethodPost:
		h.badRequest = "method " + r.Method
	case r.Header.Get("Content-Type") != "application/dns-message", r.Header.Get("Accept") != "application/dns-message":
		h.badRequest = "content type or accept header"
	case r.Header.Get("User-Agent") != "":
		h.badRequest = "user agent " + r.Header.Get("User-Agent")
	case r.URL.Path != "/dns-query":
		h.badRequest = "path " + r.URL.Path
	}
	h.mu.Unlock()
	if h.status != nil {
		if status, value := h.status(); status != 0 {
			// what goes with the status: when to come back, or where to go
			w.Header().Set("Retry-After", value)
			if status >= 300 && status < 400 {
				w.Header().Set("Location", value)
			}
			w.WriteHeader(status)
			return
		}
	}
	answer := h.server.serve(body)
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(answer)
}

// requests returns the number of requests by HTTP version.
func (h *testDoH) requests() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int{}
	for proto, n := range h.protos {
		out[proto] = n
	}
	return out
}

func (h *testDoH) connections() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns
}

// resolver is the entry of the resolvers setting for this server. Its
// certificate is one nobody signed, so it is pinned.
func (h *testDoH) resolver(alpn ...string) map[string]any {
	tlsConfig := map[string]any{"pinned-peer-cert-sha256": h.fingerprint}
	if len(alpn) > 0 {
		tlsConfig["alpn"] = alpn
	}
	return map[string]any{"addrs": []any{h.url}, "tls-config": tlsConfig}
}

// listenDoH serves the queries over HTTPS: HTTP/2 and HTTP/1.1 on TCP.
func (s *testServer) listenDoH(t *testing.T) *testDoH {
	h := &testDoH{server: s, protos: map[string]int{}}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.offered = append(h.offered, hello.SupportedProtos)
		return nil, nil
	}}
	// connections the client gave up while they were being set up
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	h.url = server.URL + "/dns-query"
	h.fingerprint = ca.CalculateFingerprint(server.Certificate().Raw)
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	t.Cleanup(func() { require.Empty(t, h.badRequest) })
	return h
}

// listenDoH3 serves the queries over HTTP/3.
func (s *testServer) listenDoH3(t *testing.T) *testDoH {
	h := &testDoH{server: s, protos: map[string]int{}}
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	sum := sha256.Sum256(block.Bytes)
	h.fingerprint = hex.EncodeToString(sum[:])
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	h.url = "https://" + pc.LocalAddr().String() + "/dns-query"
	server := &http3.Server{
		Handler:   h,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.conns++
			return ctx
		},
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close(); _ = pc.Close() })
	t.Cleanup(func() { require.Empty(t, h.badRequest) })
	return h
}
