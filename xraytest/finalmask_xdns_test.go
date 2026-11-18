package xraytest

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// The xdns mask: VMess over mKCP through a DNS tunnel. The Xray inbound with
// the mask is the authoritative DNS server of the tunnel domain on its UDP
// port, so the client is given that port as its resolver, directly or behind
// a DNS over TCP or DNS over HTTPS front made here.
//
// Sizing. The server puts whole datagrams into a DNS answer and drops one
// that does not fit (finalmask/xdns/server.go, send), so mKCP on the server
// must not send a datagram larger than the smallest answer, which is the
// answer to a query with the longest name: fmXDNSTunnel.answerCap follows
// NewResp of resp.go. Every datagram costs 2 bytes of length in the answer,
// and mkcp-legacy below mKCP adds 6 bytes that kcpSettings.mtu does not
// count, hence mtu = answerCap - 8. For the domain t.example.com:
//
//	TXT    no EDNS   512-12-(255+4)-12 = 229 -> 228   mtu 220
//	TXT    1232      1232-12-259-11-12 = 938 -> 934   mtu 926
//	AAAA   no EDNS   241/28 = 8 records  -> 119       mtu 111
//	A      no EDNS   241/16 = 15 records -> 44        mtu 36
//	A      4096      3814/16 = 238       -> 713       mtu 705
//	CNAME  no EDNS   241/(12+255) = 0 records: nothing fits, EDNS is a must
//	CNAME  1232      950/267 = 3 records -> 437       mtu 429
//
// Xray accepts an mKCP MTU down to 21, and so does mihomo's mKCP with raw.
// The client needs no small MTU for its own datagrams: the mask splits one
// over as many queries as it takes (a query name carries 135 bytes, or 132
// of a datagram that is split) and the server puts them together again. The
// checks give both sides the same MTU, which is what a user would do, and
// one of them a large one to the client.
type fmXDNSTunnel struct {
	names      []string
	types      []int // 16 TXT when empty
	edns0      int
	lenLimit   int // 255 when 0
	labelLimit int // 63 when 0
	extraPoll  int
	// mtuExtra is added to the mKCP MTU of the server.
	mtuExtra int
	// clientMTU is the mKCP MTU of the client, that of the server when 0.
	clientMTU int
	// payload is the size of the TCP round trip, 1 MiB when 0.
	payload int
}

const fmXDNSDomain = "t.example.com"

func (tn fmXDNSTunnel) limits() (lenLimit, labelLimit int) {
	lenLimit, labelLimit = tn.lenLimit, tn.labelLimit
	if lenLimit == 0 {
		lenLimit = 255
	}
	if labelLimit == 0 {
		labelLimit = 63
	}
	return
}

// nameCap follows NewDomain of domain.go: the bytes one name under the
// domain carries and the length of the longest name on the wire.
func (tn fmXDNSTunnel) nameCap(name string) (bytes, wire int) {
	lenLimit, labelLimit := tn.limits()
	room := lenLimit - (len(name) + 1) - 1
	chars := room / (labelLimit + 1) * labelLimit
	if left := room % (labelLimit + 1); left > 1 {
		chars += left - 1
	}
	bytes = chars * 5 / 8
	chars = (bytes*8 + 4) / 5
	wire = len(name) + 1 + 1 + chars + (chars+labelLimit-1)/labelLimit
	return
}

// answerCap follows NewResp of resp.go: the bytes the server puts into the
// answer to the longest query of the given type.
func (tn fmXDNSTunnel) answerCap(name string, qtype int) int {
	bytes, wire := tn.nameCap(name)
	size := 512
	if tn.edns0 > size {
		size = tn.edns0
	}
	left := size - 12 - wire - 4 // the header and the question
	if tn.edns0 > 0 {
		left -= 11 // the OPT record
	}
	records := func(size int) int {
		if n := left / size; n < 255 {
			return n
		}
		return 255
	}
	switch qtype {
	case 1:
		return 3*records(12+4) - 1
	case 28:
		return 15*records(12+16) - 1
	case 5:
		return (bytes-1)*records(12+wire) - 1
	default:
		left -= 12 // the header of the one TXT record
		n := left / 255 * 254
		if m := left % 255; m > 1 {
			n += m - 1
		}
		return n
	}
}

// mtu is the largest mKCP MTU the server may use.
func (tn fmXDNSTunnel) mtu() int {
	types := tn.types
	if len(types) == 0 {
		types = []int{16}
	}
	smallest := 1 << 16
	for _, name := range tn.names {
		for _, qtype := range types {
			if n := tn.answerCap(name, qtype); n < smallest {
				smallest = n
			}
		}
	}
	return smallest - 2 - 6
}

func (tn fmXDNSTunnel) domains(xrayNames bool) []obj {
	domain := obj{"names": tn.names}
	set := func(key, xrayKey string, value int) {
		if value == 0 {
			return
		}
		if xrayNames {
			key = xrayKey
		}
		domain[key] = value
	}
	set("edns0", "edns0", tn.edns0)
	set("len-limit", "lenLimit", tn.lenLimit)
	set("label-limit", "labelLimit", tn.labelLimit)
	return []obj{domain}
}

// start runs Xray with a VMess inbound over mKCP behind the xdns mask and
// returns its port.
func (tn fmXDNSTunnel) start(t *testing.T) (*xray, int) {
	t.Helper()
	mtu := tn.mtu() + tn.mtuExtra
	require.GreaterOrEqual(t, mtu, 21, "nothing fits into the answers")
	port := freePort(t)
	inbound := fmKCPInbound(port, fmMask("mkcp-legacy", nil), fmMask("xdns", obj{"domains": tn.domains(true)}))
	inbound["streamSettings"].(obj)["kcpSettings"] = obj{"mtu": mtu}
	return startXray(t, inbound), port
}

// proxy is the mihomo outbound that reaches the tunnel through the resolvers.
func (tn fmXDNSTunnel) proxy(t *testing.T, resolvers []obj) C.Proxy {
	t.Helper()
	domains := tn.domains(false)
	if len(tn.types) > 0 {
		domains[0]["types"] = tn.types
	}
	mask := obj{"domains": domains, "resolvers": resolvers}
	if tn.extraPoll > 0 {
		mask["extra-poll"] = tn.extraPoll
	}
	mtu := tn.clientMTU
	if mtu == 0 {
		mtu = tn.mtu()
	}
	// port 9: the mask never sends to the server address
	return fmKCP(t, 9, obj{"raw": true, "mtu": mtu}, fmMask("mkcp-legacy", nil), fmMask("xdns", mask))
}

func fmXDNSResolver(addrs ...string) []obj {
	return []obj{{"addrs": addrs}}
}

// check pushes TCP and UDP traffic through the proxy and expects the server
// to have had room for every datagram.
func (tn fmXDNSTunnel) check(t *testing.T, x *xray, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	if tn.payload == 0 {
		checkTCP(t, proxy, tg)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
		require.NoError(t, err)
		defer conn.Close()
		echoRoundTrip(t, conn, 4)
		echoRoundTrip(t, conn, tn.payload)
	}
	checkUDP(t, proxy, tg)
	require.Zero(t, x.count("err size"), "the server dropped a datagram that did not fit into an answer")
}

// run starts the tunnel with a tap as the resolver, checks it and returns
// the queries of the client.
func (tn fmXDNSTunnel) run(t *testing.T, tg targets) []fmXDNSQuery {
	t.Helper()
	x, port := tn.start(t)
	tap := fmXDNSStartTap(t, port, tn.names...)
	tn.check(t, x, tn.proxy(t, fmXDNSResolver(tap.addr)), tg)
	return tap.seen()
}

// fmXDNSUpstream opens a socket to the DNS port of Xray.
func fmXDNSUpstream(t *testing.T, port int) net.Conn {
	conn, err := net.Dial("udp", loopback(port).String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// fmXDNSQuery is what a query of the client tells: its type, the size of the
// name and of the message, and the kind of payload.
type fmXDNSQuery struct {
	qtype    dnsmessage.Type
	domain   string
	wire     int  // the length of the name on the wire
	edns0    int  // the UDP payload size announced, 0 without EDNS
	poll     bool // carries nothing
	fragment bool // carries a piece of a datagram
	first    bool // carries a whole datagram or its first piece
	pieces   int  // the number of pieces of the datagram, 0 for a whole one
}

// fmXDNSTap is a UDP relay in front of the DNS port of Xray, the path a
// plain resolver would be, that keeps what the client asked.
type fmXDNSTap struct {
	addr    string
	domains []string

	mu      sync.Mutex
	queries []fmXDNSQuery
}

func fmXDNSStartTap(t *testing.T, port int, domains ...string) *fmXDNSTap {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	tap := &fmXDNSTap{addr: "udp://" + pc.LocalAddr().String(), domains: domains}
	upstream := fmXDNSUpstream(t, port)
	var client net.Addr
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = addr
			mu.Unlock()
			tap.record(buf[:n])
			_, _ = upstream.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			addr := client
			mu.Unlock()
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return tap
}

func (tap *fmXDNSTap) record(raw []byte) {
	var msg dnsmessage.Message
	if msg.Unpack(raw) != nil || len(msg.Questions) != 1 {
		return
	}
	name := strings.ToLower(msg.Questions[0].Name.String())
	q := fmXDNSQuery{qtype: msg.Questions[0].Type, wire: len(name) + 1}
	for _, additional := range msg.Additionals {
		if additional.Header.Type == dnsmessage.TypeOPT {
			q.edns0 = int(additional.Header.Class)
		}
	}
	for _, domain := range tap.domains {
		if strings.HasSuffix(name, "."+domain+".") {
			q.domain = domain
			text := strings.ReplaceAll(strings.TrimSuffix(name, domain+"."), ".", "")
			data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(text))
			if err != nil || len(data) < 9 {
				return
			}
			// the byte after the client ID: 8 for a poll, 3 for data, with
			// the two top bits set for a piece of a datagram, which has its ID
			// and then the number of the piece and how many there are
			q.poll = data[8] == 8
			q.fragment = data[8] == 3|0xC0
			q.first = data[8] == 3 || q.fragment && len(data) > 13 && data[13] == 0
			if q.fragment && len(data) > 14 {
				q.pieces = int(data[14])
			}
		}
	}
	tap.mu.Lock()
	defer tap.mu.Unlock()
	tap.queries = append(tap.queries, q)
}

func (tap *fmXDNSTap) seen() []fmXDNSQuery {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return append([]fmXDNSQuery(nil), tap.queries...)
}

// fmXDNSStartTCP is a DNS over TCP front of the DNS port of Xray: every
// message has a two byte length in front.
func fmXDNSStartTCP(t *testing.T, port int) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("udp", loopback(port).String())
			if err != nil {
				_ = conn.Close()
				continue
			}
			t.Cleanup(func() { _ = conn.Close(); _ = upstream.Close() })
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := io.ReadFull(conn, buf[:2]); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(buf))
					if n > 512 {
						t.Errorf("a DNS query of %d bytes: the stream is not framed", n)
						return
					}
					if _, err := io.ReadFull(conn, buf[:n]); err != nil {
						return
					}
					_, _ = upstream.Write(buf[:n])
				}
			}()
			go func() {
				buf := make([]byte, 2+4096)
				for {
					n, err := upstream.Read(buf[2:])
					if err != nil {
						return
					}
					binary.BigEndian.PutUint16(buf, uint16(n))
					if _, err := conn.Write(buf[:2+n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "tcp://" + l.Addr().String()
}

// fmXDNSDoH is a DNS over HTTPS front of the DNS port of Xray.
type fmXDNSDoH struct {
	port int

	mu     sync.Mutex
	protos map[string]int
}

func (h *fmXDNSDoH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.protos[r.Proto]++
	h.mu.Unlock()
	query, err := io.ReadAll(r.Body)
	if err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	upstream, err := net.Dial("udp", loopback(h.port).String())
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	// Xray answers at once or, under the load of these checks, not at all.
	_ = upstream.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = upstream.Write(query)
	buf := make([]byte, 4096)
	n, err := upstream.Read(buf)
	if err != nil {
		w.WriteHeader(http.StatusGatewayTimeout)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(buf[:n])
}

func (h *fmXDNSDoH) requests() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]int{}
	for proto, n := range h.protos {
		out[proto] = n
	}
	return out
}

func fmXDNSCertificate(t *testing.T) tls.Certificate {
	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)
	return cert
}

// fmXDNSStartDoH serves DNS over HTTPS on TCP (HTTP/2 and HTTP/1.1).
func fmXDNSStartDoH(t *testing.T, port int) (*fmXDNSDoH, string) {
	t.Helper()
	h := &fmXDNSDoH{port: port, protos: map[string]int{}}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fmXDNSCertificate(t)}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	// mKCP keeps its socket, and so the tunnel, for some seconds after the
	// connection is closed: do not wait for the client to hang up
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	return h, server.URL + "/dns-query"
}

// fmXDNSStartDoH3 serves DNS over HTTPS on QUIC (HTTP/3).
func fmXDNSStartDoH3(t *testing.T, port int) (*fmXDNSDoH, string) {
	t.Helper()
	h := &fmXDNSDoH{port: port, protos: map[string]int{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http3.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{fmXDNSCertificate(t)}}}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close(); _ = pc.Close() })
	return h, "https://" + pc.LocalAddr().String() + "/dns-query"
}

// fmXDNSPin is the tls-config that accepts the certificate of the DNS over
// HTTPS fronts, which nobody signed, and no other.
func fmXDNSPin(t *testing.T, alpn ...string) obj {
	t.Helper()
	block, _ := pem.Decode([]byte(tlsCertificate))
	require.NotNil(t, block)
	sum := sha256.Sum256(block.Bytes)
	tlsConfig := obj{"pinned-peer-cert-sha256": hex.EncodeToString(sum[:])}
	if len(alpn) > 0 {
		tlsConfig["alpn"] = alpn
	}
	return tlsConfig
}

func TestFinalmaskXDNSSizing(t *testing.T) {
	for _, c := range []struct {
		qtype, edns0, answer, mtu int
	}{
		{16, 0, 228, 220}, {16, 1232, 934, 926}, {28, 0, 119, 111}, {1, 0, 44, 36}, {1, 4096, 713, 705},
		{5, 0, -1, -9}, {5, 1232, 437, 429},
	} {
		tn := fmXDNSTunnel{names: []string{fmXDNSDomain}, types: []int{c.qtype}, edns0: c.edns0}
		require.Equal(t, c.answer, tn.answerCap(fmXDNSDomain, c.qtype), fmt.Sprint(c))
		require.Equal(t, c.mtu, tn.mtu(), fmt.Sprint(c))
	}
}

func TestFinalmaskXDNSRejectsBadOptions(t *testing.T) {
	domains := []obj{{"names": []string{fmXDNSDomain}}}
	resolvers := fmXDNSResolver("192.0.2.53")
	valid := fmMask("xdns", obj{"domains": domains, "resolvers": resolvers})
	for name, masks := range map[string][]obj{
		"no domains":   {fmMask("xdns", obj{"resolvers": resolvers})},
		"no resolvers": {fmMask("xdns", obj{"domains": domains})},
		"record type":  {fmMask("xdns", obj{"domains": []obj{{"names": []string{fmXDNSDomain}, "types": []int{15}}}, "resolvers": resolvers})},
		"edns0":        {fmMask("xdns", obj{"domains": []obj{{"names": []string{fmXDNSDomain}, "edns0": 100}}, "resolvers": resolvers})},
		"long domain":  {fmMask("xdns", obj{"domains": []obj{{"names": []string{fmXDNSDomain}, "lenLimit": 40}}, "resolvers": resolvers})},
		"scheme":       {fmMask("xdns", obj{"domains": domains, "resolvers": fmXDNSResolver("quic://192.0.2.53")})},
		"extra-poll":   {fmMask("xdns", obj{"domains": domains, "resolvers": resolvers, "extraPoll": 4})},
		"not the last": {valid, fmMask("mkcp-legacy", nil)},
		"twice":        {valid, valid},
		"allowInsecure": {fmMask("xdns", obj{"domains": domains, "resolvers": []obj{{
			"addrs": []string{"https://dns.example.org/dns-query"}, "tlsConfig": obj{"allowInsecure": true},
		}}})},
		"brutal": {fmMask("xdns", obj{"domains": domains, "resolvers": []obj{{
			"addrs": []string{"https://dns.example.org/dns-query"}, "quicConfig": obj{"congestion": "force-brutal", "brutalUp": "10m"},
		}}})},
	} {
		mapping := fmKCPMapping(443, obj{"raw": true}, masks...)
		mapping["name"], mapping["server"] = "xray", "127.0.0.1"
		_, err := adapter.ParseProxy(mapping)
		require.Error(t, err, name)
	}
	mapping := fmKCPMapping(443, obj{"raw": true}, fmMask("mkcp-legacy", nil), valid)
	mapping["name"], mapping["server"] = "xray", "127.0.0.1"
	_, err := adapter.ParseProxy(mapping)
	require.NoError(t, err)
}

func TestFinalmaskXDNS(t *testing.T) {
	tg := startTargets(t)
	one := []string{fmXDNSDomain}

	// TXT answers without EDNS, the defaults.
	t.Run("txt", func(t *testing.T) {
		var polls, fragments, longest int
		for _, q := range (fmXDNSTunnel{names: one}).run(t, tg) {
			require.Equal(t, dnsmessage.TypeTXT, q.qtype)
			require.Equal(t, fmXDNSDomain, q.domain)
			require.Zero(t, q.edns0)
			if q.poll {
				polls++
				require.Equal(t, 1+28+1+len(fmXDNSDomain)+1, q.wire, "a poll is 17 bytes, 28 characters")
			}
			if q.fragment {
				fragments++
			}
			if q.wire > longest {
				longest = q.wire
			}
		}
		require.Greater(t, polls, 100)
		// mKCP sends datagrams of up to 226 bytes, a query carries 135
		require.Greater(t, fragments, 1000)
		require.Equal(t, 255, longest)
	})

	// With EDNS the answers are larger. The settings have the names Xray
	// uses, and the resolver is given as host:port.
	t.Run("txt-edns0", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one, edns0: 1232}
		x, port := tn.start(t)
		tap := fmXDNSStartTap(t, port, fmXDNSDomain)
		proxy := fmKCP(t, 9, obj{"raw": true, "mtu": tn.mtu()}, fmMask("mkcp-legacy", nil), fmMask("xdns", obj{
			"domains":   []obj{{"names": one, "lenLimit": 255, "labelLimit": 63, "types": []int{16}, "edns0": 1232}},
			"resolvers": []obj{{"addrs": []string{strings.TrimPrefix(tap.addr, "udp://")}, "worker": 4}},
			"extraPoll": 0,
		}))
		tn.check(t, x, proxy, tg)
		var polls, datagrams int
		for _, q := range tap.seen() {
			require.Equal(t, 1232, q.edns0)
			if q.poll {
				polls++
			}
			if q.first {
				datagrams++
			}
		}
		// one poll for an answer with data, far less than what extra-poll
		// makes of it below
		require.Less(t, polls, datagrams)
	})

	// extra-poll sends more queries for the server to answer.
	t.Run("extra-poll", func(t *testing.T) {
		var polls, datagrams int
		for _, q := range (fmXDNSTunnel{names: one, edns0: 1232, extraPoll: 2}).run(t, tg) {
			if q.poll {
				polls++
			}
			if q.first {
				datagrams++
			}
		}
		// two polls with every datagram and three for every answer with data
		require.Greater(t, polls, 2*datagrams)
	})

	// The other record types. An A record carries 3 bytes: without EDNS an
	// answer holds 18 bytes of the stream, and the megabyte of the other
	// checks would take half a minute. CNAME does not work without EDNS.
	for name, tn := range map[string]fmXDNSTunnel{
		"a":           {types: []int{1}, payload: 64 << 10},
		"a-edns0":     {types: []int{1}, edns0: 4096},
		"aaaa":        {types: []int{28}},
		"aaaa-edns0":  {types: []int{28}, edns0: 1232},
		"cname-edns0": {types: []int{5}, edns0: 1232},
	} {
		tn := tn
		tn.names = one
		t.Run(name, func(t *testing.T) {
			for _, q := range tn.run(t, tg) {
				require.Equal(t, dnsmessage.Type(tn.types[0]), q.qtype)
				require.Equal(t, tn.edns0, q.edns0)
			}
		})
	}

	// The client may send datagrams that are larger than the server's: one of
	// 1206 bytes goes out in 10 queries.
	t.Run("uplink-fragmentation", func(t *testing.T) {
		most := 0
		for _, q := range (fmXDNSTunnel{names: one, edns0: 1232, clientMTU: 1200}).run(t, tg) {
			if q.pieces > most {
				most = q.pieces
			}
		}
		require.Equal(t, 10, most)
	})

	// Shorter names, as some resolvers want them.
	t.Run("len-limit", func(t *testing.T) {
		longest := 0
		for _, q := range (fmXDNSTunnel{names: one, lenLimit: 120, labelLimit: 30}).run(t, tg) {
			if q.wire > longest {
				longest = q.wire
			}
		}
		// 120-15 bytes: 3 labels of 30 characters and one of 11
		require.Equal(t, 15+3*31+12, longest)
	})

	// Two domains and every record type, picked at random per datagram.
	t.Run("several-domains-and-types", func(t *testing.T) {
		tn := fmXDNSTunnel{names: []string{"a.example.com", "tunnel.example.org"}, types: []int{1, 5, 16, 28}, edns0: 4096}
		used := map[string]bool{}
		for _, q := range tn.run(t, tg) {
			used[q.domain+" "+q.qtype.String()] = true
		}
		require.Len(t, used, 8, used)
	})

	// Resolvers reached over TCP and over HTTPS.
	t.Run("tcp-resolver", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one, edns0: 1232}
		x, port := tn.start(t)
		tn.check(t, x, tn.proxy(t, fmXDNSResolver(fmXDNSStartTCP(t, port))), tg)
	})

	for name, alpn := range map[string][]string{"doh": nil, "doh-http1": {"http/1.1"}, "doh-http3": {"h3"}} {
		alpn := alpn
		t.Run(name, func(t *testing.T) {
			tn := fmXDNSTunnel{names: one, edns0: 1232}
			x, port := tn.start(t)
			var doh *fmXDNSDoH
			var url, proto string
			resolver := obj{"tls-config": fmXDNSPin(t, alpn...)}
			switch name {
			case "doh":
				doh, url = fmXDNSStartDoH(t, port)
				proto = "HTTP/2.0"
			case "doh-http1":
				doh, url = fmXDNSStartDoH(t, port)
				proto = "HTTP/1.1"
			case "doh-http3":
				doh, url = fmXDNSStartDoH3(t, port)
				proto = "HTTP/3.0"
				// every setting of quicParams, as an Xray config may have them
				resolver["quic-config"] = obj{
					"congestion": "bbr", "bbrProfile": "aggressive", "debug": false,
					"brutalUp": "10m", "brutalDown": "10m", "brutalDisableLossCompensation": true,
					"initStreamReceiveWindow": 1 << 20, "maxStreamReceiveWindow": 1 << 21,
					"initConnectionReceiveWindow": 1 << 21, "maxConnectionReceiveWindow": 1 << 22,
					"maxIdleTimeout": 30, "keepAlivePeriod": 10, "disablePathMTUDiscovery": true,
					"disableChromeParrot": true, "disableGSO": true, "maxIncomingStreams": 16, "disableStatelessReset": true,
				}
			}
			resolver["addrs"] = []string{url}
			tn.check(t, x, tn.proxy(t, []obj{resolver}), tg)
			requests := doh.requests()
			require.Len(t, requests, 1, requests)
			require.Greater(t, requests[proto], 1000, requests)
		})
	}

	// All three kinds at once: the queries are spread over the resolvers. The
	// DNS over HTTPS one gets fewer, its workers wait for the answers that
	// do not come.
	t.Run("several-resolvers", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one, edns0: 1232}
		x, port := tn.start(t)
		tap := fmXDNSStartTap(t, port, fmXDNSDomain)
		doh, url := fmXDNSStartDoH(t, port)
		tn.check(t, x, tn.proxy(t, []obj{
			{"addrs": []string{tap.addr, fmXDNSStartTCP(t, port)}},
			{"addrs": []string{url}, "tlsConfig": fmXDNSPin(t, "h2")},
		}), tg)
		require.Greater(t, len(tap.seen()), 500)
		require.Greater(t, doh.requests()["HTTP/2.0"], 300)
	})

	// The certificate of a DNS over HTTPS resolver is verified: without the
	// pin the one nobody signed is refused.
	t.Run("doh-untrusted-certificate", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one, edns0: 1232}
		_, port := tn.start(t)
		doh, url := fmXDNSStartDoH(t, port)
		fmCheckFails(t, tn.proxy(t, fmXDNSResolver(url)), tg)
		require.Empty(t, doh.requests())
	})

	// The sizing above is exact: one byte more and the server has datagrams
	// that do not fit into the answers to the longest queries.
	t.Run("mtu-too-large", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one, mtuExtra: 1}
		x, port := tn.start(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := tn.proxy(t, fmXDNSResolver(loopback(port).String())).DialContext(ctx, tcpMetadata(tg.tcp))
		require.NoError(t, err)
		defer conn.Close()
		go func() { _, _ = io.Copy(io.Discard, conn) }()
		_, err = conn.Write(make([]byte, 256<<10))
		require.NoError(t, err)
		x.waitCount(t, "err size", 1)
	})

	// The server answers only for its own domain.
	t.Run("wrong-domain", func(t *testing.T) {
		tn := fmXDNSTunnel{names: one}
		x, port := tn.start(t)
		tn.names = []string{"t.example.org"}
		tap := fmXDNSStartTap(t, port, "t.example.org")
		fmCheckFails(t, tn.proxy(t, fmXDNSResolver(tap.addr)), tg)
		require.NotEmpty(t, tap.seen(), "the queries did reach the server")
		require.Zero(t, x.count("creating connection"))
	})

	// Without the mask on the server the queries are not mKCP to it.
	t.Run("server-without-mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmKCPInbound(port, fmMask("mkcp-legacy", nil)))
		fmCheckFails(t, (fmXDNSTunnel{names: one}).proxy(t, fmXDNSResolver(loopback(port).String())), tg)
	})
}
