package xdns

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

const testDomain = "t.example.com"

var testDest = netip.MustParseAddrPort("192.0.2.1:443")

// dial opens the tunnel of a mask with the given settings.
func dial(t *testing.T, settings map[string]any) net.PacketConn {
	t.Helper()
	m, err := mask.BuildUDP("xdns", settings)
	require.NoError(t, err)
	_, err = m.WrapPacketConn(nil, testDest)
	require.Error(t, err, "the mask is a carrier")
	pc, err := m.(mask.UDPCarrier).DialPacketConn(context.Background(), testDialer{}, testDest)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// settings are the settings of a mask with one domain and the given entries
// of resolvers: addresses, or whole entries as testDoH.resolver makes them.
func settings(domain map[string]any, resolvers ...any) map[string]any {
	if domain == nil {
		domain = map[string]any{}
	}
	domain["names"] = []any{testDomain}
	entries := make([]any, 0, len(resolvers))
	for _, resolver := range resolvers {
		if addr, ok := resolver.(string); ok {
			resolver = map[string]any{"addrs": []any{addr}}
		}
		entries = append(entries, resolver)
	}
	return map[string]any{"domains": []any{domain}, "resolvers": entries}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return b
}

// echo sends a datagram and expects it back from the server address.
func echo(t *testing.T, pc net.PacketConn, size int) {
	t.Helper()
	data := randomBytes(size)
	// the address given to WriteTo does not matter
	n, err := pc.WriteTo(data, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 9})
	require.NoError(t, err)
	require.Equal(t, size, n)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 8192)
	n, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, buf[:n]), "echoed datagram differs (sent %d, got %d bytes)", size, n)
	require.Equal(t, testDest.String(), from.String(), "packets come from the server address")
}

// eventually waits for a condition that is expected to become true.
func eventually(t *testing.T, condition func() bool, msg string) {
	t.Helper()
	require.Eventually(t, condition, 10*time.Second, 5*time.Millisecond, msg)
}

func TestDomainCapacity(t *testing.T) {
	// len-limit 255 leaves 255-15 bytes after "t.example.com": 3 labels of 63
	// characters and one of 47, 236 characters of base32, 147 bytes.
	d, err := newDomain(testDomain, 0, 0, nil, 0)
	require.NoError(t, err)
	require.Equal(t, 147, d.cap)
	require.Equal(t, 4096, d.limit())
	require.Equal(t, []dnsmessage.Type{dnsmessage.TypeTXT}, d.types)

	name := d.encode(bytes.Repeat([]byte{0xA5}, d.cap))
	require.Equal(t, 254, int(name.Length)) // 255 bytes on the wire
	labels := splitLabels(name)
	require.Len(t, labels, 7)
	for _, label := range labels[:3] {
		require.Len(t, label, 63)
		require.Regexp(t, regexp.MustCompile(`^[a-z2-7]+$`), string(label))
	}
	require.Len(t, labels[3], 47)
	require.Equal(t, bytes.Repeat([]byte{0xA5}, d.cap), d.decode(name))

	// 100-15 bytes: 4 labels of 20 characters, 80 characters, 50 bytes
	d, err = newDomain(testDomain, 100, 20, nil, 0)
	require.NoError(t, err)
	require.Equal(t, 50, d.cap)
	name = d.encode(make([]byte, d.cap))
	require.Equal(t, 98, int(name.Length)) // the 100th byte would be a label of no characters
	for _, label := range splitLabels(name)[:4] {
		require.Len(t, label, 20)
	}

	// Names are matched whatever their case; resolvers may change it.
	mixed := dnsmessage.MustNewName("MFRGG.T.Example.COM.")
	require.True(t, d.contains(mixed))
	require.Equal(t, []byte("abc"), d.decode(mixed))
	require.True(t, sameName(mixed, dnsmessage.MustNewName("mfrgg.t.example.com.")))
	require.False(t, sameName(mixed, dnsmessage.MustNewName("mfrgh.t.example.com.")))
	require.False(t, d.contains(dnsmessage.MustNewName("t.example.com.")), "the domain itself carries nothing")
	require.Nil(t, d.decode(dnsmessage.MustNewName("mfrgg.t.example.org.")))
	require.Nil(t, d.decode(dnsmessage.MustNewName("m!rgg.t.example.com.")))
}

func TestSettings(t *testing.T) {
	resolvers := []any{map[string]any{"addrs": []any{"192.0.2.53"}}}
	domains := []any{map[string]any{"names": []any{testDomain}}}
	domain := func(key string, value any) []any {
		return []any{map[string]any{"names": []any{testDomain}, key: value}}
	}
	resolver := func(addr string, key string, value any) map[string]any {
		return map[string]any{"domains": domains, "resolvers": []any{map[string]any{"addrs": []any{addr}, key: value}}}
	}
	const doh = "https://dns.example/dns-query"
	for name, s := range map[string]map[string]any{
		"nothing":            {},
		"no domains":         {"resolvers": resolvers},
		"no names":           {"resolvers": resolvers, "domains": []any{map[string]any{"types": []any{16}}}},
		"no resolvers":       {"domains": domains},
		"no addrs":           {"domains": domains, "resolvers": []any{map[string]any{"worker": 4}}},
		"extra-poll 4":       {"domains": domains, "resolvers": resolvers, "extra-poll": 4},
		"extra-poll -1":      {"domains": domains, "resolvers": resolvers, "extraPoll": -1},
		"empty label":        {"resolvers": resolvers, "domains": []any{map[string]any{"names": []any{"t..example.com"}}}},
		"trailing dot":       {"resolvers": resolvers, "domains": []any{map[string]any{"names": []any{"t.example.com."}}}},
		"empty name":         {"resolvers": resolvers, "domains": []any{map[string]any{"names": []any{""}}}},
		"label of 64":        {"resolvers": resolvers, "domains": []any{map[string]any{"names": []any{strings.Repeat("a", 64) + ".com"}}}},
		"len-limit 256":      {"resolvers": resolvers, "domains": domain("len-limit", 256)},
		"len-limit negative": {"resolvers": resolvers, "domains": domain("lenLimit", -1)},
		"label-limit 64":     {"resolvers": resolvers, "domains": domain("label-limit", 64)},
		"len-limit short":    {"resolvers": resolvers, "domains": domain("len-limit", 10)},
		"capacity below 17":  {"resolvers": resolvers, "domains": domain("len-limit", 43)},
		"type MX":            {"resolvers": resolvers, "domains": domain("types", []any{16, 15})},
		"edns0 511":          {"resolvers": resolvers, "domains": domain("edns0", 511)},
		"edns0 4097":         {"resolvers": resolvers, "domains": domain("edns0", 4097)},
		"scheme":             resolver("tls://192.0.2.53", "worker", 1),
		"no host":            resolver("udp://:53", "worker", 1),
		"worker":             resolver(doh, "worker", -1),
		"pinned certificate": resolver(doh, "tls-config", map[string]any{"pinnedPeerCertSha256": "xyz"}),
		"allow-insecure":     resolver(doh, "tls-config", map[string]any{"allow-insecure": true}),
		"allowInsecure":      resolver(doh, "tlsConfig", map[string]any{"allowInsecure": true}),
		"tls of a udp entry": resolver("192.0.2.53", "tlsConfig", map[string]any{"allowInsecure": true}),
		"unknown tls field":  resolver(doh, "tls-config", map[string]any{"fingerprint": "chrome"}),
		"alpn":               resolver(doh, "tls-config", map[string]any{"alpn": []any{1}}),
		"brutal":             resolver(doh, "quic-config", map[string]any{"congestion": "brutal"}),
		"force-brutal":       resolver(doh, "quicConfig", map[string]any{"congestion": "force-brutal", "brutalUp": "10m"}),
		"congestion":         resolver(doh, "quic-config", map[string]any{"congestion": "cubic"}),
		"bbr profile":        resolver(doh, "quic-config", map[string]any{"bbr-profile": "fast"}),
		"small window":       resolver(doh, "quic-config", map[string]any{"init-stream-receive-window": 1000}),
		"negative window":    resolver(doh, "quic-config", map[string]any{"maxConnectionReceiveWindow": -1}),
		"idle timeout":       resolver(doh, "quic-config", map[string]any{"max-idle-timeout": 3}),
		"keep-alive":         resolver(doh, "quic-config", map[string]any{"keepAlivePeriod": 61}),
		"incoming streams":   resolver(doh, "quic-config", map[string]any{"max-incoming-streams": 7}),
	} {
		_, err := New(s)
		require.Error(t, err, name)
	}

	// 44 bytes of len-limit leave room for 28 characters, 17 bytes: the least
	// that carries a poll. A datagram is then 255 pieces of 2 bytes at most.
	m, err := New(map[string]any{"resolvers": resolvers, "domains": domain("len-limit", 44)})
	require.NoError(t, err)
	require.Equal(t, 17, m.domains[0].cap)
	require.Equal(t, 510, m.limit)

	// The names Xray-core uses in JSON, every kind of resolver address.
	m, err = New(map[string]any{
		"domains": []any{
			map[string]any{"names": []any{"a.example.com", "b.example.org"}, "lenLimit": 200, "labelLimit": 40, "types": []any{1, 5, 16, 28}, "edns0": 1232},
			map[string]any{"names": []any{"c.example.net"}},
		},
		"resolvers": []any{
			map[string]any{"addrs": []any{"192.0.2.53", "[2001:db8::53]:5353", "udp://dns.example", "tcp://192.0.2.54:5353", "tcp://dns.example"}},
			map[string]any{
				"addrs": []any{doh}, "worker": 4,
				"tlsConfig": map[string]any{"serverName": "front.example", "alpn": []any{"h3"}},
				"quicConfig": map[string]any{
					"congestion": "BBR", "bbrProfile": "Aggressive",
					"initStreamReceiveWindow": 16384, "maxStreamReceiveWindow": 32768,
					"initConnectionReceiveWindow": 65536, "maxConnectionReceiveWindow": 131072,
					"maxIdleTimeout": 30, "keepAlivePeriod": 10, "disablePathMTUDiscovery": true, "maxIncomingStreams": 8,
					// no counterpart here
					"debug": true, "disableGSO": true, "disableChromeParrot": true, "disableStatelessReset": true,
					"brutalUp": "10m", "brutalDown": "10m", "brutalDisableLossCompensation": true,
				},
			},
			map[string]any{"addrs": []any{"https://dns.example:8443/q"}},
			map[string]any{"addrs": []any{doh}, "tls-config": map[string]any{"alpn": "h2"}},
		},
		"extraPoll": 3,
	})
	require.NoError(t, err)
	require.Len(t, m.domains, 3)
	require.Equal(t, uint16(1232), m.domains[1].edns0)
	require.Equal(t, 40, m.domains[1].labelLimit)
	require.Len(t, m.domains[0].types, 4)
	require.Equal(t, 3, m.extraPoll)
	require.Equal(t, 4096, m.limit)
	var addrs []string
	for _, rc := range m.resolvers {
		addrs = append(addrs, rc.scheme+" "+rc.addr)
	}
	require.Equal(t, []string{
		"udp 192.0.2.53:53", "udp [2001:db8::53]:5353", "udp dns.example:53", "tcp 192.0.2.54:5353", "tcp dns.example:53",
		"https " + doh, "https https://dns.example:8443/q", "https " + doh,
	}, addrs)
	h3, h2, onlyH2 := m.resolvers[5], m.resolvers[6], m.resolvers[7]
	require.True(t, h3.http3())
	require.Equal(t, 4, h3.worker)
	require.Equal(t, "front.example", h3.tls.ServerName)
	require.Equal(t, "bbr", h3.congestion)
	require.Equal(t, "aggressive", h3.bbrProfile)
	require.Equal(t, uint64(16384), h3.quic.InitialStreamReceiveWindow)
	require.Equal(t, uint64(32768), h3.quic.MaxStreamReceiveWindow)
	require.Equal(t, uint64(65536), h3.quic.InitialConnectionReceiveWindow)
	require.Equal(t, uint64(131072), h3.quic.MaxConnectionReceiveWindow)
	require.Equal(t, 30*time.Second, h3.quic.MaxIdleTimeout)
	require.Equal(t, 10*time.Second, h3.quic.KeepAlivePeriod)
	require.True(t, h3.quic.DisablePathMTUDiscovery)
	require.Equal(t, int64(8), h3.quic.MaxIncomingStreams)
	require.False(t, h2.http3())
	require.Equal(t, 32, h2.worker)
	require.Equal(t, "dns.example", h2.tls.ServerName)
	require.Equal(t, []string{"h2", "http/1.1"}, h2.tls.NextProtos)
	require.False(t, h2.tls.InsecureSkipVerify)
	require.Equal(t, time.Duration(0), h2.quic.MaxIdleTimeout)
	require.Equal(t, []string{"h2"}, onlyH2.tls.NextProtos)
}

// The layout of the queries, as Xray-core's server expects it.
func TestQueryWireFormat(t *testing.T) {
	server := newTestServer(t, testDomain)
	pc := dial(t, settings(map[string]any{"types": []any{28}, "edns0": 1232}, server.listenUDP(t)))

	small := randomBytes(147 - 12) // the most one query carries
	large := randomBytes(1000)     // 8 fragments of 147-15 bytes
	for _, datagram := range [][]byte{small, large} {
		_, err := pc.WriteTo(datagram, nil)
		require.NoError(t, err)
		require.Equal(t, datagram, <-server.received)
	}
	queries := server.seen(false)
	require.Len(t, queries, 1+8)
	clientID := queries[0].data[:8]
	require.Equal(t, byte(3), clientID[0]&3, "the two low bits name the record type, 3 is AAAA")
	fragmentID := queries[1].data[12]
	ids := map[uint16]bool{}
	for i, q := range queries {
		header := q.msg.Header
		ids[header.ID] = true
		require.Equal(t, dnsmessage.Header{ID: header.ID, RecursionDesired: true}, header)
		require.Equal(t, dnsmessage.TypeAAAA, q.msg.Questions[0].Type)
		require.Equal(t, dnsmessage.ClassINET, q.msg.Questions[0].Class)
		require.Len(t, q.msg.Additionals, 1)
		require.Equal(t, dnsmessage.TypeOPT, q.msg.Additionals[0].Header.Type)
		require.Equal(t, dnsmessage.Class(1232), q.msg.Additionals[0].Header.Class)
		require.LessOrEqual(t, q.wire, 255)
		require.Equal(t, clientID, q.data[:8])
		if i == 0 {
			require.Equal(t, byte(dataRandom), q.data[8])
			require.Equal(t, small, q.data[12:])
			require.Equal(t, 255, q.wire)
			continue
		}
		require.Equal(t, byte(dataRandom|flagFragment), q.data[8])
		require.Equal(t, queries[1].data[9:12], q.data[9:12])
		require.Equal(t, []byte{fragmentID, byte(i - 1), 8}, q.data[12:15])
		if i < 8 {
			require.Len(t, q.data, 147)
		} else {
			require.Len(t, q.data, 15+1000-7*132)
		}
	}
	require.Greater(t, len(ids), 5, "message IDs are random")

	// A datagram of 4096 bytes is the largest, and it is 32 queries.
	_, err := pc.WriteTo(nil, nil)
	require.Error(t, err)
	_, err = pc.WriteTo(make([]byte, 4097), nil)
	require.Error(t, err)
	large = randomBytes(4096)
	_, err = pc.WriteTo(large, nil)
	require.NoError(t, err)
	require.Equal(t, large, <-server.received)
	queries = server.seen(false)
	require.Len(t, queries, 9+32)
	require.Equal(t, fragmentID+1, queries[9].data[12])
	require.Empty(t, server.seen(true), "no polls before the server has sent anything")
}

func TestQueryWithoutEDNS(t *testing.T) {
	server := newTestServer(t, testDomain)
	pc := dial(t, settings(map[string]any{"len-limit": 60, "label-limit": 10}, server.listenUDP(t)))
	// 60-15 bytes: 4 labels of 10 characters, 40 characters, 25 bytes
	data := randomBytes(13)
	_, err := pc.WriteTo(data, nil)
	require.NoError(t, err)
	require.Equal(t, data, <-server.received)
	data = randomBytes(14) // one byte more than a query carries: 2 fragments of 10 bytes
	_, err = pc.WriteTo(data, nil)
	require.NoError(t, err)
	require.Equal(t, data, <-server.received)
	queries := server.seen(false)
	require.Len(t, queries, 3)
	require.Empty(t, queries[0].msg.Additionals)
	require.Equal(t, 59, queries[0].wire)
	require.Equal(t, byte(2), queries[0].data[0]&3, "TXT")
	for _, label := range splitLabels(queries[0].msg.Questions[0].Name)[:4] {
		require.Len(t, label, 10)
	}
	require.Len(t, queries[1].data, 25)
	require.Len(t, queries[2].data, 15+4)
}

// A datagram that needs more than 255 queries is refused: the transport
// above has to hear that its MTU does not fit the tunnel.
func TestDatagramTooLarge(t *testing.T) {
	server := newTestServer(t, testDomain)
	// 17 bytes per name leave 2 bytes for a piece of a datagram
	pc := dial(t, settings(map[string]any{"len-limit": 44}, server.listenUDP(t)))
	for i := 0; i < 2; i++ {
		n, err := pc.WriteTo(make([]byte, 511), nil)
		require.ErrorContains(t, err, "511 bytes is too large, the tunnel carries 510")
		require.Zero(t, n)
	}
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, server.seen(false), "nothing is sent of a datagram that does not fit")
	// 255 queries at once may be more than the socket of the test server
	// holds while it is busy; a transport would send the datagram again.
	data := randomBytes(510)
	var got []byte
	for attempt := 0; attempt < 10 && got == nil; attempt++ {
		_, err := pc.WriteTo(data, nil)
		require.NoError(t, err)
		select {
		case got = <-server.received:
		case <-time.After(2 * time.Second):
		}
	}
	require.Equal(t, data, got)
	queries := server.seen(false)
	require.GreaterOrEqual(t, len(queries), 255)
	for _, q := range queries {
		require.Equal(t, byte(255), q.data[queryHeader+2], "the datagram is split over 255 queries")
	}

	// With several domains a datagram goes to one that carries it.
	server = newTestServer(t, testDomain, "wide.example.org")
	s := settings(map[string]any{"len-limit": 44}, server.listenUDP(t))
	s["domains"] = append(s["domains"].([]any), map[string]any{"names": []any{"wide.example.org"}})
	pc = dial(t, s)
	for i := 0; i < 20; i++ {
		data := randomBytes(600)
		_, err := pc.WriteTo(data, nil)
		require.NoError(t, err)
		require.Equal(t, data, <-server.received)
	}
	_, err := pc.WriteTo(make([]byte, 4097), nil)
	require.ErrorContains(t, err, "the tunnel carries 4096")
}

// The answers, as Xray-core's server builds them.
func TestResponsePayload(t *testing.T) {
	d, err := newDomain(testDomain, 0, 0, []int{1, 5, 16, 28}, 0)
	require.NoError(t, err)
	question := func(qtype dnsmessage.Type) dnsmessage.Question {
		return dnsmessage.Question{Name: d.encode([]byte("some query")), Type: qtype, Class: dnsmessage.ClassINET}
	}
	a := func(q dnsmessage.Question, b ...byte) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: [4]byte{b[0], b[1], b[2], b[3]}},
		}
	}
	abc := [][]byte{[]byte("abc")}

	// "abcd" as the only and last datagram, in three A records out of order
	// with padding in the last one
	q := question(dnsmessage.TypeA)
	msg := &dnsmessage.Message{Questions: []dnsmessage.Question{q}}
	answers := func(records ...dnsmessage.Resource) [][]byte {
		msg.Answers = records
		return splitDatagrams(d.payload(msg))
	}
	require.Equal(t, [][]byte{[]byte("abcd")}, answers(a(q, 1, 'a', 'b', 'c'), a(q, 2, 'd', 0, 0), a(q, 0, 3, 0xC0, 0x04)))
	// the first, the last or a middle record is missing
	require.Nil(t, answers(a(q, 1, 'a', 'b', 'c'), a(q, 2, 'd', 0, 0)))
	require.Nil(t, answers(a(q, 1, 'a', 'b', 'c'), a(q, 0, 3, 0xC0, 0x04)))
	require.Nil(t, answers(a(q, 2, 'd', 0, 0), a(q, 0, 3, 0xC0, 0x04)))
	require.Nil(t, answers(a(q, 2, 'd', 0, 0), a(q, 0, 2, 0xC0, 0x04)), "a gap is no shorter answer")
	// two records with one index, a record too many
	require.Equal(t, abc, answers(a(q, 0, 2, 0xC0, 0x03), a(q, 1, 'a', 'b', 'c')))
	require.Nil(t, answers(a(q, 0, 2, 0xC0, 0x03), a(q, 1, 'a', 'b', 'c'), a(q, 1, 'a', 'b', 'c')))
	require.Nil(t, answers(a(q, 0, 2, 0xC0, 0x03), a(q, 1, 'a', 'b', 'c'), a(q, 2, 0, 0, 0)))
	// Records of another name or type do not count, be it a name under the
	// domain. The case of the letters does not matter.
	other, sibling, upper := q, q, q
	other.Name = dnsmessage.MustNewName("mfrgg.t.example.org.")
	sibling.Name = d.encode([]byte("another query"))
	upper.Name = dnsmessage.MustNewName(strings.ToUpper(q.Name.String()))
	aaaa := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{9}},
	}
	require.Equal(t, abc, answers(a(q, 0, 2, 0xC0, 0x03), a(other, 5, 0, 0, 0), a(sibling, 2, 0, 0, 0), a(upper, 1, 'a', 'b', 'c'), aaaa))
	require.Nil(t, answers(a(q, 0, 2, 0xC0, 0x03), a(sibling, 1, 'a', 'b', 'c')))

	// every type, with one datagram and with several
	first, second, third := randomBytes(1), randomBytes(300), randomBytes(77)
	one := append([]byte{0xC0, 1}, first...)
	three := append(append(append(append(append([]byte{0, 1}, first...), 1, 44), second...), 0xC0, 77), third...)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME} {
		q := question(qtype)
		msg := &dnsmessage.Message{Questions: []dnsmessage.Question{q}, Answers: testAnswers(d, q, one)}
		require.Equal(t, [][]byte{first}, splitDatagrams(d.payload(msg)), qtype)
		msg.Answers = testAnswers(d, q, three)
		require.Equal(t, [][]byte{first, second, third}, splitDatagrams(d.payload(msg)), qtype)
		msg.Answers = msg.Answers[:len(msg.Answers)-1]
		require.Empty(t, splitDatagrams(d.payload(msg)), qtype)
		msg.Answers = testAnswers(d, q, nil)
		require.Empty(t, splitDatagrams(d.payload(msg)), qtype)
	}
	// the TXT answer must be a single record, of the name that was asked for
	q = question(dnsmessage.TypeTXT)
	msg = &dnsmessage.Message{Questions: []dnsmessage.Question{q}, Answers: testAnswers(d, q, one)}
	msg.Answers = append(msg.Answers, msg.Answers[0])
	require.Nil(t, d.payload(msg))
	msg.Answers = testAnswers(d, sibling, one)
	require.Nil(t, d.payload(msg))

	// what is not closed by a last datagram is dropped
	require.Nil(t, splitDatagrams([]byte{0, 1, 'x'}))
	require.Nil(t, splitDatagrams([]byte{0, 1, 'x', 0xC0}))
	require.Nil(t, splitDatagrams([]byte{0, 1, 'x', 0xC0, 2, 'y'}))
	require.Nil(t, splitDatagrams([]byte{0xC0, 2, 'y'}))
	require.Equal(t, [][]byte{{'x'}, {'y', 'z'}}, splitDatagrams([]byte{0, 1, 'x', 0xC0, 2, 'y', 'z', 0, 0, 0}))
}

// bareConn is a tunnel without resolvers and without polling, to hand
// answers to.
func bareConn(t *testing.T, resolvers int, domain map[string]any) *conn {
	m, err := New(settings(domain, "192.0.2.53"))
	require.NoError(t, err)
	return newBareConn(m, resolvers)
}

// An answer counts when it is the answer to a query that resolver was given:
// the same message ID, name and type, once.
func TestAnswerHasToMatchAQuery(t *testing.T) {
	c := bareConn(t, 2, map[string]any{"types": []any{1, 16}})
	d := c.mask.domains[0]
	name := d.encode([]byte("some query"))
	sibling := d.encode([]byte("another query"))
	answer := func(id uint16, name dnsmessage.Name, qtype dnsmessage.Type) []byte {
		question := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, Response: true},
			Questions: []dnsmessage.Question{question},
			Answers:   testAnswers(d, question, []byte{0xC0, 1, 'x'}),
		}
		raw, err := msg.Pack()
		require.NoError(t, err)
		return raw
	}
	ask := func() {
		c.sent[0].add(queryKey{id: 7, qtype: dnsmessage.TypeTXT, name: lowerName(name)}, d)
	}
	queued := func() int {
		n := len(c.readCh)
		for len(c.readCh) > 0 {
			<-c.readCh
		}
		return n
	}

	c.receive(0, answer(7, name, dnsmessage.TypeTXT))
	require.Zero(t, queued(), "nothing was asked")
	ask()
	c.receive(0, answer(8, name, dnsmessage.TypeTXT))
	c.receive(0, answer(7, sibling, dnsmessage.TypeTXT))
	c.receive(0, answer(7, name, dnsmessage.TypeA))
	c.receive(1, answer(7, name, dnsmessage.TypeTXT))
	require.Zero(t, queued(), "another ID, name, type or resolver")
	c.receive(0, answer(7, name, dnsmessage.TypeTXT))
	require.Equal(t, 1, queued())
	c.receive(0, answer(7, name, dnsmessage.TypeTXT))
	require.Zero(t, queued(), "an answer counts once")

	// the name in another case, as a resolver may send it back
	ask()
	c.receive(0, answer(7, dnsmessage.MustNewName(strings.ToUpper(name.String())), dnsmessage.TypeTXT))
	require.Equal(t, 1, queued())

	// The queries that were not answered are forgotten after a while.
	ask()
	c.sent[0].mu.Lock()
	query := c.sent[0].recent[queryKey{id: 7, qtype: dnsmessage.TypeTXT, name: lowerName(name)}]
	query.at = time.Now().Add(-queryTTL - time.Second)
	c.sent[0].recent[queryKey{id: 7, qtype: dnsmessage.TypeTXT, name: lowerName(name)}] = query
	c.sent[0].mu.Unlock()
	c.receive(0, answer(7, name, dnsmessage.TypeTXT))
	require.Zero(t, queued())
	for i := 0; i < 3*maxSentQueries; i++ {
		c.sent[0].add(queryKey{id: uint16(i), qtype: dnsmessage.TypeTXT, name: strconv.Itoa(i)}, d)
	}
	require.LessOrEqual(t, len(c.sent[0].recent)+len(c.sent[0].older), 2*maxSentQueries)

	// A reader that does not read loses datagrams, the tunnel goes on.
	for i := 0; i < readQueue+10; i++ {
		ask()
		c.receive(0, answer(7, name, dnsmessage.TypeTXT))
	}
	require.Equal(t, readQueue, queued())
}

// Whatever a resolver sends back, the client takes it or leaves it.
func TestReceiveSurvivesBrokenAnswers(t *testing.T) {
	c := bareConn(t, 1, map[string]any{"types": []any{1, 5, 16, 28}})
	d := c.mask.domains[0]
	got := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range c.readCh {
			got++
		}
	}()
	// two datagrams, of 3 and of 300 bytes, and padding
	payload := append(append([]byte{0, 3, 'a', 'b', 'c', 0xC1, 0x2C}, randomBytes(300)...), 0, 0, 0)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME} {
		question := dnsmessage.Question{Name: d.encode([]byte("some query")), Type: qtype, Class: dnsmessage.ClassINET}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true},
			Questions: []dnsmessage.Question{question},
			Answers:   testAnswers(d, question, payload),
		}
		valid, err := msg.Pack()
		require.NoError(t, err)
		key := queryKey{qtype: qtype, name: lowerName(question.Name)}
		c.sent[0].add(key, d)
		c.receive(0, valid)
		for i := 0; i < 20000; i++ {
			broken := append([]byte(nil), valid...)
			for flips := 1 + i%4; flips > 0; flips-- {
				// mostly behind the question, where the records are
				at := rand.Intn(len(broken))
				if i%3 != 0 && len(broken) > 80 {
					at = 80 + rand.Intn(len(broken)-80)
				}
				broken[at] = byte(rand.Intn(256))
			}
			if i%5 == 0 {
				broken = broken[:rand.Intn(len(broken))]
			}
			c.sent[0].add(key, d)
			c.receive(0, broken)
		}
	}
	close(c.readCh)
	<-done
	require.GreaterOrEqual(t, got, 4*2, "every valid answer carries two datagrams")
}

// dohFor starts the DNS over HTTPS front named by transport and returns it
// with its entry of the resolvers setting.
func dohFor(t *testing.T, server *testServer, transport string) (*testDoH, map[string]any, string) {
	switch transport {
	case "https":
		doh := server.listenDoH(t)
		return doh, doh.resolver(), "HTTP/2.0"
	case "h2":
		doh := server.listenDoH(t)
		return doh, doh.resolver("h2"), "HTTP/2.0"
	case "http1":
		doh := server.listenDoH(t)
		return doh, doh.resolver("http/1.1"), "HTTP/1.1"
	default:
		doh := server.listenDoH3(t)
		return doh, doh.resolver("h3"), "HTTP/3.0"
	}
}

func TestEchoOverEveryResolverAndType(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "https", "h2", "http1", "http3"} {
		for _, qtype := range []int{16, 1, 28, 5} {
			transport, qtype := transport, qtype
			t.Run(transport+"/"+strconv.Itoa(qtype), func(t *testing.T) {
				t.Parallel()
				server := newTestServer(t, testDomain)
				server.echo = true
				domain := map[string]any{"types": []any{qtype}}
				var s map[string]any
				var doh *testDoH
				var proto string
				switch transport {
				case "udp":
					s = settings(domain, server.listenUDP(t))
				case "tcp":
					s = settings(domain, server.listenTCP(t, 0))
				default:
					var entry map[string]any
					doh, entry, proto = dohFor(t, server, transport)
					s = settings(domain, entry)
				}
				pc := dial(t, s)
				// 600 bytes are 200 A records, an answer of some 3.5 KB
				for _, size := range []int{1, 135, 136, 600} {
					echo(t, pc, size)
				}
				if doh == nil {
					return
				}
				requests := doh.requests()
				require.Len(t, requests, 1, requests)
				require.Greater(t, requests[proto], 0, requests)
				// The client offers the protocols of its config and no other.
				doh.mu.Lock()
				defer doh.mu.Unlock()
				want := map[string][]string{"https": {"h2", "http/1.1"}, "h2": {"h2"}, "http1": {"http/1.1"}}[transport]
				for _, offered := range doh.offered {
					require.Equal(t, want, offered)
				}
			})
		}
	}
}

// A certificate nobody signed is refused, unless it is the pinned one.
func TestDoHVerifiesTheCertificate(t *testing.T) {
	server := newTestServer(t, testDomain)
	server.echo = true
	doh := server.listenDoH(t)
	for name, tlsConfig := range map[string]map[string]any{
		"not pinned":  nil,
		"another pin": {"pinned-peer-cert-sha256": strings.Repeat("ab", 32)},
	} {
		entry := map[string]any{"addrs": []any{doh.url}}
		if tlsConfig != nil {
			entry["tls-config"] = tlsConfig
		}
		pc := dial(t, settings(nil, entry))
		_, err := pc.WriteTo([]byte("ping"), nil)
		require.NoError(t, err)
		time.Sleep(300 * time.Millisecond)
		require.Empty(t, doh.requests(), name)
		require.Empty(t, server.seen(false), name)
	}
	echo(t, dial(t, settings(nil, map[string]any{
		"addrs": []any{doh.url}, "tlsConfig": map[string]any{"pinnedPeerCertSha256": strings.Repeat("cd", 32) + "," + doh.fingerprint},
	})), 100)
}

// quic-config reaches the QUIC connection of an HTTP/3 resolver: a
// connection that idles for longer than max-idle-timeout is closed and the
// next query opens another, unless keep-alive-period keeps it.
func TestDoH3QUICConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		quic        map[string]any
		connections int
	}{
		"idle timeout": {map[string]any{"max-idle-timeout": 4}, 2},
		"keep-alive":   {map[string]any{"maxIdleTimeout": 4, "keepAlivePeriod": 2, "congestion": "bbr", "bbrProfile": "conservative"}, 1},
	} {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newTestServer(t, testDomain) // sends nothing, so the client does not poll
			doh := server.listenDoH3(t)
			entry := doh.resolver("h3")
			entry["quic-config"] = tc.quic
			pc := dial(t, settings(nil, entry))
			// arrives sends datagrams until one gets through: the query that
			// finds the connection closed is lost.
			arrives := func() {
				eventually(t, func() bool {
					if _, err := pc.WriteTo([]byte("ping"), nil); err != nil {
						return false
					}
					select {
					case <-server.received:
						return true
					case <-time.After(200 * time.Millisecond):
						return false
					}
				}, "no query got through")
			}
			arrives()
			require.Equal(t, 1, doh.connections())
			time.Sleep(5500 * time.Millisecond)
			arrives()
			require.Equal(t, tc.connections, doh.connections())
		})
	}
}

func TestSeveralDomainsAndTypes(t *testing.T) {
	server := newTestServer(t, "a.example.com", "b.example.org")
	server.echo = true
	pc := dial(t, map[string]any{
		"domains":   []any{map[string]any{"names": []any{"a.example.com", "b.example.org"}, "types": []any{1, 5, 16, 28}}},
		"resolvers": []any{map[string]any{"addrs": []any{server.listenUDP(t)}}},
	})
	for i := 0; i < 80; i++ {
		echo(t, pc, 100+i)
	}
	used := map[string]bool{}
	for _, q := range server.seen(false) {
		name := q.msg.Questions[0].Name.String()
		used[name[len(name)-14:]+q.msg.Questions[0].Type.String()] = true
		require.Equal(t, q.data[0]&3, typeCodes[q.msg.Questions[0].Type])
	}
	require.Len(t, used, 8, "every domain with every type")
}

// seconds is the time between two queries.
func seconds(from, to testQuery) float64 {
	return to.at.Sub(from.at).Seconds()
}

// The client polls once for every answer with data, and on its own with a
// growing interval.
func TestPolling(t *testing.T) {
	server := newTestServer(t, testDomain)
	pc := dial(t, settings(nil, server.listenUDP(t)))
	buf := make([]byte, 100)
	read := func(want string) {
		t.Helper()
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Second)))
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, want, string(buf[:n]))
	}

	_, err := pc.WriteTo([]byte("first"), nil)
	require.NoError(t, err)
	time.Sleep(700 * time.Millisecond)
	require.Empty(t, server.seen(true), "no polls before the first datagram of the server")

	// The answer to the next query brings data and polling starts. The first
	// poll leaves half a second later and fetches the datagram queued
	// meanwhile; that answer had data, so the second poll follows at once.
	// The server has no more, and the next polls come after 0.5, 1 and 2
	// seconds. The bounds leave room for a slow machine.
	server.push([]byte("one"))
	_, err = pc.WriteTo([]byte("second"), nil)
	require.NoError(t, err)
	read("one")
	server.push([]byte("two"))
	read("two")
	eventually(t, func() bool { return len(server.seen(true)) >= 5 }, "five polls")
	data, polls := server.seen(false), server.seen(true)
	require.InDelta(t, 0.5, seconds(data[1], polls[0]), 0.3)
	require.Less(t, seconds(polls[0], polls[1]), 0.3)
	require.InDelta(t, 0.5, seconds(polls[1], polls[2]), 0.3)
	require.InDelta(t, 1, seconds(polls[2], polls[3]), 0.5)
	require.InDelta(t, 2, seconds(polls[3], polls[4]), 0.8)
	for _, poll := range polls {
		require.Len(t, poll.data, 17)
		require.Equal(t, data[0].data[:8], poll.data[:8])
	}

	// Several datagrams in one answer are one poll, sent at once and not
	// after the two seconds and more the interval has grown to.
	server.push([]byte("three"))
	server.push([]byte("four"))
	before := len(server.seen(true))
	_, err = pc.WriteTo([]byte("third"), nil)
	require.NoError(t, err)
	read("three")
	read("four")
	eventually(t, func() bool { return len(server.seen(true)) > before }, "a poll for the answer with data")
	data, polls = server.seen(false), server.seen(true)
	require.Less(t, seconds(data[2], polls[before]), 0.3)
	if len(polls) > before+1 {
		require.Greater(t, seconds(polls[before], polls[before+1]), 0.2, "one poll, not two")
	}
}

func TestExtraPoll(t *testing.T) {
	server := newTestServer(t, testDomain)
	s := settings(nil, server.listenUDP(t))
	s["extra-poll"] = 2
	pc := dial(t, s)
	count := func(polls bool) func() int {
		return func() int { return len(server.seen(polls)) }
	}

	// Two polls with every datagram, also before the server has sent any;
	// and no polling yet.
	_, err := pc.WriteTo(randomBytes(500), nil)
	require.NoError(t, err)
	eventually(t, func() bool { return count(false)() == 4 && count(true)() == 2 }, "4 queries with data and 2 polls")
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, 2, count(true)())

	// Three queries instead of one for every poll: 2 more with the datagram,
	// 3 half a second later that fetch "two", 3 at once for that answer.
	// Without extra-poll there would be 2 by then.
	server.push([]byte("one"))
	_, err = pc.WriteTo([]byte("x"), nil)
	require.NoError(t, err)
	_, _, err = pc.ReadFrom(make([]byte, 100))
	require.NoError(t, err)
	eventually(t, func() bool { return count(true)() >= 4 }, "the polls sent with the datagram")
	server.push([]byte("two"))
	start := time.Now()
	_, _, err = pc.ReadFrom(make([]byte, 100))
	require.NoError(t, err)
	eventually(t, func() bool { return count(true)() >= 4+3+3 }, "three queries per poll")
	require.Less(t, time.Since(start), 1500*time.Millisecond)
}

// countingResolver takes the queries while it is not full.
type countingResolver struct {
	sent     atomic.Int32
	full     atomic.Bool
	notReady atomic.Bool
}

func (r *countingResolver) send([]byte) bool {
	if r.full.Load() {
		return false
	}
	r.sent.Add(1)
	return true
}

func (r *countingResolver) ready() bool { return !r.notReady.Load() }

func (r *countingResolver) close() {}

// A resolver gets the next query when it has fewer unanswered ones than the
// resolver that was used last, and when that one has no room.
func TestResolverSelection(t *testing.T) {
	c := bareConn(t, 3, nil)
	resolvers := []*countingResolver{{}, {}, {}}
	for _, r := range resolvers {
		c.resolvers = append(c.resolvers, r)
	}
	counts := func() [3]int32 {
		return [3]int32{resolvers[0].sent.Load(), resolvers[1].sent.Load(), resolvers[2].sent.Load()}
	}
	send := func(n int) {
		for i := 0; i < n; i++ {
			require.NoError(t, c.send([]byte("data"), true))
		}
	}

	// nobody answers: the queries go round
	send(9)
	require.Equal(t, [3]int32{3, 3, 3}, counts())

	// The second resolver alone answers with data, as receive notes it. The
	// others are tried again only when it has as many unanswered queries as
	// they have.
	for i := 0; i < 300; i++ {
		sent := resolvers[1].sent.Load()
		send(1)
		if resolvers[1].sent.Load() > sent {
			c.sends[1].Store(0)
		}
	}
	got := counts()
	require.Greater(t, got[1], int32(250))
	require.Less(t, got[0]+got[2], int32(3+3+50))

	// it stops answering: the others get their share again
	send(300)
	after := counts()
	require.Greater(t, after[0]-got[0], int32(50))
	require.Greater(t, after[2]-got[2], int32(50))

	// A resolver that has no room is passed over.
	resolvers[1].full.Store(true)
	got = counts()
	send(100)
	after = counts()
	require.Equal(t, got[1], after[1])
	require.Equal(t, int32(100), after[0]-got[0]+after[2]-got[2])

	// A resolver that is not ready, such as a DoH server that asked for a
	// pause, is passed over as long as another one is.
	resolvers[1].full.Store(false)
	resolvers[0].notReady.Store(true)
	got = counts()
	send(50)
	after = counts()
	require.Equal(t, got[0], after[0])
	require.Equal(t, int32(50), after[1]-got[1]+after[2]-got[2])
	// When none is ready it takes the queries all the same.
	resolvers[1].notReady.Store(true)
	resolvers[2].notReady.Store(true)
	got = counts()
	send(30)
	after = counts()
	require.Equal(t, int32(30), after[0]-got[0]+after[1]-got[1]+after[2]-got[2])
	for _, r := range resolvers {
		r.notReady.Store(false)
	}
	resolvers[1].full.Store(true)

	// None has room: a poll is dropped, a datagram waits for the write
	// deadline, for room or for Close.
	resolvers[0].full.Store(true)
	resolvers[2].full.Store(true)
	require.NoError(t, c.send(nil, false))
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	_, err := c.WriteTo([]byte("data"), nil)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	_, err = c.WriteTo([]byte("data"), nil)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, "the deadline has passed")
	require.Equal(t, after, counts())

	require.NoError(t, c.SetDeadline(time.Time{}))
	go func() {
		time.Sleep(50 * time.Millisecond)
		resolvers[2].full.Store(false)
		c.roomCh <- struct{}{}
	}()
	_, err = c.WriteTo([]byte("data"), nil)
	require.NoError(t, err)
	require.Equal(t, after[2]+1, resolvers[2].sent.Load())

	resolvers[2].full.Store(true)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = c.Close()
	}()
	_, err = c.WriteTo([]byte("data"), nil)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestTwoResolvers(t *testing.T) {
	server := newTestServer(t, testDomain)
	server.echo = true
	pc := dial(t, settings(nil, server.listenUDP(t), server.listenTCP(t, 0)))
	for i := 0; i < 20; i++ {
		echo(t, pc, 200)
	}
}

// A TCP resolver that closed the connection is dialed again for the next
// query. The query that found the connection closed is lost.
func TestTCPResolverReconnects(t *testing.T) {
	server := newTestServer(t, testDomain)
	pc := dial(t, settings(nil, server.listenTCP(t, 2)))
	got := 0
	for i := 0; i < 30; i++ {
		_, err := pc.WriteTo([]byte{byte(i)}, nil)
		require.NoError(t, err)
		select {
		case <-server.received:
			got++
		case <-time.After(100 * time.Millisecond):
		}
	}
	require.GreaterOrEqual(t, got, 15)
}

// smallBuffers makes the TCP connections of a resolver take 2000 bytes and
// then block, as a connection does after some megabytes when the peer does
// not read. The megabytes are the buffers of the system, which a test cannot
// size the same way everywhere.
type smallBuffers struct {
	testDialer
}

func (d smallBuffers) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.testDialer.DialContext(ctx, network, address)
	if err != nil || network != "tcp" {
		return conn, err
	}
	return &stallingConn{Conn: conn, room: 2000, closed: make(chan struct{})}, nil
}

type stallingConn struct {
	net.Conn
	closed chan struct{}

	mu       sync.Mutex
	room     int
	deadline time.Time
	isClosed bool
}

// Write passes on what there is room for and then waits for the write
// deadline or for Close, as a write to a full socket does.
func (c *stallingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	n, deadline := len(p), c.deadline
	if n > c.room {
		n = c.room
	}
	c.room -= n
	c.mu.Unlock()
	if n > 0 {
		if _, err := c.Conn.Write(p[:n]); err != nil {
			return 0, err
		}
	}
	if n == len(p) {
		return n, nil
	}
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timeout = time.After(time.Until(deadline))
	}
	select {
	case <-c.closed:
		return n, net.ErrClosed
	case <-timeout:
		return n, os.ErrDeadlineExceeded
	}
}

func (c *stallingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *stallingConn) Close() error {
	c.mu.Lock()
	if !c.isClosed {
		c.isClosed = true
		close(c.closed)
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// dialStalled opens a tunnel whose first resolver is a TCP resolver the
// writes to which block. writeTimeout, if not 0, is the time a write to it
// may take.
func dialStalled(t *testing.T, addr string, writeTimeout time.Duration, more ...any) net.PacketConn {
	m, err := New(settings(nil, append([]any{addr}, more...)...))
	require.NoError(t, err)
	m.resolvers[0].writeTimeout = writeTimeout
	pc, err := m.DialPacketConn(context.Background(), smallBuffers{}, testDest)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// writeUntilBlocked writes datagrams until a write does not return, and
// returns the channel the error of that write comes on.
func writeUntilBlocked(t *testing.T, pc net.PacketConn) <-chan error {
	var written atomic.Int64
	result := make(chan error, 1)
	go func() {
		for {
			if _, err := pc.WriteTo(make([]byte, 4096), nil); err != nil {
				result <- err
				return
			}
			written.Add(1)
		}
	}()
	for last, stable := int64(-1), 0; stable < 20; {
		time.Sleep(10 * time.Millisecond)
		if now := written.Load(); now == last {
			stable++
		} else {
			last, stable = now, 0
		}
	}
	select {
	case err := <-result:
		t.Fatalf("the write did not block: %v", err)
	default:
	}
	return result
}

// A TCP resolver that stopped reading holds up the writer until the write
// deadline at most, and Close ends a write that waits.
func TestStalledResolver(t *testing.T) {
	t.Run("write deadline", func(t *testing.T) {
		pc := dialStalled(t, listenStalled(t).addr, 0)
		require.NoError(t, pc.SetWriteDeadline(time.Now().Add(time.Second)))
		start := time.Now()
		var err error
		for err == nil && time.Since(start) < 10*time.Second {
			_, err = pc.WriteTo(make([]byte, 4096), nil)
		}
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.InDelta(t, 1, time.Since(start).Seconds(), 0.5)
		// without a deadline the write waits again
		require.NoError(t, pc.SetDeadline(time.Time{}))
		blocked := writeUntilBlocked(t, pc)
		require.NoError(t, pc.SetDeadline(time.Now()))
		require.ErrorIs(t, <-blocked, os.ErrDeadlineExceeded)
	})

	t.Run("close", func(t *testing.T) {
		stalled := listenStalled(t)
		before := runtime.NumGoroutine()
		pc := dialStalled(t, stalled.addr, 0)
		blocked := writeUntilBlocked(t, pc)
		start := time.Now()
		require.NoError(t, pc.Close())
		require.ErrorIs(t, <-blocked, net.ErrClosed)
		require.Less(t, time.Since(start), time.Second, "Close does not wait for the write to the resolver")
		requireGoroutines(t, before)
		require.Equal(t, 1, stalled.accepted())
	})

	// A write that takes too long ends the connection: a part of a query is
	// in it. The next query opens another, and what the resolver reads on
	// each is whole queries from the start.
	t.Run("write timeout", func(t *testing.T) {
		server := newTestServer(t, testDomain)
		pc := dialStalled(t, server.listenTCP(t, 0), 100*time.Millisecond)
		go func() {
			for { // until the tunnel is closed
				if _, err := pc.WriteTo(make([]byte, 100), nil); err != nil {
					return
				}
			}
		}()
		connections := func() int {
			server.mu.Lock()
			defer server.mu.Unlock()
			return server.tcpConns
		}
		eventually(t, func() bool { return connections() >= 5 }, "the connection is replaced after a write that timed out")
		// 2000 bytes per connection are 11 queries of 172 bytes and a part;
		// the server may still be reading what the first connections carried
		eventually(t, func() bool {
			server.mu.Lock()
			defer server.mu.Unlock()
			return len(server.queries) >= 4*11
		}, "the queries of the replaced connections arrive whole")
		server.mu.Lock()
		defer server.mu.Unlock()
		require.Zero(t, server.badFrames)
		require.LessOrEqual(t, len(server.queries), server.tcpConns*11)
	})

	// The other resolvers go on getting queries meanwhile.
	t.Run("other resolvers", func(t *testing.T) {
		server := newTestServer(t, testDomain)
		server.echo = true
		pc := dialStalled(t, listenStalled(t).addr, 0, server.listenUDP(t))
		go func() {
			buf := make([]byte, 8192)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		start := time.Now()
		for i := 0; i < 300; i++ {
			_, err := pc.WriteTo(make([]byte, 4096), nil)
			require.NoError(t, err)
			time.Sleep(time.Millisecond) // the answers reset the count of the resolver that works
		}
		require.Less(t, time.Since(start), 5*time.Second)
		// what went to the stalled resolver is lost, the rest arrived
		eventually(t, func() bool { return len(server.received) >= 150 }, "datagrams through the resolver that works")
	})
}

// With one worker a DNS over HTTPS resolver has one request under way. A
// writer that does not read in between must not wait for itself: the answers
// are queued, and dropped when nobody takes them.
func TestDoHWriterThatDoesNotRead(t *testing.T) {
	for _, transport := range []string{"https", "http3"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			server := newTestServer(t, testDomain)
			server.echo = true
			_, entry, _ := dohFor(t, server, transport)
			entry["worker"] = 1
			s := settings(nil, entry)
			s["extra-poll"] = 2
			pc := dial(t, s)
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 2*readQueue; i++ {
					if _, err := pc.WriteTo(randomBytes(600), nil); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(30 * time.Second):
				t.Fatal("the writes wait for a reader")
			}
			// the tunnel still works, behind what has piled up
			require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 8192)
			for i := 0; i < readQueue/2; i++ {
				n, _, err := pc.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, 600, n)
			}
		})
	}
}

// A DNS over HTTPS server that answers 429 is left alone for the time it
// names.
func TestDoHCooldown(t *testing.T) {
	server := newTestServer(t, testDomain)
	doh := server.listenDoH(t)
	var limit atomic.Bool
	doh.status = func() (int, string) {
		if limit.Load() {
			return 429, "1"
		}
		return 0, ""
	}
	pc := dial(t, settings(nil, doh.resolver()))
	requests := func() int { return doh.requests()["HTTP/2.0"] }

	_, err := pc.WriteTo([]byte("one"), nil)
	require.NoError(t, err)
	<-server.received
	require.Equal(t, 1, requests())

	limit.Store(true)
	_, err = pc.WriteTo([]byte("two"), nil)
	require.NoError(t, err)
	eventually(t, func() bool { return requests() == 2 }, "the request that is told to wait")
	cooldown := time.Now()
	limit.Store(false)
	time.Sleep(50 * time.Millisecond) // the client has read the answer
	for i := 0; i < 5; i++ {
		_, err = pc.WriteTo([]byte("dropped"), nil)
		require.NoError(t, err)
	}
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 2, requests(), "no requests while cooling down")
	require.Empty(t, server.received)

	time.Sleep(time.Until(cooldown.Add(1100 * time.Millisecond)))
	_, err = pc.WriteTo([]byte("three"), nil)
	require.NoError(t, err)
	require.Equal(t, []byte("three"), <-server.received)
}

// A redirect is not followed: it would take the queries, and with them the
// data of the tunnel, to another server, in the clear if that is plain HTTP.
func TestDoHDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer plain.Close()

	server := newTestServer(t, testDomain)
	doh := server.listenDoH(t)
	doh.status = func() (int, string) { return http.StatusTemporaryRedirect, plain.URL + "/dns-query" }
	pc := dial(t, settings(nil, doh.resolver()))
	for i := 0; i < 3; i++ {
		_, err := pc.WriteTo([]byte("data"), nil)
		require.NoError(t, err)
	}
	eventually(t, func() bool { return doh.requests()["HTTP/2.0"] == 3 }, "the requests that are redirected")
	time.Sleep(200 * time.Millisecond)
	require.Zero(t, elsewhere.Load())
	require.Empty(t, server.received)
}

func TestReadDeadline(t *testing.T) {
	server := newTestServer(t, testDomain)
	server.echo = true
	pc := dial(t, settings(nil, server.listenUDP(t)))
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err := pc.ReadFrom(make([]byte, 10))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	// a deadline set while the read waits
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = pc.SetDeadline(time.Now())
	}()
	require.NoError(t, pc.SetReadDeadline(time.Time{}))
	_, _, err = pc.ReadFrom(make([]byte, 10))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	_, err = pc.WriteTo([]byte("late"), nil)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, "SetDeadline is for writes too")
	require.NoError(t, pc.SetDeadline(time.Time{}))
	echo(t, pc, 10)
}

func TestDialFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	server := newTestServer(t, testDomain)
	before := runtime.NumGoroutine()
	m, err := New(settings(nil, server.listenUDP(t), "tcp://"+addr))
	require.NoError(t, err)
	_, err = m.DialPacketConn(context.Background(), testDialer{}, testDest)
	require.Error(t, err)
	requireGoroutines(t, before+1) // the listener
}

func requireGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > want {
		buf := make([]byte, 1<<16)
		t.Fatalf("%d goroutines, want %d:\n%s", n, want, buf[:runtime.Stack(buf, true)])
	}
}

// Close ends the reads, the polling and everything the resolvers started.
func TestClose(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "https", "http3"} {
		t.Run(transport, func(t *testing.T) {
			server := newTestServer(t, testDomain)
			server.echo = true
			var s map[string]any
			switch transport {
			case "udp":
				s = settings(nil, server.listenUDP(t))
			case "tcp":
				s = settings(nil, server.listenTCP(t, 0))
			default:
				_, entry, _ := dohFor(t, server, transport)
				s = settings(nil, entry)
			}
			// the listeners are up, what comes on top is the client's
			time.Sleep(50 * time.Millisecond)
			before := runtime.NumGoroutine()
			pc := dial(t, s)
			echo(t, pc, 100) // polling has started
			require.NoError(t, pc.SetReadDeadline(time.Time{}))

			readErr := make(chan error)
			go func() {
				_, _, err := pc.ReadFrom(make([]byte, 100))
				readErr <- err
			}()
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, pc.Close())
			require.ErrorIs(t, <-readErr, net.ErrClosed)
			_, err := pc.WriteTo([]byte("late"), nil)
			require.ErrorIs(t, err, net.ErrClosed)
			require.NoError(t, pc.Close())

			queries := len(server.seen(true)) + len(server.seen(false))
			time.Sleep(700 * time.Millisecond)
			require.Equal(t, queries, len(server.seen(true))+len(server.seen(false)), "no queries after Close")
			if transport == "udp" || transport == "tcp" {
				requireGoroutines(t, before+boolInt(transport == "tcp")) // the server's connection handler
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
