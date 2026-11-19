package xraytest

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// The xdns mask through a real recursive resolver. The other checks give the
// client the DNS port of Xray, directly or behind a relay made here; a
// resolver between them does things a relay does not: it sends its own
// queries from its own ports and IDs, may change the case of the letters in
// the name (0x20), minimises the names it asks, caches the answers and
// rotates the records of an answer. UNBOUND_BIN names an Unbound binary; it
// resolves the tunnel domain through a stub zone that points at Xray, so no
// delegation at a registrar is needed.

type fmUnbound struct {
	// caps turns on use-caps-for-id, the 0x20 case randomisation.
	caps bool
	// minimise turns on QNAME minimisation.
	minimise bool
	// edns0 is the EDNS buffer size the resolver announces to the server.
	edns0 int
}

func (u fmUnbound) start(t *testing.T, domain string, upstream int) string {
	t.Helper()
	bin := os.Getenv("UNBOUND_BIN")
	if bin == "" {
		t.Skip("UNBOUND_BIN is not set, skip the check through a real recursive resolver")
	}
	yesno := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	edns0 := u.edns0
	if edns0 == 0 {
		edns0 = 1232
	}
	port := freePort(t)
	conf := fmt.Sprintf(`server:
  interface: 127.0.0.1
  port: %d
  do-ip6: no
  do-daemonize: no
  username: ""
  chroot: ""
  pidfile: ""
  use-syslog: no
  logfile: ""
  verbosity: 1
  num-threads: 1
  access-control: 127.0.0.0/8 allow
  do-not-query-localhost: no
  module-config: "iterator"
  use-caps-for-id: %s
  qname-minimisation: %s
  edns-buffer-size: %d
  max-udp-size: 4096
  local-zone: "example.com." nodefault
stub-zone:
  name: "%s."
  stub-addr: 127.0.0.1@%d
  stub-no-cache: no
`, port, yesno(u.caps), yesno(u.minimise), edns0, domain, upstream)
	path := filepath.Join(t.TempDir(), "unbound.conf")
	require.NoError(t, os.WriteFile(path, []byte(conf), 0o644))
	var out strings.Builder
	cmd := exec.Command(bin, "-d", "-c", path)
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("unbound:\n%s", out.String())
		}
	})
	addr := loopback(port).String()
	require.Eventually(t, func() bool { return fmDNSAnswers(addr) }, 10*time.Second, 100*time.Millisecond,
		"unbound does not answer")
	return addr
}

// fmDNSAnswers tells whether the resolver at addr answers a query at all.
func fmDNSAnswers(addr string) bool {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	name, _ := dnsmessage.NewName("localhost.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	raw, err := msg.Pack()
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err = conn.Write(raw); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n >= 12
}

func TestFinalmaskXDNSRecursiveResolver(t *testing.T) {
	tg := startTargets(t)
	one := []string{fmXDNSDomain}
	const payload = 128 << 10

	cases := []struct {
		name     string
		tunnel   fmXDNSTunnel
		resolver fmUnbound
		// stalls tells that small datagrams get through and full ones do not.
		stalls bool
	}{
		// The tunnel without EDNS: the resolver still asks the server with
		// EDNS, so the answers carry an OPT record and hold 11 bytes less.
		{"txt", fmXDNSTunnel{names: one, payload: payload}, fmUnbound{}, false},
		// TXT with EDNS on both sides, what a user would set.
		{"txt-edns0", fmXDNSTunnel{names: one, edns0: 1232, payload: payload}, fmUnbound{}, false},
		// The resolver changes the case of the letters in every query.
		{"txt-edns0-0x20", fmXDNSTunnel{names: one, edns0: 1232, payload: payload}, fmUnbound{caps: true}, false},
		// The resolver asks for the name label by label first. Xray does not
		// answer those questions, the resolver waits for it and then asks for
		// the whole name: the tunnel works, some ten times slower.
		{"txt-edns0-qname-minimisation", fmXDNSTunnel{names: one, edns0: 1232, payload: payload}, fmUnbound{minimise: true}, false},
		// Both at once, the way the large public resolvers work.
		{"txt-edns0-0x20-minimisation", fmXDNSTunnel{names: one, edns0: 1232, payload: payload}, fmUnbound{caps: true, minimise: true}, false},
		// Several records in an answer: a resolver may rotate them.
		// 1232 and not more: after a lost answer a resolver asks again with
		// a smaller EDNS size, and a server sized for 4096 then drops its own
		// datagrams (seen with Unbound in one run out of three).
		{"a-edns0", fmXDNSTunnel{names: one, types: []int{1}, edns0: 1232, payload: payload}, fmUnbound{}, false},
		{"aaaa", fmXDNSTunnel{names: one, types: []int{28}, payload: 16 << 10}, fmUnbound{}, false},
		// A name has one CNAME record. Xray puts as many as a datagram needs
		// into an answer, up to three here, and the resolver does not pass
		// an answer with several on: small datagrams get through, full ones
		// never do. CNAME works through a resolver only with an EDNS size
		// that leaves room for one record.
		{"cname-several-records", fmXDNSTunnel{names: one, types: []int{5}, edns0: 1232, payload: payload}, fmUnbound{}, true},
		{"cname-one-record", fmXDNSTunnel{names: one, types: []int{5}, edns0: 600, payload: 16 << 10}, fmUnbound{}, false},
		// Shorter names, as some resolvers want them.
		{"txt-edns0-short-names", fmXDNSTunnel{names: one, edns0: 1232, lenLimit: 128, labelLimit: 32, payload: payload}, fmUnbound{caps: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.tunnel.resolver = true
			x, port := c.tunnel.start(t)
			addr := c.resolver.start(t, fmXDNSDomain, port)
			proxy := c.tunnel.proxy(t, fmXDNSResolver(addr))
			if c.stalls {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
				require.NoError(t, err)
				defer conn.Close()
				echoRoundTrip(t, conn, 4)
				data := make([]byte, 64<<10)
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				go func() { _, _ = conn.Write(data) }()
				_, err = io.ReadFull(conn, make([]byte, len(data)))
				require.Error(t, err, "answers with several CNAME records must not pass the resolver")
				return
			}
			c.tunnel.check(t, x, proxy, tg)
		})
	}
}
