// Package xraytest checks mihomo outbounds against a real Xray-core server.
//
// The tests start the binary named by XRAY_BIN (Xray-core v26.11.9) as a
// subprocess with a generated config and push traffic through a mihomo
// outbound into it. Without XRAY_BIN they are skipped. XRAYTEST_LOG=1 prints
// the Xray debug log of passing tests too.
//
//	docker create --name x ghcr.io/xtls/xray-core:26.11.9 && docker cp x:/usr/local/bin/xray /tmp/xray && docker rm x
//	XRAY_BIN=/tmp/xray go test -tags with_gvisor -count=1 ./xraytest/
package xraytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// xrayVersion is the Xray-core release the checks are written against.
const xrayVersion = "26.11.9"

const userUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

var tlsCertificate, tlsPrivateKey, _, _ = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)

type obj = map[string]any

func xrayBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN is not set, skip real xray interop test")
	}
	return bin
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// xray is a running Xray-core process.
type xray struct {
	log *syncBuffer
}

// count returns how many times the debug log contains substr.
func (x *xray) count(substr string) int {
	return strings.Count(x.log.String(), substr)
}

// waitFor waits until cond holds for the debug log, which Xray writes with a delay.
func (x *xray) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("xray log: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitCount waits until the debug log contains substr at least n times.
func (x *xray) waitCount(t *testing.T, substr string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for x.count(substr) < n {
		if time.Now().After(deadline) {
			t.Fatalf("xray log has %q %d times, want %d", substr, x.count(substr), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startXray runs Xray-core with the given inbounds and a freedom outbound.
func startXray(t *testing.T, inbounds ...obj) *xray {
	t.Helper()
	return startXrayConfig(t, obj{
		"log":       obj{"loglevel": "debug"},
		"inbounds":  inbounds,
		"outbounds": []obj{freedom("direct")},
	})
}

// freedom is a direct outbound that may reach the loopback targets, which
// Xray blocks by default for traffic coming from proxy inbounds.
func freedom(tag string) obj {
	return obj{
		"protocol": "freedom",
		"tag":      tag,
		"settings": obj{"finalRules": []obj{{"action": "allow"}}},
	}
}

// startXrayConfig runs Xray-core with a complete config.
func startXrayConfig(t *testing.T, cfg obj) *xray {
	t.Helper()
	bin := xrayBin(t)
	config, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, config, 0o600))

	x := &xray{log: &syncBuffer{}}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout = x.log
	cmd.Stderr = x.log
	require.NoError(t, cmd.Start())
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if t.Failed() || os.Getenv("XRAYTEST_LOG") != "" {
			t.Logf("xray config:\n%s\nxray log:\n%s", config, x.log.String())
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(x.log.String(), "started") {
		select {
		case <-exited:
			t.Fatalf("xray exited early:\n%s\n%s", config, x.log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("xray did not start:\n%s", x.log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(x.log.String(), "Xray "+xrayVersion+" ") {
		t.Fatalf("XRAY_BIN is not Xray %s:\n%s", xrayVersion, x.log.String())
	}
	return x
}

// freePorts returns n distinct ports that are free for both TCP and UDP on
// loopback. Xray binds them a moment later, there is no way to hand them over.
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var ports []int
	var held []io.Closer
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; len(ports) < n && i < 50*n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		held = append(held, l)
		pc, err := net.ListenPacket("udp", l.Addr().String())
		if err != nil {
			continue
		}
		held = append(held, pc)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	require.Len(t, ports, n, "no free ports")
	return ports
}

func freePort(t *testing.T) int {
	t.Helper()
	return freePorts(t, 1)[0]
}

func tlsSettings() obj {
	return obj{
		"certificates": []obj{{
			"certificate": strings.Split(strings.TrimSpace(tlsCertificate), "\n"),
			"key":         strings.Split(strings.TrimSpace(tlsPrivateKey), "\n"),
		}},
	}
}

// targets are the servers the proxied traffic is sent to.
type targets struct {
	tcp  netip.AddrPort // echo
	tls  netip.AddrPort // TLS 1.3 echo
	udp  netip.AddrPort // echo
	udp2 netip.AddrPort // echo
	who  netip.AddrPort // UDP, answers with the address the packet came from
	who2 netip.AddrPort // the same
}

func loopback(port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// at returns the same targets reached through another local address. An IP
// tunnel cannot carry packets to 127.0.0.1.
func (tg targets) at(addr netip.Addr) targets {
	for _, p := range []*netip.AddrPort{&tg.tcp, &tg.tls, &tg.udp, &tg.udp2, &tg.who, &tg.who2} {
		*p = netip.AddrPortFrom(addr, p.Port())
	}
	return tg
}

// hostAddr returns a non-loopback IPv4 address of this host.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipNet.IP.To4()); ok && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

func startTargets(t *testing.T) targets {
	t.Helper()
	xrayBin(t) // skip before anything is set up
	var tg targets

	// The targets listen on every address so that IP tunnels reach them too.
	var mu sync.Mutex
	var accepted []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range accepted {
			_ = c.Close()
		}
	})
	echo := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
			go func() { _, _ = io.Copy(c, c) }()
		}
	}

	l, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	tg.tcp = loopback(l.Addr().(*net.TCPAddr).Port)
	go echo(l)

	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)
	tl, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tl.Close() })
	tg.tls = loopback(tl.Addr().(*net.TCPAddr).Port)
	go echo(tl)

	udp := func(reply func(data []byte, from net.Addr) []byte) netip.AddrPort {
		pc, err := net.ListenPacket("udp", "0.0.0.0:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			buf := make([]byte, 65535)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(reply(buf[:n], addr), addr)
			}
		}()
		return loopback(pc.LocalAddr().(*net.UDPAddr).Port)
	}
	same := func(data []byte, _ net.Addr) []byte { return data }
	from := func(_ []byte, from net.Addr) []byte { return []byte(from.String()) }
	tg.udp, tg.udp2 = udp(same), udp(same)
	tg.who, tg.who2 = udp(from), udp(from)
	return tg
}

// srcPort gives every proxied flow its own source address, as real clients
// have. XUDP derives its GlobalID from it.
var srcPort atomic.Uint32

func tcpMetadata(dst netip.AddrPort) *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: uint16(20000 + srcPort.Add(1)),
		DstIP:   dst.Addr(),
		DstPort: dst.Port(),
	}
}

func udpMetadata(dst netip.AddrPort) *C.Metadata {
	m := tcpMetadata(dst)
	m.NetWork = C.UDP
	return m
}

func echoRoundTrip(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	data := make([]byte, size)
	_, _ = rand.Read(data)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(data)
		errCh <- err
	}()
	got := make([]byte, size)
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
	require.True(t, bytes.Equal(data, got), "echoed data differs")
}

// checkTCP sends a small and a large payload through the proxy to the echo target.
func checkTCP(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	require.NoError(t, err)
	defer conn.Close()
	echoRoundTrip(t, conn, 4)
	echoRoundTrip(t, conn, 1<<20)
}

// checkTLS runs a TLS 1.3 session inside the proxy, the traffic XTLS Vision is made for.
func checkTLS(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tls))
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	require.NoError(t, tlsConn.HandshakeContext(ctx))
	echoRoundTrip(t, tlsConn, 4)
	echoRoundTrip(t, tlsConn, 1<<20)
}

func udpRoundTrip(t *testing.T, pc net.PacketConn, dst netip.AddrPort, size int) {
	t.Helper()
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Second)))
	data := make([]byte, size)
	_, _ = rand.Read(data)
	_, err := pc.WriteTo(data, net.UDPAddrFromAddrPort(dst))
	require.NoError(t, err)
	got := make([]byte, 65535)
	n, from, err := pc.ReadFrom(got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, got[:n]), "echoed packet differs (sent %d, got %d bytes)", size, n)
	fromAddr, err := netip.ParseAddrPort(from.String())
	require.NoError(t, err)
	require.Equal(t, dst, netip.AddrPortFrom(fromAddr.Addr().Unmap(), fromAddr.Port()), "packet source")
}

// checkUDP sends packets of several sizes to one echo target.
func checkUDP(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := proxy.ListenPacketContext(ctx, udpMetadata(tg.udp))
	require.NoError(t, err)
	defer pc.Close()
	for _, size := range []int{1, 512, 1200} {
		udpRoundTrip(t, pc, tg.udp, size)
	}
}

// checkUDPTwoTargets sends to two targets over one association and expects
// each reply to carry its own source address.
func checkUDPTwoTargets(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := proxy.ListenPacketContext(ctx, udpMetadata(tg.udp))
	require.NoError(t, err)
	defer pc.Close()
	udpRoundTrip(t, pc, tg.udp, 100)
	udpRoundTrip(t, pc, tg.udp2, 200)
	udpRoundTrip(t, pc, tg.udp, 300)
}

// checkUDPFullCone is checkUDPTwoTargets plus the full cone property: both
// targets must see the association come from one server-side socket.
func checkUDPFullCone(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	checkUDPTwoTargets(t, proxy, tg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := proxy.ListenPacketContext(ctx, udpMetadata(tg.who))
	require.NoError(t, err)
	defer pc.Close()
	require.Equal(t, whoami(t, pc, tg.who), whoami(t, pc, tg.who2), "both targets must see one server-side socket")
}

// whoami returns the source address the target saw for a packet sent through
// pc. It retries like a UDP application would: Xray can drop the first reply
// after it reattaches an XUDP session (the previous session's goroutine may
// still be reading the shared pipe, common/mux/session.go Session.Close).
func whoami(t *testing.T, pc net.PacketConn, target netip.AddrPort) string {
	t.Helper()
	got := make([]byte, 1500)
	var err error
	for i := 0; i < 5; i++ {
		_, err = pc.WriteTo([]byte("who"), net.UDPAddrFromAddrPort(target))
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(2*time.Second)))
		var n int
		if n, _, err = pc.ReadFrom(got); err == nil {
			return string(got[:n])
		}
	}
	require.NoError(t, err)
	return ""
}

// checkXUDPGlobalID reconnects with the same client source address and expects
// the server to reattach the session and keep its UDP socket (XUDP GlobalID),
// then with another source address and expects a new socket.
func checkXUDPGlobalID(t *testing.T, x *xray, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Xray logs "XUDP put" once it has detached a closed session.
	dial := func(metadata *C.Metadata) string {
		put := x.count("XUDP put")
		pc, err := proxy.ListenPacketContext(ctx, metadata)
		require.NoError(t, err)
		seen := whoami(t, pc, tg.who)
		require.NoError(t, pc.Close())
		x.waitCount(t, "XUDP put", put+1)
		return seen
	}
	metadata := udpMetadata(tg.who)
	first := dial(metadata)
	hit := x.count("XUDP hit")
	same := *metadata
	second := dial(&same)
	x.waitCount(t, "XUDP hit", hit+1) // the server reattached the session by GlobalID
	require.Equal(t, first, second, "same client source must keep the server-side UDP socket")
	other := dial(udpMetadata(tg.who))
	require.NotEqual(t, first, other, "another client source must get its own UDP socket")
}
