package udphop

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testDialer opens plain UDP sockets and remembers them.
type testDialer struct {
	mu      sync.Mutex
	sockets []net.PacketConn
}

func (d *testDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	panic("not used")
}

func (d *testDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		d.mu.Lock()
		d.sockets = append(d.sockets, pc)
		d.mu.Unlock()
	}
	return pc, err
}

func (d *testDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sockets)
}

// server is a set of UDP echo sockets that note where packets came from.
type server struct {
	ports []uint16

	mu      sync.Mutex
	sources map[string]int // client address -> packets
	hits    map[uint16]int // server port -> packets
}

func newServer(t *testing.T, n int) *server {
	t.Helper()
	s := &server{sources: map[string]int{}, hits: map[uint16]int{}}
	for i := 0; i < n; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		s.ports = append(s.ports, port)
		go func() {
			buf := make([]byte, 2000)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				s.mu.Lock()
				s.sources[addr.String()]++
				s.hits[port]++
				s.mu.Unlock()
				_, _ = pc.WriteTo(buf[:n], addr)
			}
		}()
	}
	return s
}

func (s *server) portList() string {
	list := ""
	for i, port := range s.ports {
		if i > 0 {
			list += ","
		}
		list += strconv.Itoa(int(port))
	}
	return list
}

func (s *server) stats() (sources, ports int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sources), len(s.hits)
}

func dial(t *testing.T, settings map[string]any, dest netip.AddrPort) (*Conn, *testDialer) {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	m.unit = 20 * time.Millisecond // an "interval: 5" is 100 ms here
	d := &testDialer{}
	pc, err := m.DialPacketConn(context.Background(), d, dest)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*Conn), d
}

// echo sends packets for the given time and expects every one back, from the
// address the connection was created for.
func echo(t *testing.T, conn *Conn, dest netip.AddrPort, d time.Duration) {
	t.Helper()
	buf := make([]byte, 100)
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		_, err := conn.WriteTo([]byte("ping"), nil)
		require.NoError(t, err)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, addr, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "ping", string(buf[:n]))
		require.Equal(t, dest.String(), addr.String())
	}
}

func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func TestPerConnRemote(t *testing.T) {
	s := newServer(t, 4)
	// the server address given is a port nobody listens on
	dest := loopback(9)
	conn, d := dial(t, map[string]any{"mode": "perConnRemote", "remotePorts": s.portList()}, dest)
	echo(t, conn, dest, 300*time.Millisecond)
	sources, ports := s.stats()
	require.Equal(t, 1, sources)
	require.Equal(t, 1, ports, "one port for the whole connection")
	require.Equal(t, 1, d.count())
}

func TestIntervalRemote(t *testing.T) {
	s := newServer(t, 8)
	dest := loopback(s.ports[0])
	conn, d := dial(t, map[string]any{"mode": "intervalRemote", "interval": "5-6", "remote-ports": s.portList()}, dest)
	echo(t, conn, dest, time.Second) // about 8 hops
	sources, ports := s.stats()
	require.Equal(t, 1, sources, "the local socket stays")
	require.Greater(t, ports, 1, "the server port changes")
	require.Equal(t, 1, d.count())
}

func TestIntervalLocal(t *testing.T) {
	s := newServer(t, 1)
	dest := loopback(s.ports[0])
	conn, d := dial(t, map[string]any{"mode": "intervalLocal", "interval": 5}, dest)
	echo(t, conn, dest, time.Second)
	sources, ports := s.stats()
	require.Greater(t, sources, 2, "the local socket changes")
	require.Equal(t, 1, ports)
	require.Greater(t, d.count(), 2)

	// only the current and the previous socket stay open
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, opened := range d.sockets {
		if opened == conn.cur.PacketConn || (conn.pre != nil && opened == conn.pre.PacketConn) {
			continue
		}
		_, err := opened.WriteTo([]byte("x"), opened.LocalAddr())
		require.ErrorIs(t, err, net.ErrClosed)
	}
}

// Nobody reads the connection: the readers of the sockets a hop retired must
// not stay behind, holding a packet.
func TestRetiredSocketsLetGo(t *testing.T) {
	s := newServer(t, 1)
	dest := loopback(s.ports[0])
	conn, d := dial(t, map[string]any{"mode": "intervalLocal", "interval": 5}, dest)
	deadline := time.Now().Add(5 * time.Second)
	for d.count() < 5 {
		require.True(t, time.Now().Before(deadline), "no hops")
		_, err := conn.WriteTo([]byte("ping"), nil) // every socket gets an echo nobody reads
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond)
	}
	// Every reader but those of the current and the previous socket is gone
	// before the connection is closed: with them the count below would not
	// reach zero while the connection is open.
	conn.mu.Lock() // no hop meanwhile
	_ = conn.cur.Close()
	if conn.pre != nil {
		_ = conn.pre.Close()
	}
	conn.mu.Unlock()
	stopped := make(chan struct{})
	go func() { conn.wg.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the readers of retired sockets are still there")
	}
	require.NoError(t, conn.Close())
	wait := make(chan struct{})
	go func() { conn.wg.Wait(); close(wait) }()
	select {
	case <-wait:
	case <-time.After(2 * time.Second):
		t.Fatal("readers did not stop")
	}
}

func TestBothWithPrefix(t *testing.T) {
	s := newServer(t, 4)
	dest := loopback(s.ports[0])
	conn, _ := dial(t, map[string]any{
		"mode": "intervalLocal, intervalRemote", "interval": 5,
		"remoteIPs": []any{"127.0.0.1/32", "127.0.0.1"}, "remotePorts": s.portList(),
	}, dest)
	echo(t, conn, dest, time.Second)
	sources, ports := s.stats()
	require.Greater(t, sources, 2)
	require.Greater(t, ports, 1)
}

func TestDeadlineAndClose(t *testing.T) {
	s := newServer(t, 1)
	conn, _ := dial(t, map[string]any{"mode": "intervalLocal"}, loopback(s.ports[0]))
	buf := make([]byte, 10)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err := conn.ReadFrom(buf)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())

	// a deadline that has passed wins over a packet that is ready
	_, err = conn.WriteTo([]byte("ping"), nil)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
	for i := 0; i < 20; i++ {
		_, _, err = conn.ReadFrom(buf)
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	}
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)

	// the deadline can be lifted and the connection works on
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	_, err = conn.WriteTo([]byte("ping"), nil)
	require.NoError(t, err)
	n, _, err = conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 4, n)

	// Close wakes a blocked reader
	done := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(buf)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not return after Close")
	}
	_, err = conn.WriteTo([]byte("ping"), nil)
	require.ErrorIs(t, err, net.ErrClosed)
	require.NoError(t, conn.Close())
}

func TestRandomAddr(t *testing.T) {
	prefix := netip.MustParsePrefix("10.20.0.0/14")
	seen := map[netip.Addr]bool{}
	for i := 0; i < 200; i++ {
		addr := randomAddr(prefix)
		require.True(t, prefix.Contains(addr), addr)
		seen[addr] = true
	}
	require.Greater(t, len(seen), 100)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), randomAddr(netip.MustParsePrefix("2001:db8::1/128")))
	v6 := netip.MustParsePrefix("2001:db8::/33")
	for i := 0; i < 50; i++ {
		require.True(t, v6.Contains(randomAddr(v6)))
	}
}

func TestSettings(t *testing.T) {
	m, err := New(map[string]any{"mode": "IntervalLocal,PERCONNREMOTE", "remotePorts": "1000-1002, 2000", "remote-ips": []any{"192.0.2.0/24", "2001:db8::1"}})
	require.NoError(t, err)
	require.True(t, m.local)
	require.True(t, m.remoteOnce)
	require.False(t, m.remote)
	require.Equal(t, []uint16{1000, 1001, 1002, 2000}, m.remotePorts)
	require.Equal(t, int32(30), m.interval.From)
	require.Len(t, m.remoteIPs, 2)

	m, err = New(map[string]any{"mode": "intervalRemote", "remotePorts": 443})
	require.NoError(t, err)
	require.Equal(t, []uint16{443}, m.remotePorts)

	for name, settings := range map[string]map[string]any{
		"no mode":        {},
		"unknown mode":   {"mode": "intervalLocal,hop"},
		"short interval": {"mode": "intervalLocal", "interval": "3-10"},
		"bad ip":         {"mode": "intervalRemote", "remote-ips": []any{"example.org"}},
		"bad port":       {"mode": "intervalRemote", "remote-ports": "70000"},
		"bad port range": {"mode": "intervalRemote", "remote-ports": "200-100"},
	} {
		_, err := New(settings)
		require.Error(t, err, name)
	}
}
