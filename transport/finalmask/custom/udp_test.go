package custom

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/stretchr/testify/require"
)

// socket is a scripted UDP socket: the test plays the network.
type socket struct {
	in      chan packet   // what ReadFrom returns
	out     chan []byte   // what WriteTo got
	closed  chan struct{} // closed by Close
	once    sync.Once
	reading atomic.Int32 // ReadFrom calls under way
}

type packet struct {
	data []byte
	err  error
}

var (
	localAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
	peerAddr  = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 443}
)

func newSocket() *socket {
	return &socket{in: make(chan packet, 64), out: make(chan []byte, 64), closed: make(chan struct{})}
}

func (s *socket) ReadFrom(p []byte) (int, net.Addr, error) {
	s.reading.Add(1)
	defer s.reading.Add(-1)
	select {
	case d := <-s.in:
		return copy(p, d.data), peerAddr, d.err
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *socket) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	s.out <- append([]byte(nil), p...)
	return len(p), nil
}

func (s *socket) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *socket) LocalAddr() net.Addr         { return localAddr }
func (s *socket) SetDeadline(time.Time) error { return nil }
func (s *socket) SetReadDeadline(time.Time) error {
	return errors.New("the mask must keep read deadlines to itself")
}
func (s *socket) SetWriteDeadline(time.Time) error { return nil }

// sent returns the next datagram the client put on the wire.
func (s *socket) sent(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-s.out:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was sent")
		return nil
	}
}

func (s *socket) nothingSent(t *testing.T) {
	t.Helper()
	select {
	case p := <-s.out:
		t.Fatalf("unexpected datagram %q", p)
	case <-time.After(50 * time.Millisecond):
	}
}

func wrapUDP(t *testing.T, settings obj, tune func(*UDP)) (net.PacketConn, *socket) {
	t.Helper()
	m, err := NewUDP(settings)
	require.NoError(t, err)
	if tune != nil {
		tune(m)
	}
	sock := newSocket()
	conn, err := m.WrapPacketConn(sock, netip.AddrPort{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, sock
}

func read(t *testing.T, conn net.PacketConn) string {
	t.Helper()
	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, peerAddr, addr)
	return string(buf[:n])
}

func TestUDPPrefix(t *testing.T) {
	settings := obj{
		"client": []any{
			obj{"packet": "C1", "type": "str"},
			obj{"rand": 4, "rand-range": "97-122", "capture": "n"},
			tr("be16", meta("remote_port")),
			obj{"reuse": "n"},
		},
		"server": []any{
			obj{"packet": "5331", "type": "hex"},
			obj{"reuse": "n"},
			obj{"rand": 2, "capture": "s"},
			tr("concat", reuse("s"), raw(0)),
		},
	}
	conn, sock := wrapUDP(t, settings, nil)
	// answer is a datagram of the server: its header for the nonce n, then data.
	answer := func(n []byte, data string) packet {
		return packet{data: append(append(append([]byte("S1"), n...), 'x', 'y', 'x', 'y', 0), data...)}
	}
	// write sends data and returns the nonce its header carried.
	write := func(data string) []byte {
		n, err := conn.WriteTo([]byte(data), peerAddr)
		require.NoError(t, err)
		require.Equal(t, len(data), n)
		got := sock.sent(t)
		require.Len(t, got, 12+len(data))
		require.Equal(t, "C1", string(got[:2]))
		nonce := got[2:6]
		for _, b := range nonce {
			require.GreaterOrEqual(t, b, byte('a'))
			require.LessOrEqual(t, b, byte('z'))
		}
		require.Equal(t, []byte{443 >> 8, 443 & 0xFF}, got[6:8])
		require.Equal(t, nonce, got[8:12])
		require.Equal(t, data, string(got[12:]))
		return nonce
	}

	first := write("hello")
	// Datagrams whose header is not the server's are dropped.
	sock.in <- packet{data: []byte("S1")}                                                   // too short
	sock.in <- packet{data: append(append([]byte("S2"), first...), "xyxy\x00data"...)}      // another packet
	sock.in <- packet{data: append(append([]byte("S1"), first...), "xyxz\x00data"...)}      // s is not repeated
	sock.in <- packet{data: append(append([]byte("S1"), first...), "xyxy\x01data"...)}      // the transform differs
	sock.in <- packet{data: append(append([]byte("S1"), first[1:]...), "!xyxy\x00data"...)} // not the nonce sent
	sock.in <- answer(first, "world")
	require.Equal(t, "world", read(t, conn))
	sock.in <- answer(first, "") // a header alone is an empty datagram
	require.Equal(t, "", read(t, conn))

	// Every datagram sent has a new nonce, and the server has to answer to the last one.
	second := write("again")
	require.NotEqual(t, first, second)
	sock.in <- answer(first, "stale")
	sock.in <- answer(second, "fresh")
	require.Equal(t, "fresh", read(t, conn))

	// The caller's buffer is never overrun.
	sock.in <- answer(second, "0123456789")
	small := make([]byte, 16)
	n, _, err := conn.ReadFrom(small[:4])
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, append([]byte("0123"), make([]byte, 12)...), small)

	_, err = conn.WriteTo(make([]byte, mask.BufferSize), peerAddr)
	require.ErrorContains(t, err, "too large")
	sock.nothingSent(t)

	// An error of the socket is the caller's to handle.
	boom := errors.New("boom")
	sock.in <- packet{err: boom}
	_, _, err = conn.ReadFrom(small)
	require.Equal(t, boom, err)
}

// What was captured with a peer is forgotten after the TTL.
func TestUDPPrefixStateExpires(t *testing.T) {
	conn, sock := wrapUDP(t, obj{
		"client": []any{obj{"rand": 4, "capture": "n"}},
		"server": []any{obj{"reuse": "n"}},
	}, func(m *UDP) { m.ttl = 50 * time.Millisecond })

	_, err := conn.WriteTo([]byte("1"), peerAddr)
	require.NoError(t, err)
	first := sock.sent(t)[:4]
	got := make(chan string, 1)
	go func() { got <- read(t, conn) }()
	time.Sleep(80 * time.Millisecond)
	sock.in <- packet{data: append(append([]byte(nil), first...), "late"...)}
	select {
	case data := <-got:
		t.Fatalf("accepted %q for a nonce that has expired", data)
	case <-time.After(50 * time.Millisecond):
	}
	_, err = conn.WriteTo([]byte("2"), peerAddr)
	require.NoError(t, err)
	second := sock.sent(t)[:4]
	sock.in <- packet{data: append(append([]byte(nil), second...), "in time"...)}
	require.Equal(t, "in time", <-got)
}

// A client header may use what the server header captured, once the server
// has spoken; until then nothing can be sent.
func TestUDPPrefixClientReusesServerVariable(t *testing.T) {
	conn, sock := wrapUDP(t, obj{
		"client": []any{tr("slice", reuse("s"), u64(1), u64(2))},
		"server": []any{obj{"rand": 3, "capture": "s"}},
	}, nil)
	_, err := conn.WriteTo([]byte("early"), peerAddr)
	require.ErrorContains(t, err, `unknown variable "s"`)
	sock.nothingSent(t)

	sock.in <- packet{data: []byte("abcdata")}
	require.Equal(t, "data", read(t, conn))
	_, err = conn.WriteTo([]byte("now"), peerAddr)
	require.NoError(t, err)
	require.Equal(t, "bcnow", string(sock.sent(t)))
}

var standalone = obj{
	"mode":   "standalone",
	"client": []any{obj{"packet": "hello?", "type": "str"}, obj{"rand": 4, "capture": "n"}, tr("be16", meta("local_port"))},
	"server": []any{obj{"packet": "hello!", "type": "str"}, obj{"reuse": "n"}},
}

// probe checks a handshake datagram of the standalone settings and returns
// the answer to it.
func probe(t *testing.T, got []byte) packet {
	t.Helper()
	require.Len(t, got, 12)
	require.Equal(t, "hello?", string(got[:6]))
	require.Equal(t, []byte{40000 >> 8, 40000 & 0xFF}, got[10:])
	return packet{data: append([]byte("hello!"), got[6:10]...)}
}

func TestUDPStandalone(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)

	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	// The handshake goes first, the data waits for its answer.
	answer := probe(t, sock.sent(t))
	sock.nothingSent(t)
	// Datagrams that are not the answer are data, even of the same length.
	sock.in <- packet{data: []byte("hello!nope")}
	sock.in <- packet{data: []byte("early")}
	sock.in <- answer
	require.NoError(t, <-wrote)
	require.Equal(t, "data", string(sock.sent(t)))

	// The handshake is good for a while: the next datagrams leave as they are.
	n, err := conn.WriteTo([]byte("more"), peerAddr)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, "more", string(sock.sent(t)))

	sock.in <- packet{data: []byte("pong")}
	require.Equal(t, "hello!nope", read(t, conn))
	require.Equal(t, "early", read(t, conn))
	require.Equal(t, "pong", read(t, conn))
}

// Writers that come during a handshake wait for it instead of starting
// their own.
func TestUDPStandaloneConcurrentWriters(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)
	const writers = 8
	wrote := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() {
			_, err := conn.WriteTo([]byte("data"), peerAddr)
			wrote <- err
		}()
	}
	answer := probe(t, sock.sent(t))
	sock.nothingSent(t)
	sock.in <- answer
	for i := 0; i < writers; i++ {
		require.NoError(t, <-wrote)
		require.Equal(t, "data", string(sock.sent(t)))
	}
	sock.nothingSent(t)
}

func TestUDPStandaloneRetransmits(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) { m.probeInterval = 20 * time.Millisecond })

	// The same handshake is sent again until it is answered.
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	first := sock.sent(t)
	require.Equal(t, first, sock.sent(t))
	require.Equal(t, first, sock.sent(t))
	sock.in <- probe(t, first)
	require.NoError(t, <-wrote)
	for string(first) == string(sock.sent(t)) { // handshakes sent while the answer was on its way
	}
}

func TestUDPStandaloneNoAnswer(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) { m.probeInterval = 10 * time.Millisecond })

	_, err := conn.WriteTo([]byte("data"), peerAddr)
	require.ErrorContains(t, err, "no answer")
	first := sock.sent(t)
	for i := 1; i < probeCount; i++ {
		require.Equal(t, first, sock.sent(t))
	}
	sock.nothingSent(t)

	// The next write starts over, with a handshake of its own.
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	second := sock.sent(t)
	require.NotEqual(t, first, second)
	sock.in <- probe(t, first) // the answer to the handshake that was given up
	sock.in <- probe(t, second)
	require.NoError(t, <-wrote)
}

func TestUDPStandaloneHandshakeExpires(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) { m.ttl = 300 * time.Millisecond })
	write := func(handshake bool) {
		wrote := make(chan error, 1)
		go func() {
			_, err := conn.WriteTo([]byte("data"), peerAddr)
			wrote <- err
		}()
		if handshake {
			sock.in <- probe(t, sock.sent(t))
		}
		require.NoError(t, <-wrote)
		require.Equal(t, "data", string(sock.sent(t)))
	}
	write(true)
	// Traffic does not extend the handshake.
	time.Sleep(180 * time.Millisecond)
	write(false)
	time.Sleep(180 * time.Millisecond)
	write(true)
}

// The server answers every datagram of a handshake. The answers that come
// after the first one are not data while the handshake is good.
func TestUDPStandaloneRepeatedAnswers(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) {
		m.probeInterval = 20 * time.Millisecond
		m.ttl = 300 * time.Millisecond
	})
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	first := sock.sent(t)
	require.Equal(t, first, sock.sent(t))
	require.Equal(t, first, sock.sent(t))
	answer := probe(t, first)
	for i := 0; i < 3; i++ {
		sock.in <- answer
	}
	sock.in <- packet{data: []byte("pong")}
	require.NoError(t, <-wrote)
	require.Equal(t, "pong", read(t, conn))

	// Three datagrams were sent, so three answers are not data. A fourth
	// datagram that looks like the answer is: with a server header that any
	// datagram of its size matches, data would be lost otherwise.
	sock.in <- answer
	require.Equal(t, string(answer.data), read(t, conn))

	// Another datagram of that length is data, and so is the answer itself
	// once the handshake has expired.
	sock.in <- packet{data: []byte("hello!nope")}
	require.Equal(t, "hello!nope", read(t, conn))
	time.Sleep(350 * time.Millisecond)
	sock.in <- answer
	require.Equal(t, string(answer.data), read(t, conn))
}

// The writers that wait for a handshake share it: when nobody answers, all
// of them fail after one round of datagrams.
func TestUDPStandaloneWritersShareAFailure(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) { m.probeInterval = 30 * time.Millisecond })
	const writers = 5
	wrote := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() {
			_, err := conn.WriteTo([]byte("data"), peerAddr)
			wrote <- err
		}()
	}
	for i := 0; i < writers; i++ {
		require.ErrorContains(t, <-wrote, "no answer")
	}
	first := sock.sent(t)
	for i := 1; i < probeCount; i++ {
		require.Equal(t, first, sock.sent(t))
	}
	sock.nothingSent(t)
}

// The write deadline bounds the wait for a handshake, and a write that gave
// up does not take the handshake from the others.
func TestUDPStandaloneWriteDeadline(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(40*time.Millisecond)))
	start := time.Now()
	wrote := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := conn.WriteTo([]byte("data"), peerAddr)
			wrote <- err
		}()
	}
	for i := 0; i < 2; i++ {
		err := <-wrote
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		require.True(t, netErr.Timeout())
	}
	require.Less(t, time.Since(start), probeInterval)
	first := sock.sent(t)
	sock.nothingSent(t)
	_, err := conn.WriteTo([]byte("data"), peerAddr)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	// The handshake is still under way: once it is answered, a write that
	// has time goes out without another one.
	sock.in <- probe(t, first)
	require.NoError(t, conn.SetWriteDeadline(time.Time{}))
	_, err = conn.WriteTo([]byte("data"), peerAddr)
	require.NoError(t, err)
	require.Equal(t, "data", string(sock.sent(t)))
}

// Data that nobody reads does not keep the answer of a handshake in the
// socket: with the queue full the reader goes on, dropping the data.
func TestUDPStandaloneFullQueue(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, func(m *UDP) { m.ttl = 100 * time.Millisecond })
	write := func() {
		wrote := make(chan error, 1)
		go func() {
			_, err := conn.WriteTo([]byte("data"), peerAddr)
			wrote <- err
		}()
		sock.in <- probe(t, sock.sent(t))
		require.NoError(t, <-wrote)
		require.Equal(t, "data", string(sock.sent(t)))
	}
	write()
	for i := 0; i < queueSize+8; i++ {
		sock.in <- packet{data: []byte{byte(i)}}
	}
	time.Sleep(150 * time.Millisecond) // the handshake expires
	write()                            // its answer is behind the data in the socket

	// What was queued is read in order; what found the queue full is gone.
	for i := 0; i < queueSize; i++ {
		require.Equal(t, string([]byte{byte(i)}), read(t, conn))
	}
	sock.in <- packet{data: []byte("pong")}
	require.Equal(t, "pong", read(t, conn))

	// Close gives back the buffers of the datagrams nobody read.
	for i := 0; i < 5; i++ {
		sock.in <- packet{data: []byte{byte(i)}}
	}
	queue := conn.(*standaloneConn).queue
	require.Eventually(t, func() bool { return len(queue) == 5 }, time.Second, time.Millisecond)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return len(queue) == 0 }, time.Second, time.Millisecond)
}

// The peers that went away are forgotten when their state has expired.
func TestUDPPeersAreForgotten(t *testing.T) {
	other := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 443}

	conn, sock := wrapUDP(t, obj{"client": []any{obj{"rand": 2, "capture": "n"}}}, func(m *UDP) { m.ttl = 30 * time.Millisecond })
	_, err := conn.WriteTo([]byte("data"), other)
	require.NoError(t, err)
	time.Sleep(80 * time.Millisecond)
	_, err = conn.WriteTo([]byte("data"), peerAddr)
	require.NoError(t, err)
	prefix := conn.(*prefixConn)
	prefix.mu.Lock()
	require.Len(t, prefix.peers.m, 1)
	require.Contains(t, prefix.peers.m, peerAddr.String())
	prefix.mu.Unlock()
	sock.sent(t)

	conn, sock = wrapUDP(t, standalone, func(m *UDP) {
		m.ttl = 30 * time.Millisecond
		m.probeInterval = 5 * time.Millisecond
	})
	_, err = conn.WriteTo([]byte("data"), other)
	require.ErrorContains(t, err, "no answer")
	for i := 0; i < probeCount; i++ {
		sock.sent(t)
	}
	time.Sleep(40 * time.Millisecond)
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	sock.in <- probe(t, sock.sent(t))
	require.NoError(t, <-wrote)
	alone := conn.(*standaloneConn)
	alone.mu.Lock()
	require.Len(t, alone.peers.m, 1)
	require.Contains(t, alone.peers.m, peerAddr.String())
	alone.mu.Unlock()
}

// A read deadline ends the read it is set for and nothing else.
func TestUDPStandaloneReadDeadline(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, _, err := conn.ReadFrom(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
	_, _, err = conn.ReadFrom(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	// A deadline set while a read waits applies to it.
	require.NoError(t, conn.SetDeadline(time.Time{}))
	failed := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 16))
		failed <- err
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, conn.SetDeadline(time.Now()))
	require.ErrorIs(t, <-failed, os.ErrDeadlineExceeded)

	// The connection works on: a handshake completes and data arrives.
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	sock.in <- probe(t, sock.sent(t))
	require.NoError(t, <-wrote)
	sock.in <- packet{data: []byte("pong")}
	require.Equal(t, "pong", read(t, conn))
}

// An error of the socket ends the handshakes under way and reaches the
// reader; the connection is not given up for it.
func TestUDPStandaloneSocketError(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)

	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	first := sock.sent(t)
	refused := errors.New("connection refused")
	sock.in <- packet{err: refused}
	require.ErrorIs(t, <-wrote, refused)
	_, _, err := conn.ReadFrom(make([]byte, 16))
	require.Equal(t, refused, err)

	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	second := sock.sent(t)
	require.NotEqual(t, first, second)
	sock.in <- probe(t, second)
	require.NoError(t, <-wrote)
	sock.in <- packet{data: []byte("pong")}
	require.Equal(t, "pong", read(t, conn))
}

// Close ends the waiting handshake, the waiting read and the goroutine that
// reads the socket.
func TestUDPStandaloneClose(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)

	wrote := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("data"), peerAddr)
		wrote <- err
	}()
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 16))
		readDone <- err
	}()
	sock.sent(t)
	require.Eventually(t, func() bool { return sock.reading.Load() == 1 }, time.Second, time.Millisecond)

	require.NoError(t, conn.Close())
	require.ErrorIs(t, <-wrote, net.ErrClosed)
	require.ErrorIs(t, <-readDone, net.ErrClosed)
	select {
	case <-conn.(*standaloneConn).done:
	default:
		t.Fatal("not marked closed")
	}
	require.Eventually(t, func() bool { return sock.reading.Load() == 0 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, int32(0), sock.reading.Load(), "the socket is read after Close")

	_, err := conn.WriteTo([]byte("data"), peerAddr)
	require.ErrorIs(t, err, net.ErrClosed)
	_, _, err = conn.ReadFrom(make([]byte, 16))
	require.ErrorIs(t, err, net.ErrClosed)
	require.NoError(t, conn.Close())
}

// A connection that was never used has nothing to stop.
func TestUDPStandaloneUnused(t *testing.T) {
	conn, sock := wrapUDP(t, standalone, nil)
	time.Sleep(10 * time.Millisecond)
	require.Equal(t, int32(0), sock.reading.Load())
	require.NoError(t, conn.Close())
}

// The header is told from the data by the addresses of real sockets too.
func TestUDPOverLoopback(t *testing.T) {
	for _, mode := range []string{"prefix", "standalone"} {
		m, err := NewUDP(obj{
			"mode":   mode,
			"client": []any{tr("be16", meta("remote_port")), tr("be16", meta("local_port")), tr("be32", meta("remote_ip4_u32"))},
			"server": []any{obj{"packet": "ok", "type": "str"}},
		})
		require.NoError(t, err)
		server, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer server.Close()
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conn, err := m.WrapPacketConn(raw, netip.AddrPort{})
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

		serverPort, clientPort := server.LocalAddr().(*net.UDPAddr).Port, raw.LocalAddr().(*net.UDPAddr).Port
		header := []byte{byte(serverPort >> 8), byte(serverPort), byte(clientPort >> 8), byte(clientPort), 127, 0, 0, 1}
		go func() {
			buf := make([]byte, 64)
			for {
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					return
				}
				switch string(buf[:n]) {
				case string(header): // the standalone handshake
					_, _ = server.WriteTo([]byte("ok"), addr)
				case string(header) + "ping":
					_, _ = server.WriteTo([]byte("okpong"), addr)
				case "ping":
					_, _ = server.WriteTo([]byte("pong"), addr)
				}
			}
		}()
		_, err = conn.WriteTo([]byte("ping"), server.LocalAddr())
		require.NoError(t, err, mode)
		buf := make([]byte, 64)
		n, addr, err := conn.ReadFrom(buf)
		require.NoError(t, err, mode)
		require.Equal(t, "pong", string(buf[:n]), mode)
		require.Equal(t, server.LocalAddr().String(), addr.String())
	}
}
