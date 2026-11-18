package xmc

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testServer is the server side of the mask as Xray-core's server.go has it,
// as far as the client can tell.
type testServer struct {
	password string
	profiles []profile
	// stopAfterHello makes the server go silent after the Login Start packet.
	stopAfterHello bool
	// extraPadding is added to the length of the server's first turn.
	extraPadding int

	// what the client sent
	host        string
	port        int
	player      string
	turnLengths []int
}

// accept logs the client in and returns the stream that carries the payload.
func (s *testServer) accept(conn net.Conn) (*wire, error) {
	w := &wire{r: bufio.NewReader(conn), w: conn}
	id, data, _, err := w.readPacket()
	if err != nil || id != idHandshake {
		return nil, fmt.Errorf("handshake packet 0x%x: %v", id, err)
	}
	hello := fields{data: data}
	version := hello.varint()
	s.host = hello.str()
	s.port = int(binary.BigEndian.Uint16(hello.take(2)))
	if state := hello.varint(); hello.err != nil || version != protocolVersion || state != stateLogin || len(hello.data) != 0 {
		return nil, fmt.Errorf("bad handshake packet %x", data)
	}

	if id, data, _, err = w.readPacket(); err != nil || id != idLoginStart {
		return nil, fmt.Errorf("login start packet 0x%x: %v", id, err)
	}
	start := fields{data: data}
	s.player = start.str()
	var uuid [16]byte
	copy(uuid[:], start.take(16))
	if start.err != nil || len(start.data) != 0 {
		return nil, fmt.Errorf("bad login start packet %x", data)
	}
	if s.stopAfterHello {
		return nil, nil
	}

	key := testPrivateKey(s.password)
	public, err := deriveKey(s.password)
	if err != nil {
		return nil, err
	}
	token := []byte{0xde, 0xad, 0xbe, 0xef}
	err = w.writePacket(idEncryption, appendPrefixed(nil, ""), appendPrefixed(nil, string(public.der)),
		appendPrefixed(nil, string(token)), []byte{1})
	if err != nil {
		return nil, err
	}
	if id, data, _, err = w.readPacket(); err != nil || id != idEncryption {
		return nil, fmt.Errorf("encryption response 0x%x: %v", id, err)
	}
	response := fields{data: data}
	secret, err := rsa.DecryptPKCS1v15(rand.Reader, key, response.bytes())
	if err != nil || len(secret) != 16 {
		return nil, fmt.Errorf("shared secret of %d bytes: %v", len(secret), err)
	}
	proof, err := rsa.DecryptPKCS1v15(rand.Reader, key, response.bytes())
	if err != nil || response.err != nil || len(response.data) != 0 {
		return nil, fmt.Errorf("bad encryption response: %v", err)
	}
	if !bytes.Equal(proof, append(token, s.password...)) {
		return nil, errors.New("verify token or password mismatch")
	}
	w.enc, _ = newCFB8(secret, secret, false)
	w.dec, _ = newCFB8(secret, secret, true)

	var player *profile
	for i := range s.profiles {
		if s.profiles[i].username == s.player && s.profiles[i].uuid == uuid {
			player = &s.profiles[i]
		}
	}
	if player == nil {
		return nil, w.writePacket(idDisconnect, appendPrefixed(nil, `{"text":"You are not white-listed on this server!"}`))
	}
	err = w.writePacket(idLoginSuccess, player.uuid[:], appendPrefixed(nil, player.username), []byte{1},
		appendPrefixed(nil, "textures"), appendPrefixed(nil, player.texturesValue), []byte{1},
		appendPrefixed(nil, player.texturesSignature))
	if err != nil {
		return nil, err
	}
	if id, data, _, err = w.readPacket(); err != nil || id != idLoginAcknowledged || len(data) != 0 {
		return nil, fmt.Errorf("login acknowledged 0x%x %x: %v", id, data, err)
	}

	for i := range schedule {
		t := &schedule[i]
		if !t.fromClient {
			chunks := []int{t.min}
			if len(t.templates) > 0 {
				chunks = t.templates[len(t.templates)-1]
			}
			if i == 1 && s.extraPadding != 0 {
				chunks = append(append([]int(nil), chunks...), s.extraPadding)
			}
			if err = w.writePadding(chunks); err != nil {
				return nil, err
			}
			continue
		}
		length, size, err := readVarint(w.readByte)
		if err != nil {
			return nil, err
		}
		if !t.accepts(t.prefix + int(length)) {
			return nil, fmt.Errorf("turn %d has length %d", i, length)
		}
		s.turnLengths = append(s.turnLengths, int(length))
		if err = w.discard(int(length) - size); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// testPair returns a client connection under the mask and the server end of
// the TCP connection below it.
func testPair(t *testing.T, settings map[string]any) (*Conn, net.Conn) {
	t.Helper()
	conn, server, _ := testFaultyPair(t, settings)
	return conn, server
}

// testFaultyPair is testPair with the means to disturb the client's side of
// the TCP connection.
func testFaultyPair(t *testing.T, settings map[string]any) (*Conn, net.Conn, *faultyConn) {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	faulty := &faultyConn{Conn: client}
	conn, err := m.WrapConn(faulty)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
	})
	return conn.(*Conn), server, faulty
}

// faultyConn is a connection whose writes can be held back or made to fail,
// and that remembers its deadlines.
type faultyConn struct {
	net.Conn
	mu          sync.Mutex
	hold        chan struct{} // writes wait until it is closed
	failWritten int           // the next write passes this many bytes on
	failErr     error         // and fails with this
	read, write time.Time
}

func (c *faultyConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	hold, n, err := c.hold, c.failWritten, c.failErr
	c.failErr = nil
	c.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if err != nil {
		if _, writeErr := c.Conn.Write(p[:n]); writeErr != nil {
			return 0, writeErr
		}
		return n, err
	}
	return c.Conn.Write(p)
}

func (c *faultyConn) set(change func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change()
}

func (c *faultyConn) SetDeadline(t time.Time) error {
	c.set(func() { c.read, c.write = t, t })
	return c.Conn.SetDeadline(t)
}

func (c *faultyConn) SetReadDeadline(t time.Time) error {
	c.set(func() { c.read = t })
	return c.Conn.SetReadDeadline(t)
}

func (c *faultyConn) SetWriteDeadline(t time.Time) error {
	c.set(func() { c.write = t })
	return c.Conn.SetWriteDeadline(t)
}

func (c *faultyConn) deadlines() (read, write time.Time) {
	c.set(func() { read, write = c.read, c.write })
	return read, write
}

// testEcho sends the payload of the client back until the stream ends.
func testEcho(w *wire) {
	for {
		id, data, _, err := w.readPacket()
		if err != nil {
			return
		}
		if id == idPayloadFromClient {
			payload := fields{data: data}
			_ = payload.str()
			if w.writePacket(idPayloadFromServer, payloadChannelField, append([]byte(nil), payload.data...)) != nil {
				return
			}
		}
	}
}

// testLogin logs conn in to the server and returns the server's end of the
// stream.
func testLogin(t *testing.T, conn *Conn, serverConn net.Conn, server *testServer) *wire {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(nil)
		done <- err
	}()
	w, err := server.accept(serverConn)
	require.NoError(t, err)
	require.NoError(t, <-done)
	return w
}

func testServerFor(t *testing.T, settings map[string]any) *testServer {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	return &testServer{password: m.password, profiles: m.profiles}
}

func TestConn(t *testing.T) {
	settings := testSettings("unit-test-password", "first_player", "second_player")
	settings["hostname"] = "mc.example.org"
	conn, serverConn := testPair(t, settings)
	server := testServerFor(t, settings)

	// The mask changes every byte: the relay must not reach below it.
	_, ok := any(conn).(interface{ Upstream() any })
	require.False(t, ok)
	_, ok = any(conn).(interface{ ReaderReplaceable() bool })
	require.False(t, ok)
	_, ok = any(conn).(interface{ WriterReplaceable() bool })
	require.False(t, ok)
	require.Equal(t, serverConn.LocalAddr().String(), conn.RemoteAddr().String())

	// The server echoes the payload packet by packet and sends a keep-alive
	// packet ahead of every answer.
	const packets = 40
	var (
		serverErr = make(chan error, 1)
		mu        sync.Mutex
		sizes     []int // of the payload packets of the client
		answered  []uint64
	)
	go func() {
		serverErr <- func() error {
			w, err := server.accept(serverConn)
			if err != nil {
				return err
			}
			for sent := uint64(0); ; {
				id, data, _, err := w.readPacket()
				if err != nil {
					return err
				}
				mu.Lock()
				switch id {
				case idKeepAlive:
					if len(data) != 8 {
						err = fmt.Errorf("keep-alive answer %x", data)
					}
					answered = append(answered, binary.BigEndian.Uint64(data))
				case idPayloadFromClient:
					payload := fields{data: data}
					if channel := payload.str(); channel != payloadChannel {
						err = fmt.Errorf("payload channel %q", channel)
					}
					sizes = append(sizes, len(payload.data))
					data = append([]byte(nil), payload.data...)
				default:
					err = fmt.Errorf("packet 0x%x", id)
				}
				mu.Unlock()
				if err != nil || id == idKeepAlive {
					if err != nil {
						return err
					}
					continue
				}
				sent++
				number := binary.BigEndian.AppendUint64(nil, sent)
				err = w.writePacket(idKeepAlive, number)
				if err == nil { // a packet of another channel and an empty one are skipped
					err = w.writePacket(idPayloadFromServer, appendPrefixed(nil, "minecraft:brand"), []byte("vanilla"))
				}
				if err == nil {
					err = w.writePacket(idPayloadFromServer, payloadChannelField)
				}
				if err == nil {
					err = w.writePacket(idPayloadFromServer, payloadChannelField, data)
				}
				if err != nil {
					return err
				}
			}
		}()
	}()

	data := make([]byte, packets*maxPayload-100)
	_, _ = rand.Read(data)
	writeErr := make(chan error, 1)
	go func() {
		// writes of several sizes, the last one of many packets
		_, err := conn.Write(data[:5])
		if err == nil {
			_, err = conn.Write(data[5 : maxPayload+7]) // one packet and 2 bytes
		}
		if err == nil {
			_, err = conn.Write(data[maxPayload+7:])
		}
		writeErr <- err
	}()
	got := make([]byte, len(data))
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.True(t, bytes.Equal(data, got))

	// A read that runs into its deadline between two packets can be repeated.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = conn.Read(got)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	n, err := conn.Write([]byte("again"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	_, err = io.ReadFull(conn, got[:5])
	require.NoError(t, err)
	require.Equal(t, "again", string(got[:5]))
	n, err = conn.Read(nil)
	require.NoError(t, err)
	require.Zero(t, n)

	// The end of the stream is a plain EOF.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(answered) == len(sizes)
	}, 5*time.Second, 5*time.Millisecond, "every keep-alive is answered")
	require.NoError(t, serverConn.Close())
	_, err = conn.Read(got)
	require.Equal(t, io.EOF, err)
	require.Error(t, <-serverErr)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "mc.example.org", server.host)
	require.Equal(t, serverConn.LocalAddr().(*net.TCPAddr).Port, server.port)
	require.Contains(t, []string{"first_player", "second_player"}, server.player)
	require.Len(t, server.turnLengths, 20)
	require.Equal(t, []int{42, 25, 2}, server.turnLengths[:3])
	// 5 bytes, a full packet and 2 bytes, then full packets and the rest
	require.Equal(t, []int{5, maxPayload, 2, maxPayload, maxPayload}, sizes[:5])
	require.Equal(t, len(data)+5, sumOf(sizes))
	for _, size := range sizes {
		require.LessOrEqual(t, size, maxPayload)
	}
	// every keep-alive was answered, in order, between the payload packets
	require.Len(t, answered, len(sizes))
	for i, number := range answered {
		require.EqualValues(t, i+1, number)
	}
}

func TestConnUsesRemoteAddress(t *testing.T) {
	settings := testSettings("unit-test-password", "player")
	conn, serverConn := testPair(t, settings)
	server := testServerFor(t, settings)
	server.stopAfterHello = true
	go func() { _, _ = conn.Write([]byte("x")) }()
	_, err := server.accept(serverConn)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", server.host)
	require.Equal(t, serverConn.LocalAddr().(*net.TCPAddr).Port, server.port)
	require.Equal(t, "player", server.player)
}

func TestConnHandshakeFailures(t *testing.T) {
	run := func(t *testing.T, client, server map[string]any, change func(*testServer)) error {
		conn, serverConn := testPair(t, client)
		s := testServerFor(t, server)
		if change != nil {
			change(s)
		}
		go func() {
			_, _ = s.accept(serverConn)
			_, _ = io.Copy(io.Discard, serverConn)
		}()
		_, err := conn.Write([]byte("payload"))
		require.Error(t, err)
		// the failure stays: the stream is not read or written again
		_, again := conn.Read(make([]byte, 1))
		require.Equal(t, err, again)
		_, again = conn.Write(nil)
		require.Equal(t, err, again)
		return err
	}

	t.Run("another password", func(t *testing.T) {
		err := run(t, testSettings("client-password", "player"), testSettings("server-password", "player"), nil)
		require.ErrorContains(t, err, "server public key mismatch")
	})
	t.Run("unknown profile", func(t *testing.T) {
		err := run(t, testSettings("password", "stranger"), testSettings("password", "player"), nil)
		require.ErrorContains(t, err, "the server refused the login")
		require.ErrorContains(t, err, "not white-listed")
	})
	t.Run("another profile confirmed", func(t *testing.T) {
		settings := testSettings("password", "player")
		err := run(t, settings, settings, func(s *testServer) { s.profiles[0].texturesSignature += "x" })
		require.ErrorContains(t, err, "login profile mismatch")
	})
	t.Run("unexpected padding length", func(t *testing.T) {
		settings := testSettings("password", "player")
		err := run(t, settings, settings, func(s *testServer) { s.extraPadding = 1 })
		require.ErrorContains(t, err, "padding turn 1: unexpected length 73")
	})
	t.Run("deadline of the caller", func(t *testing.T) {
		settings := testSettings("password", "player")
		conn, _ := testPair(t, settings)
		require.NoError(t, conn.SetDeadline(time.Now().Add(50*time.Millisecond)))
		start := time.Now()
		_, err := conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.Less(t, time.Since(start), 5*time.Second)
	})
}

func TestConnCloseInterruptsHandshake(t *testing.T) {
	settings := testSettings("password", "player")
	conn, serverConn := testPair(t, settings)
	server := testServerFor(t, settings)
	server.stopAfterHello = true
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		done <- err
	}()
	// the client now waits for the Encryption Request
	_, err := server.accept(serverConn)
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, conn.Close())
	select {
	case err = <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the handshake")
	}
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
	// the pauses of the padding end as well
	require.ErrorIs(t, conn.sleep(time.Hour), net.ErrClosed)
}

// A caller waits for a handshake somebody else started no longer than its own
// deadline allows, and the handshake goes on without it.
func TestConnDeadlineBoundsWaitForHandshake(t *testing.T) {
	settings := testSettings("password", "player")
	conn, serverConn, lower := testFaultyPair(t, settings)
	server := testServerFor(t, settings)
	release := make(chan struct{})
	go func() {
		<-release
		if w, err := server.accept(serverConn); err == nil {
			testEcho(w)
		}
	}()

	// A Read without a deadline starts the handshake and waits for the server.
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()
	isTimeout := func(err error) {
		t.Helper()
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		var netErr net.Error
		require.True(t, errors.As(err, &netErr) && netErr.Timeout())
	}

	start := time.Now()
	require.NoError(t, conn.SetWriteDeadline(start.Add(50*time.Millisecond)))
	n, err := conn.Write([]byte("early"))
	isTimeout(err)
	require.Zero(t, n)
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	require.Less(t, time.Since(start), 2*time.Second)

	// A deadline set while the Write waits counts as well.
	require.NoError(t, conn.SetWriteDeadline(time.Time{}))
	waiting := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("early"))
		waiting <- err
	}()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	select {
	case err = <-waiting:
		isTimeout(err)
	case <-time.After(2 * time.Second):
		t.Fatal("the Write waits past its deadline")
	}

	// Meanwhile the connection below has the deadline of the handshake.
	read, write := lower.deadlines()
	require.WithinDuration(t, time.Now().Add(handshakeTimeout), read, 5*time.Second)
	require.True(t, read.Equal(write))

	// The handshake was not harmed: once the server answers, the connection
	// works and has the deadlines of the caller.
	far := time.Now().Add(time.Hour)
	require.NoError(t, conn.SetWriteDeadline(far))
	close(release)
	_, err = conn.Write([]byte("late"))
	require.NoError(t, err)
	require.Equal(t, "late", <-got)
	read, write = lower.deadlines()
	require.True(t, read.IsZero())
	require.True(t, write.Equal(far))

	// And a Read waits for the handshake within the read deadline.
	conn, _, _ = testFaultyPair(t, settings)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = conn.Read(make([]byte, 1))
	isTimeout(err)
}

// Read hands the answer to a keep-alive packet over and goes on, whatever
// keeps the writing side busy.
func TestConnKeepAliveDoesNotBlockRead(t *testing.T) {
	settings := testSettings("password", "player")
	conn, serverConn, lower := testFaultyPair(t, settings)
	w := testLogin(t, conn, serverConn, testServerFor(t, settings))

	hold := make(chan struct{})
	lower.set(func() { lower.hold = hold })
	for number := byte(1); number <= 3; number++ {
		require.NoError(t, w.writePacket(idKeepAlive, []byte{0, 0, 0, 0, 0, 0, 0, number}))
	}
	require.NoError(t, w.writePacket(idPayloadFromServer, payloadChannelField, []byte("data")))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	require.NoError(t, err, "Read must not wait for the answer to be written")
	require.Equal(t, "data", string(buf[:n]))

	// The answers leave when the writing side can write, in order.
	lower.set(func() { lower.hold = nil })
	close(hold)
	for number := byte(1); number <= 3; number++ {
		id, data, _, err := w.readPacket()
		require.NoError(t, err)
		require.EqualValues(t, idKeepAlive, id)
		require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, number}, data)
	}
	require.Eventually(t, func() bool { return !conn.flushing.Load() }, time.Second, time.Millisecond)
}

func TestConnWriteFailures(t *testing.T) {
	settings := testSettings("password", "player")
	readPayload := func(w *wire) string {
		id, data, _, err := w.readPacket()
		require.NoError(t, err)
		require.EqualValues(t, idPayloadFromClient, id)
		payload := fields{data: data}
		require.Equal(t, payloadChannel, payload.str())
		return string(payload.data)
	}

	// A write that timed out before a byte left can be repeated: nothing of
	// it reached the server and the cipher is where it was.
	conn, serverConn, lower := testFaultyPair(t, settings)
	w := testLogin(t, conn, serverConn, testServerFor(t, settings))
	_, err := conn.Write([]byte("first"))
	require.NoError(t, err)
	lower.set(func() { lower.failErr = os.ErrDeadlineExceeded })
	n, err := conn.Write([]byte("timed out"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Zero(t, n)
	// the second packet of a Write: the first one is counted
	data := bytes.Repeat([]byte("x"), maxPayload+10)
	n, err = conn.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.Equal(t, "first", readPayload(w))
	require.Equal(t, string(data[:maxPayload]), readPayload(w))
	require.Equal(t, string(data[maxPayload:]), readPayload(w))

	// A write that failed after a part of the packet left, or failed for
	// another reason than its deadline, ends the writing.
	for name, fail := range map[string]func(c *faultyConn){
		"partial write": func(c *faultyConn) { c.failWritten, c.failErr = 3, os.ErrDeadlineExceeded },
		"broken":        func(c *faultyConn) { c.failErr = io.ErrClosedPipe },
	} {
		conn, serverConn, lower := testFaultyPair(t, settings)
		testLogin(t, conn, serverConn, testServerFor(t, settings))
		lower.set(func() { fail(lower) })
		_, err := conn.Write([]byte("lost"))
		require.Error(t, err, name)
		_, again := conn.Write([]byte("never sent"))
		require.Equal(t, err, again, name)
	}
}

// The packets of one Write are not mixed with those of another.
func TestConnWritesDoNotInterleave(t *testing.T) {
	settings := testSettings("password", "player")
	conn, serverConn := testPair(t, settings)
	w := testLogin(t, conn, serverConn, testServerFor(t, settings))

	const writers, size = 4, 6*maxPayload + 100
	for round := 0; round < 3; round++ {
		errs := make(chan error, writers)
		for i := 0; i < writers; i++ {
			go func(fill byte) {
				_, err := conn.Write(bytes.Repeat([]byte{fill}, size))
				errs <- err
			}(byte('a' + i))
		}
		var stream []byte
		for len(stream) < writers*size {
			id, data, _, err := w.readPacket()
			require.NoError(t, err)
			require.EqualValues(t, idPayloadFromClient, id)
			stream = append(stream, data[len(payloadChannelField):]...)
		}
		for i := 0; i < writers; i++ {
			require.NoError(t, <-errs)
			block := stream[i*size : (i+1)*size]
			require.Equal(t, size, bytes.Count(block, block[:1]), "write %d of round %d is mixed with another", i, round)
		}
	}
}

func TestDeadlines(t *testing.T) {
	lower := &faultyConn{Conn: deadlineSink{}}
	d := &deadlines{conn: lower, changed: make(chan struct{})}
	done := make(chan struct{})

	// Before the handshake is over the deadlines only bound the wait for it.
	far, soon := time.Now().Add(time.Hour), time.Now().Add(30*time.Millisecond)
	require.NoError(t, d.set(&soon, &far))
	read, write := lower.deadlines()
	require.True(t, read.IsZero() && write.IsZero())
	require.ErrorIs(t, d.wait(done, true), os.ErrDeadlineExceeded)
	require.GreaterOrEqual(t, time.Until(soon), -time.Second)
	require.False(t, time.Now().Before(soon))
	// the write deadline is an hour away: this wait ends with the handshake
	waited := make(chan error, 1)
	go func() { waited <- d.wait(done, false) }()
	select {
	case err := <-waited:
		t.Fatalf("the wait ended early: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	require.NoError(t, d.handOver())
	close(done)
	require.NoError(t, <-waited)
	require.NoError(t, d.wait(done, true))

	// From then on they are the deadlines of the connection.
	read, write = lower.deadlines()
	require.True(t, read.Equal(soon) && write.Equal(far))
	require.NoError(t, d.set(nil, &time.Time{}))
	read, write = lower.deadlines()
	require.True(t, read.Equal(soon) && write.IsZero())
	require.NoError(t, d.set(&far, nil))
	read, write = lower.deadlines()
	require.True(t, read.Equal(far) && write.IsZero())
}

// deadlineSink takes deadlines and does nothing else.
type deadlineSink struct {
	net.Conn
}

func (deadlineSink) SetDeadline(time.Time) error      { return nil }
func (deadlineSink) SetReadDeadline(time.Time) error  { return nil }
func (deadlineSink) SetWriteDeadline(time.Time) error { return nil }
