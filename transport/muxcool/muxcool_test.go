package muxcool

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func socksaddr(s string) M.Socksaddr {
	return M.ParseSocksaddr(s)
}

// The byte layout is that of Xray-core common/mux/frame.go.
func TestMetadataWire(t *testing.T) {
	cases := []struct {
		name    string
		meta    Metadata
		payload int
		wire    string
	}{
		{"new tcp ipv4 with data",
			Metadata{SessionID: 1, Status: StatusNew, Option: OptionData, Target: Endpoint{NetworkTCP, socksaddr("1.2.3.4:443")}}, 5,
			"000c" + "0001" + "01" + "01" + "01" + "01bb" + "01" + "01020304" + "0005"},
		{"new tcp domain without data",
			Metadata{SessionID: 2, Status: StatusNew, Target: Endpoint{NetworkTCP, socksaddr("example.org:80")}}, 0,
			"0014" + "0002" + "01" + "00" + "01" + "0050" + "02" + "0b" + hex.EncodeToString([]byte("example.org"))},
		{"new udp ipv6 with global id",
			Metadata{SessionID: 3, Status: StatusNew, Option: OptionData, Target: Endpoint{NetworkUDP, socksaddr("[2001:db8::1]:53")}, GlobalID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, 9,
			"0020" + "0003" + "01" + "01" + "02" + "0035" + "03" + "20010db8000000000000000000000001" + "0102030405060708" + "0009"},
		{"keep stream",
			Metadata{SessionID: 1, Status: StatusKeep, Option: OptionData}, 8192,
			"0004" + "0001" + "02" + "01" + "2000"},
		{"keep udp packet",
			Metadata{SessionID: 3, Status: StatusKeep, Option: OptionData, Target: Endpoint{NetworkUDP, socksaddr("9.9.9.9:53")}}, 2,
			"000c" + "0003" + "02" + "01" + "02" + "0035" + "01" + "09090909" + "0002"},
		{"end with error",
			Metadata{SessionID: 1, Status: StatusEnd, Option: OptionError}, 0,
			"0004" + "0001" + "03" + "02"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.meta.Append(nil, tc.payload)
			require.NoError(t, err)
			assert.Equal(t, tc.wire, hex.EncodeToString(b))

			r := bytes.NewReader(b)
			got, err := ReadMetadata(r, false)
			require.NoError(t, err)
			assert.Equal(t, tc.meta, got)
			if tc.meta.HasData() {
				n, err := ReadPayloadLen(r)
				require.NoError(t, err)
				assert.Equal(t, tc.payload, n)
			}
			assert.Zero(t, r.Len())
		})
	}
}

// A reverse proxy portal puts the endpoints of the original connection after
// the target of a new session.
func TestMetadataReverse(t *testing.T) {
	meta := Metadata{
		SessionID: 7, Status: StatusNew, Option: OptionData,
		Target: Endpoint{NetworkTCP, socksaddr("10.0.0.1:22")},
		Source: Endpoint{NetworkTCP, socksaddr("203.0.113.5:51000")},
		Local:  Endpoint{NetworkTCP, socksaddr("198.51.100.1:443")},
	}
	b, err := meta.Append(nil, 1)
	require.NoError(t, err)
	got, err := ReadMetadata(bytes.NewReader(b), true)
	require.NoError(t, err)
	assert.Equal(t, meta, got)

	// an ordinary peer reads the same block as a session without those
	got, err = ReadMetadata(bytes.NewReader(b), false)
	require.NoError(t, err)
	assert.Equal(t, meta.Target, got.Target)
	assert.Zero(t, got.Source)

	// the source alone, and none at all
	meta.Local = Endpoint{}
	b, err = meta.Append(nil, 1)
	require.NoError(t, err)
	got, err = ReadMetadata(bytes.NewReader(b), true)
	require.NoError(t, err)
	assert.Equal(t, meta, got)
	meta.Source = Endpoint{}
	b, err = meta.Append(nil, 1)
	require.NoError(t, err)
	got, err = ReadMetadata(bytes.NewReader(b), true)
	require.NoError(t, err)
	assert.Equal(t, meta, got)
}

func TestMetadataInvalid(t *testing.T) {
	for _, wire := range []string{
		"0003" + "000101",                                                 // shorter than a header
		"0005" + "0001" + "01" + "00" + "01",                              // new without an address
		"0008" + "0001" + "01" + "00" + "03" + "0050" + "01",              // unknown network
		"000b" + "0001" + "01" + "00" + "01" + "0050" + "09" + "01020304", // unknown address type
		"0201", // metadata too long
	} {
		b, err := hex.DecodeString(wire)
		require.NoError(t, err)
		_, err = ReadMetadata(bytes.NewReader(b), false)
		assert.Error(t, err, wire)
	}
	_, err := (&Metadata{Status: StatusNew, Target: Endpoint{NetworkTCP, M.Socksaddr{}}}).Append(nil, 0)
	assert.Error(t, err)
	for _, n := range []int{-1, 0x10000} {
		_, err = (&Metadata{Status: StatusKeep, Option: OptionData}).Append(nil, n)
		assert.Error(t, err)
	}
}

// peer is the other end of a carrier: it echoes the payload of every session
// and records what it has seen.
type peer struct {
	conn net.Conn

	mu      sync.Mutex
	news    []Metadata
	ends    []uint16
	largest int
	hold    chan struct{} // while set, the peer does not answer
}

func newPeer(conn net.Conn) *peer {
	p := &peer{conn: conn}
	go p.run()
	return p
}

func (p *peer) write(meta Metadata, payload []byte) {
	b, _ := meta.Append(nil, len(payload))
	_, _ = p.conn.Write(append(b, payload...))
}

func (p *peer) run() {
	reader := bufio.NewReader(p.conn)
	for {
		meta, err := ReadMetadata(reader, false)
		if err != nil {
			return
		}
		var payload []byte
		if meta.HasData() {
			n, err := ReadPayloadLen(reader)
			if err != nil {
				return
			}
			payload = make([]byte, n)
			if _, err = io.ReadFull(reader, payload); err != nil {
				return
			}
		}
		p.mu.Lock()
		hold := p.hold
		switch meta.Status {
		case StatusNew:
			p.news = append(p.news, meta)
		case StatusEnd:
			p.ends = append(p.ends, meta.SessionID)
		}
		if len(payload) > p.largest {
			p.largest = len(payload)
		}
		p.mu.Unlock()
		if hold != nil {
			<-hold
		}
		if meta.HasData() {
			answer := Metadata{SessionID: meta.SessionID, Status: StatusKeep, Option: OptionData}
			if meta.Target.Network == NetworkUDP {
				answer.Target = meta.Target // the packet comes back from where it went
			}
			p.write(answer, payload)
		}
	}
}

func (p *peer) seen() (news []Metadata, ends []uint16, largest int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Metadata(nil), p.news...), append([]uint16(nil), p.ends...), p.largest
}

func newCarrier(t *testing.T, limits Limits) (*Carrier, *peer) {
	t.Helper()
	local, remote := net.Pipe()
	carrier := NewCarrier(local, limits)
	t.Cleanup(func() {
		_ = carrier.Close()
		_ = remote.Close()
	})
	return carrier, newPeer(remote)
}

func echo(t *testing.T, conn net.Conn, size int) {
	t.Helper()
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
	require.True(t, bytes.Equal(data, got))
}

func TestStream(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	require.True(t, conn.(interface{ NeedHandshake() bool }).NeedHandshake())

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
	require.False(t, conn.(interface{ NeedHandshake() bool }).NeedHandshake())
	echo(t, conn, 300000) // cut in frames, and more than the receive buffer

	news, _, largest := peer.seen()
	require.Len(t, news, 1)
	assert.Equal(t, uint16(1), news[0].SessionID)
	assert.Equal(t, Endpoint{NetworkTCP, socksaddr("example.org:443")}, news[0].Target)
	assert.True(t, news[0].HasData(), "the first write travels in the frame that opens the session")
	assert.Equal(t, MaxPayload, largest)

	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { _, ends, _ := peer.seen(); return len(ends) == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, 0, carrier.Sessions())
	_, err = conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed)

	// the next session gets the next ID
	conn, err = carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 1)
	news, _, _ = peer.seen()
	assert.Equal(t, uint16(2), news[1].SessionID)
}

// A session that is read before it is written opens without data.
func TestStreamReadFirst(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:22"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, errDeadline)
	news, _, _ := peer.seen()
	require.Len(t, news, 1)
	assert.False(t, news[0].HasData())

	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	echo(t, conn, 10)
	news, _, _ = peer.seen()
	require.Len(t, news, 1, "the session is opened once")
}

func TestStreamPeerEnd(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	other, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	echo(t, other, 10)

	// data before the end frame is still delivered
	peer.write(Metadata{SessionID: 1, Status: StatusKeep, Option: OptionData}, []byte("bye"))
	peer.write(Metadata{SessionID: 1, Status: StatusEnd}, nil)
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, "bye", string(got))
	_, err = conn.Write([]byte("x"))
	assert.ErrorIs(t, err, io.ErrClosedPipe)

	peer.write(Metadata{SessionID: 2, Status: StatusEnd, Option: OptionError}, nil)
	_, err = other.Read(make([]byte, 1))
	assert.ErrorIs(t, err, ErrSessionClosed)
	assert.False(t, carrier.Closed())

	// a frame for a session that is gone is answered with an end frame
	peer.write(Metadata{SessionID: 1, Status: StatusKeep, Option: OptionData}, []byte("late"))
	conn, err = carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	_, ends, _ := peer.seen()
	assert.Contains(t, ends, uint16(1))
}

// A session that is not read holds the carrier back instead of losing data
// or buffering without bound.
func TestStreamBackpressure(t *testing.T) {
	carrier, _ := newCarrier(t, Limits{})
	slow, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	data := make([]byte, 4*streamBuffer)
	_, _ = rand.Read(data)
	written := make(chan error, 1)
	go func() {
		_, err := slow.Write(data)
		written <- err
	}()

	time.Sleep(200 * time.Millisecond) // the echo piles up unread
	select {
	case <-written:
		t.Fatal("the writer must be held back")
	default:
	}
	s := slow.(*streamConn).session
	s.mu.Lock()
	queued := s.queued
	s.mu.Unlock()
	assert.GreaterOrEqual(t, queued, streamBuffer)
	assert.Less(t, queued, streamBuffer+MaxPayload)

	got := make([]byte, len(data))
	_, err = io.ReadFull(slow, got)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, got))
	require.NoError(t, <-written)
}

// Closing a session does not wait for a carrier that is stuck, and the
// carrier gives up on a peer that reads nothing.
func TestStuckCarrier(t *testing.T) {
	old := writeTimeout
	writeTimeout = 300 * time.Millisecond
	defer func() { writeTimeout = old }()

	local, remote := net.Pipe() // nobody reads remote
	defer remote.Close()
	carrier := NewCarrier(local, Limits{})
	defer carrier.Close()
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	other, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("stuck"))
		written <- err
	}()
	time.Sleep(50 * time.Millisecond)

	closed := make(chan struct{})
	go func() {
		_ = conn.Close()
		_ = other.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close must not wait for the carrier")
	}
	select {
	case err = <-written:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the stuck write must end")
	}
	<-carrier.Done()
}

// Empty frames carry nothing and must not pile up in a session.
func TestStreamEmptyFrames(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	for i := 0; i < 1000; i++ {
		peer.write(Metadata{SessionID: 1, Status: StatusKeep, Option: OptionData}, nil)
	}
	echo(t, conn, 10)
	s := conn.(*streamConn).session
	s.mu.Lock()
	defer s.mu.Unlock()
	assert.Empty(t, s.queue)
}

// Every blocked reader wakes up when the session ends.
func TestPacketReadersWake(t *testing.T) {
	for _, end := range []string{"close", "peer end", "carrier"} {
		t.Run(end, func(t *testing.T) {
			carrier, peer := newCarrier(t, Limits{})
			pc, err := carrier.OpenPacket(socksaddr("9.9.9.9:53"), [8]byte{})
			require.NoError(t, err)
			_, err = pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("9.9.9.9:53")))
			require.NoError(t, err)
			_, _, err = pc.ReadFrom(make([]byte, 10))
			require.NoError(t, err)

			var wg sync.WaitGroup
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _, _ = pc.ReadFrom(make([]byte, 10))
				}()
			}
			time.Sleep(50 * time.Millisecond)
			switch end {
			case "close":
				_ = pc.Close()
			case "peer end":
				peer.write(Metadata{SessionID: 1, Status: StatusEnd}, nil)
			case "carrier":
				_ = peer.conn.Close()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("readers left blocked")
			}
		})
	}
}

func TestPacket(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	globalID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	pc, err := carrier.OpenPacket(socksaddr("9.9.9.9:53"), globalID)
	require.NoError(t, err)

	buf := make([]byte, 2000)
	for _, to := range []string{"9.9.9.9:53", "1.1.1.1:53", "[2001:db8::1]:5353"} {
		addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(to))
		_, err = pc.WriteTo([]byte(to), addr)
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, to, string(buf[:n]))
		assert.Equal(t, addr.String(), from.String())
	}
	news, _, _ := peer.seen()
	require.Len(t, news, 1)
	assert.Equal(t, Endpoint{NetworkUDP, socksaddr("9.9.9.9:53")}, news[0].Target)
	assert.Equal(t, globalID, news[0].GlobalID)

	// a packet Xray-core cannot carry is refused, not sent
	_, err = pc.WriteTo(make([]byte, MaxPayload+1), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("9.9.9.9:53")))
	require.ErrorIs(t, err, ErrPacketTooLarge)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err = pc.ReadFrom(buf)
	assert.ErrorIs(t, err, errDeadline)

	// a packet without an address came from where the first one went
	peer.write(Metadata{SessionID: 1, Status: StatusKeep, Option: OptionData}, []byte("y"))
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Second)))
	_, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "9.9.9.9:53", from.String())

	require.NoError(t, pc.Close())
	require.Eventually(t, func() bool { _, ends, _ := peer.seen(); return len(ends) == 1 }, time.Second, time.Millisecond)
}

func TestCarrierLimitsAndClose(t *testing.T) {
	carrier, _ := newCarrier(t, Limits{MaxConcurrency: 2, MaxSessions: 3})
	first, err := carrier.OpenStream(socksaddr("example.org:1"))
	require.NoError(t, err)
	second, err := carrier.OpenStream(socksaddr("example.org:2"))
	require.NoError(t, err)
	_, err = carrier.OpenStream(socksaddr("example.org:3"))
	require.ErrorIs(t, err, ErrCarrierFull)
	require.True(t, carrier.Full())

	require.NoError(t, first.Close())
	third, err := carrier.OpenStream(socksaddr("example.org:3"))
	require.NoError(t, err)
	require.NoError(t, third.Close())
	require.True(t, carrier.Full(), "the carrier has had all the sessions of its life")

	echo(t, second, 10)
	require.NoError(t, carrier.Close())
	_, err = second.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = carrier.OpenStream(socksaddr("example.org:4"))
	require.ErrorIs(t, err, net.ErrClosed)
	select {
	case <-carrier.Done():
	default:
		t.Fatal("the carrier must be done")
	}
}

func TestCarrierPeerGone(t *testing.T) {
	carrier, peer := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	require.NoError(t, peer.conn.Close())
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	<-carrier.Done()
}

func TestClient(t *testing.T) {
	var dials atomic.Int32
	var peers sync.Map
	dial := func(ctx context.Context) (net.Conn, error) {
		local, remote := net.Pipe()
		peers.Store(dials.Add(1), newPeer(remote))
		return local, nil
	}
	client := NewClient(dial, 2)
	defer client.Close()
	ctx := context.Background()

	var conns []net.Conn
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 5; i++ { // a burst of sessions: 2 + 2 + 1
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := client.DialContext(ctx, socksaddr("example.org:443"))
			require.NoError(t, err)
			echo(t, conn, 1000)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(3), dials.Load())
	assert.Equal(t, 3, client.Carriers())

	// a freed place is used before a new carrier is opened
	require.NoError(t, conns[0].Close())
	pc, err := client.ListenPacket(ctx, socksaddr("9.9.9.9:53"), [8]byte{})
	require.NoError(t, err)
	_, err = pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("9.9.9.9:53")))
	require.NoError(t, err)
	assert.Equal(t, int32(3), dials.Load())

	// a carrier that died is replaced
	peers.Range(func(_, p any) bool {
		_ = p.(*peer).conn.Close()
		return true
	})
	require.Eventually(t, func() bool { return client.Carriers() == 0 }, time.Second, time.Millisecond)
	conn, err := client.DialContext(ctx, socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	assert.Equal(t, int32(4), dials.Load())

	require.NoError(t, client.Close())
	_, err = client.DialContext(ctx, socksaddr("example.org:443"))
	require.ErrorIs(t, err, net.ErrClosed)
}

// A caller waiting for somebody else's dial gives up with its context.
func TestClientDialContext(t *testing.T) {
	release := make(chan struct{})
	dial := func(ctx context.Context) (net.Conn, error) {
		<-release
		local, remote := net.Pipe()
		newPeer(remote)
		return local, nil
	}
	client := NewClient(dial, 0)
	defer client.Close()
	first := make(chan error, 1)
	go func() {
		_, err := client.DialContext(context.Background(), socksaddr("example.org:443"))
		first <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.DialContext(ctx, socksaddr("example.org:443"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	close(release)
	require.NoError(t, <-first)
}

func TestCarrierIdle(t *testing.T) {
	old := idleInterval
	idleInterval = 20 * time.Millisecond
	defer func() { idleInterval = old }()

	carrier, _ := newCarrier(t, Limits{})
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	time.Sleep(100 * time.Millisecond)
	require.False(t, carrier.Closed(), "a carrier with a session stays")
	require.NoError(t, conn.Close())
	select {
	case <-carrier.Done():
	case <-time.After(time.Second):
		t.Fatal("an idle carrier must close")
	}
}
