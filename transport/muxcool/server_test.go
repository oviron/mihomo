package muxcool

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoHandler echoes every session and records the frames that opened them.
type echoHandler struct {
	mu    sync.Mutex
	metas []Metadata
}

func (h *echoHandler) record(meta Metadata) {
	h.mu.Lock()
	h.metas = append(h.metas, meta)
	h.mu.Unlock()
}

func (h *echoHandler) NewStream(conn net.Conn, meta Metadata) {
	h.record(meta)
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func (h *echoHandler) NewPacket(conn net.PacketConn, meta Metadata) {
	h.record(meta)
	defer conn.Close()
	buf := make([]byte, 2000)
	for {
		n, to, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		// answer from the address the packet was sent to
		if _, err = conn.WriteTo(buf[:n], to); err != nil {
			return
		}
	}
}

func newPair(t *testing.T, reverse bool) (*Carrier, *Carrier, *echoHandler) {
	t.Helper()
	local, remote := net.Pipe()
	handler := &echoHandler{}
	client := NewCarrier(local, Limits{})
	server := NewServerCarrier(remote, handler, reverse)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server, handler
}

func TestServerCarrier(t *testing.T) {
	client, server, handler := newPair(t, false)

	conn, err := client.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	echo(t, conn, 200000)

	pc, err := client.OpenPacket(socksaddr("9.9.9.9:53"), [8]byte{1})
	require.NoError(t, err)
	buf := make([]byte, 2000)
	for _, to := range []string{"9.9.9.9:53", "1.1.1.1:53"} {
		addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(to))
		_, err = pc.WriteTo([]byte(to), addr)
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, to, string(buf[:n]))
		assert.Equal(t, to, from.String())
	}

	require.Eventually(t, func() bool { handler.mu.Lock(); defer handler.mu.Unlock(); return len(handler.metas) == 2 }, time.Second, time.Millisecond)
	assert.Equal(t, Endpoint{NetworkTCP, socksaddr("example.org:443")}, handler.metas[0].Target)
	assert.Equal(t, Endpoint{NetworkUDP, socksaddr("9.9.9.9:53")}, handler.metas[1].Target)
	assert.Equal(t, [8]byte{1}, handler.metas[1].GlobalID)

	// the client ends a session: the handler's connection sees the end
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return server.Sessions() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, pc.Close())
	require.Eventually(t, func() bool { return server.Sessions() == 0 }, time.Second, time.Millisecond)
}

// A reverse proxy portal names the endpoints of the connection it received.
func TestServerCarrierReverse(t *testing.T) {
	local, remote := net.Pipe()
	handler := &echoHandler{}
	server := NewServerCarrier(remote, handler, true)
	defer server.Close()
	portal := newPeerWriter(local)
	defer local.Close()

	meta := Metadata{
		SessionID: 9, Status: StatusNew, Option: OptionData,
		Target: Endpoint{NetworkTCP, socksaddr("192.168.1.10:22")},
		Source: Endpoint{NetworkTCP, socksaddr("203.0.113.5:51000")},
		Local:  Endpoint{NetworkTCP, socksaddr("198.51.100.1:443")},
	}
	portal.write(meta, []byte("hello"))
	got, payload := portal.read(t)
	assert.Equal(t, uint16(9), got.SessionID)
	assert.Equal(t, StatusKeep, got.Status)
	assert.Equal(t, "hello", string(payload))
	handler.mu.Lock()
	assert.Equal(t, meta, handler.metas[0])
	handler.mu.Unlock()

	portal.write(Metadata{SessionID: 9, Status: StatusEnd}, nil)
	got, _ = portal.read(t) // the handler closed its side in answer
	assert.Equal(t, StatusEnd, got.Status)
}

// The accepting side opens nothing, and a session ID the peer uses again
// belongs to the new session.
func TestServerCarrierSessionIDs(t *testing.T) {
	local, remote := net.Pipe()
	handler := &echoHandler{}
	server := NewServerCarrier(remote, handler, false)
	defer server.Close()
	defer local.Close()
	peer := newPeerWriter(local)

	_, err := server.OpenStream(socksaddr("example.org:443"))
	require.Error(t, err)

	open := Metadata{SessionID: 5, Status: StatusNew, Option: OptionData, Target: Endpoint{NetworkTCP, socksaddr("example.org:1")}}
	peer.write(open, []byte("one"))
	_, payload := peer.read(t)
	assert.Equal(t, "one", string(payload))

	open.Target.Addr = socksaddr("example.org:2")
	peer.write(open, []byte("two")) // the same ID again: the first session is over
	got, payload := peer.read(t)
	if got.Status == StatusEnd { // the first handler letting go
		got, payload = peer.read(t)
	}
	assert.Equal(t, "two", string(payload))
	require.Eventually(t, func() bool { return server.Sessions() == 1 }, time.Second, time.Millisecond)

	peer.write(Metadata{SessionID: 5, Status: StatusKeep, Option: OptionData}, []byte("more"))
	for {
		got, payload = peer.read(t)
		if got.Status == StatusKeep {
			break
		}
	}
	assert.Equal(t, "more", string(payload))
	handler.mu.Lock()
	defer handler.mu.Unlock()
	require.Len(t, handler.metas, 2)
	assert.Equal(t, socksaddr("example.org:2"), handler.metas[1].Target.Addr)
}

// deadlineConn closes itself when a write deadline that was left set
// expires, like the gRPC and XHTTP connections of this repository do.
type deadlineConn struct {
	net.Conn
	mu    sync.Mutex
	timer *time.Timer
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if !t.IsZero() {
		c.timer = time.AfterFunc(time.Until(t), func() { _ = c.Conn.Close() })
	}
	return nil
}

// A carrier must not leave a write deadline behind: the connection would be
// closed some time after a write that had long succeeded.
func TestCarrierWriteDeadlineCleared(t *testing.T) {
	local, remote := net.Pipe()
	carrier := newCarrier(&deadlineConn{Conn: local}, Limits{}, defaultIdleInterval, 100*time.Millisecond)
	defer carrier.Close()
	newPeer(remote)
	conn, err := carrier.OpenStream(socksaddr("example.org:443"))
	require.NoError(t, err)
	echo(t, conn, 10)
	time.Sleep(300 * time.Millisecond)
	require.False(t, carrier.Closed())
	echo(t, conn, 10)
}
