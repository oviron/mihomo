package custom

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recorder keeps every Write of the client.
type recorder struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.writes = append(r.writes, append([]byte(nil), p...))
	r.mu.Unlock()
	return r.Conn.Write(p)
}

// serve plays the server of the handshake: it reads and checks what the
// client sends and writes what the client reads. It returns its variables.
func serve(conn net.Conn, m *TCP) (map[string][]byte, error) {
	s := &scope{vars: map[string][]byte{}, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	for _, st := range m.steps {
		var err error
		if st.read {
			err = writeItems(conn, st.items, s, nil)
		} else {
			err = readItems(conn, st.items, s)
		}
		if err != nil {
			return nil, err
		}
	}
	return s.vars, nil
}

// pipe returns a masked client connection, a record of what it writes and
// the other end of the connection.
func pipe(t *testing.T, settings obj) (*Conn, *recorder, net.Conn) {
	t.Helper()
	m, err := NewTCP(settings)
	require.NoError(t, err)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	rec := &recorder{Conn: client}
	conn, err := m.WrapConn(rec)
	require.NoError(t, err)
	return conn.(*Conn), rec, server
}

func TestTCPHandshake(t *testing.T) {
	settings := obj{
		"clients": []any{
			[]any{
				obj{"packet": "GET / HTTP/1.1\r\n", "type": "str"},
				obj{"rand": 4, "randRange": "48-57", "capture": "id"},
				obj{"delay": "20-30", "transform": tr("be16", u64(4))["transform"]},
				obj{"reuse": "id"},
			},
			[]any{
				obj{"reuse": "srv"},
				tr("concat", reuse("id"), nested("be32", nested("xor32", u64(0xFFFF), u64(0xFF)))),
				obj{"delay": 1}, // a pause after the last piece
			},
		},
		"servers": []any{
			[]any{obj{"packet": []any{1, 2, 3}}, obj{"reuse": "id"}, obj{"rand": 3, "capture": "srv"}},
			[]any{tr("truncate", reuse("srv"), u64(2))},
			[]any{obj{"packet": "0d0a", "type": "hex", "capture": "end"}, obj{"reuse": "end"}},
		},
	}
	conn, rec, server := pipe(t, settings)
	require.False(t, conn.ReaderReplaceable())
	require.False(t, conn.WriterReplaceable())

	type result struct {
		vars map[string][]byte
		data []byte
		err  error
	}
	served := make(chan result, 1)
	go func() {
		vars, err := serve(server, conn.mask)
		data := make([]byte, 4)
		if err == nil {
			_, err = io.ReadFull(server, data)
		}
		if err == nil {
			_, err = server.Write([]byte("pong"))
		}
		served <- result{vars, data, err}
	}()

	// nothing is to reach under the mask before the handshake
	require.Nil(t, conn.Upstream())
	require.False(t, conn.ReaderReplaceable())

	start := time.Now()
	n, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
	got := make([]byte, 4)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "pong", string(got))

	res := <-served
	require.NoError(t, res.err)
	require.Equal(t, "ping", string(res.data))
	require.True(t, conn.ReaderReplaceable())
	require.True(t, conn.WriterReplaceable())
	require.Same(t, rec, conn.Upstream())

	// The pieces before a delay leave on their own, the rest of a list in one write.
	id, srv := res.vars["id"], res.vars["srv"]
	require.Len(t, id, 4)
	for _, b := range id {
		require.Contains(t, []byte("0123456789"), b)
	}
	require.Len(t, srv, 3)
	require.Equal(t, [][]byte{
		append([]byte("GET / HTTP/1.1\r\n"), id...),
		append([]byte{0, 4}, id...),
		append(append(append([]byte(nil), srv...), id...), 0, 0, 0xFF, 0x00),
		[]byte("ping"),
	}, rec.writes)
}

// The server may be the one the caller waits for first: reading starts the
// handshake as well.
func TestTCPReadStartsTheHandshake(t *testing.T) {
	conn, rec, server := pipe(t, obj{
		"clients": []any{[]any{obj{"packet": "hello", "type": "str"}}},
		"servers": []any{[]any{obj{"packet": "welcome", "type": "str"}}},
	})
	go func() {
		if _, err := serve(server, conn.mask); err == nil {
			_, _ = server.Write([]byte("banner"))
			_, _ = io.ReadFull(server, make([]byte, 4))
		}
	}()

	// A read and a write that start together run one handshake.
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("ping"))
		wrote <- err
	}()
	got := make([]byte, 6)
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "banner", string(got))
	require.NoError(t, <-wrote)
	require.Equal(t, [][]byte{[]byte("hello"), []byte("ping")}, rec.writes)
}

func TestTCPHandshakeFails(t *testing.T) {
	settings := obj{
		"clients": []any{[]any{obj{"rand": 2, "capture": "id"}}},
		"servers": []any{[]any{obj{"packet": "ok", "type": "str"}, obj{"reuse": "id"}}},
	}

	t.Run("wrong bytes", func(t *testing.T) {
		conn, _, server := pipe(t, settings)
		go func() {
			id := make([]byte, 2)
			_, _ = io.ReadFull(server, id)
			id[1]++
			_, _ = server.Write(append([]byte("ok"), id...))
		}()
		_, err := conn.Write([]byte("ping"))
		require.ErrorContains(t, err, "handshake failed at servers[0]: item 1")
		// Every later call gets the same error and nothing reaches the server.
		_, err2 := conn.Read(make([]byte, 1))
		require.Equal(t, err, err2)
		_, err2 = conn.Write([]byte("ping"))
		require.Equal(t, err, err2)
		require.False(t, conn.ReaderReplaceable())
		require.False(t, conn.WriterReplaceable())
	})

	t.Run("connection closed", func(t *testing.T) {
		conn, _, server := pipe(t, settings)
		go func() {
			_, _ = io.ReadFull(server, make([]byte, 2))
			_, _ = server.Write([]byte("o"))
			_ = server.Close()
		}()
		_, err := conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("no addresses for the metadata", func(t *testing.T) {
		conn, rec, _ := pipe(t, obj{"clients": []any{[]any{obj{"packet": []any{1}}, tr("be16", meta("remote_port"))}}})
		_, err := conn.Write([]byte("ping"))
		require.ErrorContains(t, err, "metadata remote_port needs the remote TCP or UDP address")
		require.Empty(t, rec.writes)
	})
}

// The metadata of a real connection: each side sees its own end as local.
func TestTCPMetadata(t *testing.T) {
	m, err := NewTCP(obj{
		"clients": []any{[]any{tr("be16", meta("remote_port")), tr("be32", meta("dst_ip4_u32"))}},
		"servers": []any{[]any{tr("be16", meta("local_port")), tr("be32", meta("src_ip4_u32"))}},
	})
	require.NoError(t, err)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	raw, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	server, err := l.Accept()
	require.NoError(t, err)
	defer server.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))

	conn, err := m.WrapConn(raw)
	require.NoError(t, err)
	go func() {
		// The server answers with the client's port as it sees it.
		got := make([]byte, 6)
		_, _ = io.ReadFull(server, got)
		answer := binary.BigEndian.AppendUint16(nil, uint16(server.RemoteAddr().(*net.TCPAddr).Port))
		_, _ = server.Write(append(append(answer, 127, 0, 0, 1), got...))
	}()
	echoed := make([]byte, 6)
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.Equal(t, []byte{byte(port >> 8), byte(port), 127, 0, 0, 1}, echoed)
}

// Close ends a pause of the handshake and whoever waits for it.
func TestTCPCloseEndsADelay(t *testing.T) {
	conn, _, server := pipe(t, obj{"clients": []any{[]any{
		obj{"packet": "a", "type": "str"},
		obj{"delay": 60000, "packet": "b", "type": "str"},
	}}})
	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("ping"))
		wrote <- err
	}()
	_, err := io.ReadFull(server, make([]byte, 1)) // the handshake is in its pause now
	require.NoError(t, err)

	start := time.Now()
	require.NoError(t, conn.Close())
	require.ErrorIs(t, <-wrote, net.ErrClosed)
	select {
	case <-conn.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handshake outlives Close")
	}
	require.Less(t, time.Since(start), 5*time.Second)
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.False(t, conn.ReaderReplaceable())
}

// A deadline bounds what its caller waits for, the answer of the server
// included, and leaves the handshake to the callers that can wait longer.
func TestTCPDeadlines(t *testing.T) {
	settings := obj{
		"clients": []any{[]any{obj{"packet": "hello", "type": "str"}}},
		"servers": []any{[]any{obj{"packet": "welcome", "type": "str"}}},
	}
	timedOut := func(err error) {
		t.Helper()
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		require.True(t, netErr.Timeout())
	}

	t.Run("write", func(t *testing.T) {
		conn, _, server := pipe(t, settings)
		// Only the write deadline is set, and it is the read of the answer
		// that the handshake hangs on.
		require.NoError(t, conn.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
		read := make(chan error, 1)
		go func() {
			got := make([]byte, 4)
			_, err := io.ReadFull(conn, got)
			if err == nil && string(got) != "pong" {
				err = io.ErrUnexpectedEOF
			}
			read <- err
		}()
		start := time.Now()
		_, err := conn.Write([]byte("ping"))
		timedOut(err)
		require.Less(t, time.Since(start), 2*time.Second)
		_, err = conn.Write([]byte("ping"))
		timedOut(err)

		// The handshake goes on for the reader, and for a write that has time.
		hello := make([]byte, 5)
		_, err = io.ReadFull(server, hello)
		require.NoError(t, err)
		require.Equal(t, "hello", string(hello))
		go func() { _, _ = server.Write([]byte("welcomepong")) }()
		require.NoError(t, <-read)
		require.NoError(t, conn.SetWriteDeadline(time.Time{}))
		go func() { _, _ = io.ReadFull(server, make([]byte, 4)) }()
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		require.True(t, conn.WriterReplaceable())
	})

	t.Run("read", func(t *testing.T) {
		conn, _, server := pipe(t, settings)
		go func() { _, _ = io.ReadFull(server, make([]byte, 5)) }()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
		_, err := conn.Read(make([]byte, 1))
		timedOut(err)
		// A deadline in the past fails at once, a later one gives time again.
		require.NoError(t, conn.SetDeadline(time.Now().Add(-time.Second)))
		_, err = conn.Write([]byte("ping"))
		timedOut(err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		go func() { _, _ = server.Write([]byte("welcomepong")) }()
		got := make([]byte, 4)
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err)
		require.Equal(t, "pong", string(got))
	})

	// The deadlines set before and during the handshake are those of the
	// connection once it is over.
	t.Run("kept", func(t *testing.T) {
		conn, _, server := pipe(t, settings)
		go func() { _, _ = serve(server, conn.mask) }()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		start := time.Now()
		_, err := conn.Read(make([]byte, 1)) // the handshake is done at once, then nothing comes
		timedOut(err)
		require.True(t, conn.ReaderReplaceable(), "it is the connection that timed out")
		require.GreaterOrEqual(t, time.Since(start), 90*time.Millisecond)
		// From now on the connection gets them directly.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		go func() { _, _ = server.Write([]byte("x")) }()
		_, err = conn.Read(make([]byte, 1))
		require.NoError(t, err)
	})
}
