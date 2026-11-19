package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A session of the client against the other end of the same storage: what one
// side writes the other reads, in order, and nothing is left behind.
func TestSessionOverLocalStorage(t *testing.T) {
	folder := t.TempDir()
	client, err := NewClient(Config{Service: "local", RemoteFolder: folder, SegmentBytes: 4096, PollIntervalMs: 5})
	require.NoError(t, err)
	conn, err := client.Dial(context.Background())
	require.NoError(t, err)

	announced, err := os.ReadDir(filepath.Join(folder, sessionsDir))
	require.NoError(t, err)
	require.Len(t, announced, 1)
	_, id, ok := cutLast(announced[0].Name(), '-')
	require.True(t, ok)
	require.Len(t, id, 32)

	// the server side of the session: the prefixes the other way round
	storage, err := newLocalStorage(folder)
	require.NoError(t, err)
	server := newConn(context.Background(), storage, streamsDir+"/"+id+"/"+downlinkDir, streamsDir+"/"+id+"/"+uplinkDir, client.params)

	data := make([]byte, 100_000)
	_, _ = rand.Read(data)
	go func() {
		_, _ = conn.Write(data)
		_ = conn.Close()
	}()
	got, err := io.ReadAll(server)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, got))

	// the reader deletes what it has read, in the background, while the
	// session is open
	uplink := filepath.Join(folder, streamsDir, id, uplinkDir)
	left, err := os.ReadDir(uplink)
	require.NoError(t, err)
	for i := 0; i < 300 && len(left) > 0; i++ {
		time.Sleep(10 * time.Millisecond)
		left, _ = os.ReadDir(uplink)
	}
	assert.Empty(t, left)

	_, err = server.Write([]byte("answer"))
	require.NoError(t, err)
	require.NoError(t, server.Close())
}

func cutLast(s string, sep byte) (string, string, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func TestReadDeadline(t *testing.T) {
	client, err := NewClient(Config{Service: "local", RemoteFolder: t.TempDir()})
	require.NoError(t, err)
	conn, err := client.Dial(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestServices(t *testing.T) {
	_, err := NewClient(Config{Service: "google-drive"})
	require.ErrorContains(t, err, "not supported")
	_, err = NewClient(Config{Service: "ftp"})
	require.ErrorContains(t, err, "unknown service")
	_, err = NewClient(Config{Service: "s3", RemoteFolder: "x", Secrets: []string{"a", "b"}})
	require.Error(t, err) // no s3 block
	_, err = NewClient(Config{Service: "template", Template: `{"put":{"url":"http://x/{name}"}}`, HTTPClient: nil})
	require.Error(t, err)
}

// slowStorage stores nothing until released.
type slowStorage struct {
	Storage
	release chan struct{}
}

func (s *slowStorage) Put(ctx context.Context, name string, data []byte) error {
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A writer faster than the storage is held back, and the end of the session
// lets it go.
func TestWriterIsHeldBack(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	require.NoError(t, err)
	slow := &slowStorage{Storage: storage, release: make(chan struct{})}
	p := paramsFromConfig(&Config{SegmentBytes: 1024, Concurrency: 2})
	ctx, cancel := context.WithCancel(context.Background())
	w := newWALWriter(ctx, slow, "streams/x/c2s", p)

	wrote := make(chan int, 1)
	go func() {
		n := 0
		for {
			if _, err := w.Write(make([]byte, 1024)); err != nil {
				wrote <- n
				return
			}
			n++
		}
	}()
	time.Sleep(200 * time.Millisecond)
	w.mu.Lock()
	pending := w.pending
	w.mu.Unlock()
	assert.Equal(t, maxPendingSegments*p.concurrency, pending)

	cancel()
	select {
	case n := <-wrote:
		assert.LessOrEqual(t, n, maxPendingSegments*p.concurrency+1)
	case <-time.After(3 * time.Second):
		t.Fatal("the writer was not let go")
	}
}

// Close of the client ends its sessions.
func TestClientCloseEndsSessions(t *testing.T) {
	client, err := NewClient(Config{Service: "local", RemoteFolder: t.TempDir()})
	require.NoError(t, err)
	conn, err := client.Dial(context.Background())
	require.NoError(t, err)
	read := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		read <- err
	}()
	require.NoError(t, client.Close())
	select {
	case err := <-read:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Read did not end with the client")
	}
}
