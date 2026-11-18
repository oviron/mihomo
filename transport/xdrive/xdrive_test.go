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

	_, _ = server.Write([]byte("answer"))
	require.NoError(t, server.Close())

	left, err := os.ReadDir(filepath.Join(folder, streamsDir, id, uplinkDir))
	require.NoError(t, err)
	// the reader deletes segments in the background
	for i := 0; i < 100 && len(left) > 0; i++ {
		time.Sleep(10 * time.Millisecond)
		left, _ = os.ReadDir(filepath.Join(folder, streamsDir, id, uplinkDir))
	}
	assert.Empty(t, left)
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
