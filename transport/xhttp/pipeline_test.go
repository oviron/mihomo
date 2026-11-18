package xhttp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pipelineTestServer stands for the server side of packet-up: it reports the
// request as written, answers after a delay and keeps what it was sent.
type pipelineTestServer struct {
	protoMajor int
	delay      time.Duration
	fail       func(seq string) bool

	mu       sync.Mutex
	packets  map[string][]byte
	order    []string
	inFlight int
	maxSeen  int
}

func (s *pipelineTestServer) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	seq := req.URL.Path[strings.LastIndexByte(req.URL.Path, '/')+1:]
	s.mu.Lock()
	if s.packets == nil {
		s.packets = map[string][]byte{}
	}
	s.packets[seq] = body
	s.order = append(s.order, seq)
	s.inFlight++
	if s.inFlight > s.maxSeen {
		s.maxSeen = s.inFlight
	}
	s.mu.Unlock()
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	}
	time.Sleep(s.delay)
	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()
	status := http.StatusOK
	if s.fail != nil && s.fail(seq) {
		status = http.StatusInternalServerError
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), ProtoMajor: s.protoMajor, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (s *pipelineTestServer) received(t *testing.T) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []byte
	for i := 0; i < len(s.packets); i++ {
		packet, ok := s.packets[itoa(i)]
		require.True(t, ok, "packet %d is missing", i)
		all = append(all, packet...)
	}
	return all
}

func itoa(i int) string {
	return string(appendInt(nil, i))
}

func appendInt(b []byte, i int) []byte {
	if i >= 10 {
		b = appendInt(b, i/10)
	}
	return append(b, byte('0'+i%10))
}

func newTestPipelinedWriter(server *pipelineTestServer, maxSize int) *pipelinedWriter {
	ctx, cancel := context.WithCancel(context.Background())
	return newPipelinedWriter(&PacketUpWriter{
		ctx:                  ctx,
		cancel:               cancel,
		cfg:                  &Config{Host: "example.org", Path: "/x"},
		scMaxEachPostBytes:   maxSize,
		scMinPostsIntervalMs: Range{1, 1},
		sessionID:            "session",
		transport:            server,
	})
}

func pipelineTestData(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i * 7)
	}
	return data
}

// Over HTTP/2 the POSTs overlap, stay bounded, and carry the data in order.
func TestPipelinedWriterMultiplexed(t *testing.T) {
	server := &pipelineTestServer{protoMajor: 2, delay: 50 * time.Millisecond}
	writer := newTestPipelinedWriter(server, 100)
	data := pipelineTestData(100 * 60)

	start := time.Now()
	for i := 0; i < len(data); i += 250 { // writes do not line up with packets
		n, err := writer.Write(data[i : i+250])
		require.NoError(t, err)
		require.Equal(t, 250, n)
	}
	require.NoError(t, writer.Close())
	elapsed := time.Since(start)

	assert.True(t, bytes.Equal(data, server.received(t)))
	assert.Greater(t, server.maxSeen, 1, "the POSTs did not overlap")
	assert.LessOrEqual(t, server.maxSeen, pipelineMaxInFlight)
	// one at a time, sixty packets of 50 ms would take three seconds
	assert.Less(t, elapsed, 1500*time.Millisecond)
	for i, seq := range server.order {
		assert.Equal(t, itoa(i), seq, "requests are written in order")
	}
}

// Over HTTP/1.1 every POST waits for the response to the one before.
func TestPipelinedWriterHTTP1(t *testing.T) {
	server := &pipelineTestServer{protoMajor: 1, delay: 5 * time.Millisecond}
	writer := newTestPipelinedWriter(server, 100)
	data := pipelineTestData(100 * 20)
	_, err := writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	assert.True(t, bytes.Equal(data, server.received(t)))
	assert.Equal(t, 1, server.maxSeen)
}

// What is written while a POST is under way goes into one next packet.
func TestPipelinedWriterBatches(t *testing.T) {
	server := &pipelineTestServer{protoMajor: 1, delay: 100 * time.Millisecond}
	writer := newTestPipelinedWriter(server, 1000)
	_, err := writer.Write([]byte("first"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond) // the first POST is out
	for i := 0; i < 10; i++ {
		_, err = writer.Write([]byte("more"))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())

	server.mu.Lock()
	defer server.mu.Unlock()
	assert.Equal(t, "first", string(server.packets["0"]))
	assert.Equal(t, strings.Repeat("more", 10), string(server.packets["1"]))
	assert.Len(t, server.packets, 2)
}

// A refused POST ends the stream: the following writes fail.
func TestPipelinedWriterError(t *testing.T) {
	server := &pipelineTestServer{protoMajor: 2, fail: func(seq string) bool { return seq == "1" }}
	writer := newTestPipelinedWriter(server, 10)
	defer writer.Close()
	var err error
	for i := 0; i < 1000 && err == nil; i++ {
		_, err = writer.Write(pipelineTestData(10))
		time.Sleep(time.Millisecond)
	}
	require.ErrorContains(t, err, "bad status")
	_, err = writer.Write([]byte("x"))
	require.Error(t, err)
}

// Close wakes a writer that waits for room and fails it.
func TestPipelinedWriterClose(t *testing.T) {
	server := &pipelineTestServer{protoMajor: 1, delay: 300 * time.Millisecond}
	writer := newTestPipelinedWriter(server, 10)
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(pipelineTestData(1000))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, writer.Close())
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Write did not return after Close")
	}
}
