package masque

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/metacubex/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capsule(kind uint64, payload []byte) []byte {
	b := quicvarint.Append(nil, kind)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func newTestCapsuleStream(response io.ReadCloser) (*h2CapsuleStream, *io.PipeReader) {
	requestReader, requestWriter := io.Pipe()
	s := &h2CapsuleStream{
		requestBody:  requestWriter,
		responseBody: response,
		cancel:       func() {},
		datagrams:    make(chan []byte, h2DatagramQueue),
		done:         make(chan struct{}),
	}
	s.control, s.controlWriter = io.Pipe()
	go s.run()
	return s, requestReader
}

// The response body mixes IP packets with control capsules; the stream hands
// the packets out as datagrams and the rest, untouched, as a byte stream.
func TestH2CapsuleStreamSplit(t *testing.T) {
	assign := capsule(1, []byte{0, 4, 10, 9, 0, 2, 32})
	routes := capsule(3, bytes.Repeat([]byte{7}, 300))
	var body bytes.Buffer
	body.Write(capsule(0, []byte{0, 0x45, 1}))
	body.Write(assign)
	body.Write(capsule(0, []byte{0, 0x45, 2}))
	body.Write(routes)
	body.Write(capsule(0, []byte{0, 0x45, 3}))
	s, _ := newTestCapsuleStream(io.NopCloser(&body))

	control := make([]byte, len(assign)+len(routes))
	_, err := io.ReadFull(s, control)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte(nil), assign...), routes...), control)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := byte(1); i <= 3; i++ {
		datagram, err := s.ReceiveDatagram(ctx)
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 0x45, i}, datagram)
	}
	// the body ended: both sides see it
	_, err = s.ReceiveDatagram(ctx)
	assert.ErrorIs(t, err, io.EOF)
	_, err = s.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestH2CapsuleStreamSend(t *testing.T) {
	response, _ := io.Pipe() // nothing arrives
	s, request := newTestCapsuleStream(response)
	go func() {
		_ = s.SendDatagram([]byte{0, 0x45, 9})
		_, _ = s.Write(capsule(2, []byte{1}))
		_ = s.Close()
	}()
	sent, err := io.ReadAll(request)
	require.NoError(t, err)
	assert.Equal(t, append(capsule(0, []byte{0, 0x45, 9}), capsule(2, []byte{1})...), sent)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = s.ReceiveDatagram(ctx)
	assert.ErrorIs(t, err, io.ErrClosedPipe)
}

// A capsule too long to be a packet, or to be the addresses and routes of the
// server, is skipped; an unknown capsule of a sane length is passed on, and
// none of them ends the tunnel.
func TestH2CapsuleStreamOversize(t *testing.T) {
	var body bytes.Buffer
	body.Write(capsule(0, make([]byte, maxH2Datagram+1)))
	body.Write(capsule(1, make([]byte, maxH2Control+1)))
	unknown := capsule(0x1234, make([]byte, 2000))
	body.Write(unknown)
	body.Write(capsule(0, []byte{0, 0x45, 7}))
	s, _ := newTestCapsuleStream(io.NopCloser(&body))
	control := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(s)
		control <- b
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	datagram, err := s.ReceiveDatagram(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 0x45, 7}, datagram)
	select {
	case b := <-control:
		assert.Equal(t, unknown, b)
	case <-time.After(time.Second):
		t.Fatal("the control capsules did not end with the body")
	}
}

// Packets that nobody reads are dropped; the control capsule behind them
// still arrives.
func TestH2CapsuleStreamFullQueue(t *testing.T) {
	var body bytes.Buffer
	for i := 0; i < 2*h2DatagramQueue; i++ {
		body.Write(capsule(0, []byte{0, 0x45}))
	}
	assign := capsule(1, []byte{0, 4, 10, 9, 0, 2, 32})
	body.Write(assign)
	s, _ := newTestCapsuleStream(io.NopCloser(&body))
	control := make([]byte, len(assign))
	_, err := io.ReadFull(s, control)
	require.NoError(t, err)
	assert.Equal(t, assign, control)
	assert.Equal(t, h2DatagramQueue, len(s.datagrams))
}
