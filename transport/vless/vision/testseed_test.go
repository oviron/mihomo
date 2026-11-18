package vision

import (
	"encoding/binary"
	"testing"

	"github.com/metacubex/mihomo/common/buf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestseed(t *testing.T) {
	seed, err := NewTestseed([]uint32{901, 501, 902, 257, 1})
	require.NoError(t, err)
	assert.Equal(t, Testseed{901, 501, 902, 257}, *seed)
	assert.Equal(t, 1403, seed.maxPadding())

	// like Xray-core: fewer than four values are its defaults, large ones are capped
	seed, err = NewTestseed([]uint32{1})
	require.NoError(t, err)
	assert.Equal(t, DefaultTestseed, *seed)
	seed, err = NewTestseed([]uint32{1 << 31, 9000, 1 << 31, 9000})
	require.NoError(t, err)
	assert.Equal(t, Testseed{xrayBufSize, xrayBufSize, xrayBufSize, xrayBufSize}, *seed)
	assert.Equal(t, xrayBufSize-PaddingHeaderLen, seed.maxPadding())
	assert.Equal(t, int32(xrayBufSize-PaddingHeaderLen-100), seed.paddingLen(100, true))

	for _, values := range [][]uint32{{900, 0, 900, 256}, {900, 500, 900, 0}} {
		_, err = NewTestseed(values)
		assert.Error(t, err, "%v", values)
	}
}

func TestTestseedPaddingLen(t *testing.T) {
	seed := DefaultTestseed
	sawShort, sawLong := map[int32]bool{}, map[int32]bool{}
	for i := 0; i < 5000; i++ {
		// a short handshake block is padded to 900..1399 bytes
		n := seed.paddingLen(100, true)
		assert.GreaterOrEqual(t, n, int32(800))
		assert.Less(t, n, int32(1300))
		sawLong[n] = true
		// anything else gets 0..255 bytes, long blocks included
		for _, contentLen := range []int32{100, 899, 900, 1455, 4096} {
			n = seed.paddingLen(contentLen, contentLen >= 900)
			assert.GreaterOrEqual(t, n, int32(0))
			assert.Less(t, n, int32(256))
		}
		sawShort[seed.paddingLen(1455, true)] = true
	}
	assert.Greater(t, len(sawLong), 400)
	assert.Greater(t, len(sawShort), 200)

	// never past Xray-core's buffer
	assert.Equal(t, int32(0), seed.paddingLen(xrayBufSize-PaddingHeaderLen, true))
	for i := 0; i < 1000; i++ {
		assert.LessOrEqual(t, seed.paddingLen(xrayBufSize-PaddingHeaderLen-10, true), int32(10))
	}
	// a seed whose long padding is shorter than the content does not go negative
	odd := Testseed{900, 1, 100, 1}
	assert.Equal(t, int32(0), odd.paddingLen(800, true))
}

func record(payloadLen int) []byte {
	b := make([]byte, 5+payloadLen)
	copy(b, tlsApplicationDataStart)
	binary.BigEndian.PutUint16(b[3:], uint16(payloadLen))
	return b
}

func TestIsCompleteRecords(t *testing.T) {
	one := record(32)
	assert.True(t, isCompleteRecords(one))
	assert.True(t, isCompleteRecords(append(record(1), record(300)...)))
	assert.False(t, isCompleteRecords(nil))
	assert.False(t, isCompleteRecords(one[:13]))                                // cut inside the record
	assert.False(t, isCompleteRecords(one[:4]))                                 // cut inside the header
	assert.False(t, isCompleteRecords(one[13:]))                                // the rest of a record
	assert.False(t, isCompleteRecords(append(record(32), one[:13]...)))         // whole record and a cut one
	assert.False(t, isCompleteRecords(append(record(32), 0x16, 3, 3, 0, 1, 0))) // another record type
	assert.False(t, isCompleteRecords(record(0)))
}

type blockWriter struct {
	blocks [][]byte
}

func (w *blockWriter) Write(p []byte) (int, error) {
	w.blocks = append(w.blocks, append([]byte(nil), p...))
	return len(p), nil
}

func (w *blockWriter) WriteBuffer(buffer *buf.Buffer) error {
	_, _ = w.Write(buffer.Bytes())
	buffer.Release()
	return nil
}

// block parses a padded block that does not start with the UUID.
func block(t *testing.T, b []byte) (command byte, content []byte) {
	t.Helper()
	require.GreaterOrEqual(t, len(b), 5)
	contentLen := int(binary.BigEndian.Uint16(b[1:]))
	paddingLen := int(binary.BigEndian.Uint16(b[3:]))
	require.Equal(t, 5+contentLen+paddingLen, len(b))
	return b[0], b[5 : 5+contentLen]
}

func TestWriteBufferWithTestseed(t *testing.T) {
	padded, direct := &blockWriter{}, &blockWriter{}
	vc := &Conn{
		ExtendedWriter:             padded,
		isTLS:                      true,
		isTLS12orAbove:             true,
		enableXTLS:                 true,
		writeFilterApplicationData: true,
		testseed:                   &DefaultTestseed,
	}
	write := func(data []byte) {
		buffer := buf.NewSize(PaddingHeaderLen + len(data) + vc.RearHeadroom())
		buffer.Resize(PaddingHeaderLen, 0)
		_, err := buffer.Write(data)
		require.NoError(t, err)
		// the writer is swapped by hand: the test has no real connection to switch to
		before := vc.writeDirect
		require.NoError(t, vc.writeBufferWithTestseed(buffer))
		if vc.writeDirect && !before {
			vc.ExtendedWriter = direct
		}
	}

	finished := record(53)
	write(finished[:13]) // a record cut in two must not end the padding phase
	write(finished[13:])
	require.Len(t, padded.blocks, 2)
	for i, want := range [][]byte{finished[:13], finished[13:]} {
		command, content := block(t, padded.blocks[i])
		assert.Equal(t, commandPaddingContinue, command)
		assert.Equal(t, want, content)
		assert.GreaterOrEqual(t, len(padded.blocks[i]), 900, "handshake blocks get the long padding")
	}
	assert.True(t, vc.writeFilterApplicationData)
	assert.False(t, vc.writeDirect)

	data := record(21)
	write(data) // a whole record does
	require.Len(t, padded.blocks, 3)
	command, content := block(t, padded.blocks[2])
	assert.Equal(t, commandPaddingDirect, command)
	assert.Equal(t, data, content)
	assert.False(t, vc.writeFilterApplicationData)
	assert.True(t, vc.writeDirect)
}

// A buffer longer than a block is cut in pieces; the direct copy command
// belongs to the last one and the padding must be zeroed.
func TestWriteBufferWithTestseedReshape(t *testing.T) {
	padded := &blockWriter{}
	vc := &Conn{
		ExtendedWriter:             padded,
		isTLS:                      true,
		isTLS12orAbove:             true,
		enableXTLS:                 true,
		writeFilterApplicationData: true,
		testseed:                   &Testseed{xrayBufSize, xrayBufSize, xrayBufSize, xrayBufSize},
	}
	data := append(record(16), record(xrayBufSize-PaddingHeaderLen-5)...)
	for i := range data[5:21] {
		data[5+i] = 0xff
	}
	buffer := buf.NewSize(PaddingHeaderLen + len(data) + vc.RearHeadroom())
	buffer.Resize(PaddingHeaderLen, 0)
	for i := range buffer.FreeBytes() {
		buffer.FreeBytes()[i] = 0xee // stale pool data
	}
	_, err := buffer.Write(data)
	require.NoError(t, err)
	require.NoError(t, vc.writeBufferWithTestseed(buffer))

	require.Greater(t, len(padded.blocks), 1)
	var got []byte
	for i, b := range padded.blocks {
		command, content := block(t, b)
		if i == len(padded.blocks)-1 {
			assert.Equal(t, commandPaddingDirect, command)
		} else {
			assert.Equal(t, commandPaddingContinue, command)
		}
		assert.LessOrEqual(t, len(b), xrayBufSize)
		for _, p := range b[5+len(content):] {
			require.Zero(t, p, "padding must be zeroed")
		}
		got = append(got, content...)
	}
	assert.Equal(t, data, got)
	assert.True(t, vc.writeDirect)
}
