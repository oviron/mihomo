package fragment

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recorder keeps every Write it gets.
type recorder struct {
	net.Conn
	writes [][]byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func tlsRecord(typ byte, payload []byte) []byte {
	return append([]byte{typ, 3, 1, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func wrap(t *testing.T, settings map[string]any) (*Conn, *recorder) {
	t.Helper()
	m, err := New(settings)
	require.NoError(t, err)
	rec := &recorder{}
	conn, err := m.WrapConn(rec)
	require.NoError(t, err)
	return conn.(*Conn), rec
}

// records splits a byte stream into TLS records and returns their payloads.
func records(t *testing.T, stream []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 5)
		l := int(stream[3])<<8 | int(stream[4])
		require.GreaterOrEqual(t, len(stream), 5+l)
		require.Equal(t, []byte{22, 3, 1}, stream[:3])
		out = append(out, stream[5:5+l])
		stream = stream[5+l:]
	}
	return out
}

func TestTLSHelloIsSplitIntoRecords(t *testing.T) {
	hello := bytes.Repeat([]byte("0123456789"), 52) // 520 bytes
	tail := []byte("after the hello")

	t.Run("one write per record", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"packets": "tlshello", "length": "50-60", "delay": "1-2"})
		require.False(t, conn.WriterReplaceable())
		n, err := conn.Write(append(tlsRecord(22, hello), tail...))
		require.NoError(t, err)
		require.Equal(t, 5+len(hello)+len(tail), n)

		require.Equal(t, tail, rec.writes[len(rec.writes)-1])
		var payload []byte
		for _, w := range rec.writes[:len(rec.writes)-1] {
			parts := records(t, w)
			require.Len(t, parts, 1, "each write carries one record")
			payload = append(payload, parts[0]...)
		}
		require.Equal(t, hello, payload)
		// 520 bytes in pieces of 50..59 bytes
		require.GreaterOrEqual(t, len(rec.writes)-1, 9)
		require.LessOrEqual(t, len(rec.writes)-1, 11)
		require.True(t, conn.WriterReplaceable())

		// Later writes pass untouched.
		_, err = conn.Write(tlsRecord(22, hello))
		require.NoError(t, err)
		require.Equal(t, tlsRecord(22, hello), rec.writes[len(rec.writes)-1])
	})

	t.Run("no delay merges the records into one write", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"packets": "tlshello", "length": "100-101"})
		_, err := conn.Write(tlsRecord(22, hello))
		require.NoError(t, err)
		require.Len(t, rec.writes, 1)
		parts := records(t, rec.writes[0])
		require.Len(t, parts, 6) // 5 x 100 + 20
		require.Equal(t, hello, bytes.Join(parts, nil))
	})

	t.Run("max-split and per piece lengths", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"packets": "tlshello", "lengths": []any{10, 20, "30-31"}, "maxSplit": 4})
		_, err := conn.Write(tlsRecord(22, hello))
		require.NoError(t, err)
		parts := records(t, rec.writes[0])
		require.Len(t, parts, 4)
		require.Len(t, parts[0], 10)
		require.Len(t, parts[1], 20)
		require.Len(t, parts[2], 30)
		require.Len(t, parts[3], 460)
	})

	t.Run("not a handshake record", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"packets": "tlshello", "length": "10-20"})
		data := tlsRecord(23, hello)
		_, err := conn.Write(data)
		require.NoError(t, err)
		require.Equal(t, [][]byte{data}, rec.writes)
	})
}

func TestWritesAreSplit(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefghij"), 10)

	t.Run("chosen writes", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"packets": "2-3", "length": "30-31"})
		for i := 0; i < 4; i++ {
			n, err := conn.Write(data)
			require.NoError(t, err)
			require.Equal(t, len(data), n)
		}
		// write 1 whole, writes 2 and 3 in pieces of 30+30+30+10, write 4 whole
		require.Len(t, rec.writes, 1+4+4+1)
		require.Equal(t, data, rec.writes[0])
		require.Equal(t, data, bytes.Join(rec.writes[1:5], nil))
		require.Len(t, rec.writes[1], 30)
		require.Equal(t, data, rec.writes[9])
		require.True(t, conn.WriterReplaceable())
	})

	t.Run("every write, with a delay", func(t *testing.T) {
		conn, rec := wrap(t, map[string]any{"length": "50-51", "delay": "5-6"})
		start := time.Now()
		_, err := conn.Write(data)
		require.NoError(t, err)
		require.Len(t, rec.writes, 2)
		require.GreaterOrEqual(t, time.Since(start), 10*time.Millisecond)
		require.False(t, conn.WriterReplaceable())
	})
}

func TestSettings(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"no length":        {"packets": "tlshello"},
		"packets from 0":   {"packets": "0-3", "length": 5},
		"bad packets":      {"packets": "first", "length": 5},
		"last length is 0": {"lengths": []any{5, 0}},
	} {
		_, err := New(settings)
		require.Error(t, err, name)
	}
}
