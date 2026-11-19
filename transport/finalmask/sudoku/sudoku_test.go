package sudoku

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/fragment"
	"github.com/metacubex/mihomo/transport/finalmask/mask"
	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"

	"github.com/metacubex/randv2"
	"github.com/stretchr/testify/require"
)

// cases are the table sets the codec tests run with; ref names the layouts
// for the reference ("" entropy, "ascii" or a custom pattern).
var cases = []struct {
	name     string
	settings map[string]any
	ref      []string
}{
	{"entropy", map[string]any{"password": "secret"}, []string{""}},
	{"ascii", map[string]any{"password": "secret", "ascii": "prefer_ascii"}, []string{"ascii"}},
	{"custom", map[string]any{"password": "secret", "custom-table": "xpxvvpvv"}, []string{"xpxvvpvv"}},
	{"two tables", map[string]any{"password": "other", "custom-tables": []any{"xpxvvpvv", "vxpvxvvp"}}, []string{"xpxvvpvv", "vxpvxvvp"}},
	{"three tables, no password", map[string]any{"custom-tables": []any{"pxvvxvvp", "", "vvxpxpvv"}}, []string{"pxvvxvvp", "", "vvxpxpvv"}},
}

func newMask(t *testing.T, settings map[string]any, extra ...any) *Mask {
	t.Helper()
	merged := map[string]any{}
	for key, value := range settings {
		merged[key] = value
	}
	for i := 0; i < len(extra); i += 2 {
		merged[extra[i].(string)] = extra[i+1]
	}
	m, err := New(merged)
	require.NoError(t, err)
	return m
}

func password(settings map[string]any) string {
	s, _ := settings["password"].(string)
	return s
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	rand.New(rand.NewSource(int64(n))).Read(data)
	return data
}

func testRand(t *testing.T) *randv2.Rand {
	t.Helper()
	rng, err := newRand()
	require.NoError(t, err)
	return rng
}

// fakeConn serves reads from a list of chunks and keeps the writes.
type fakeConn struct {
	net.Conn
	in          [][]byte
	inErr       error // returned once, together with the last chunk
	out         [][]byte
	outErr      error // returned once, by the write after outErrAfter good ones
	outErrAfter int
	closed      bool
	closedWrite bool
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if len(f.in) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.in[0])
	if f.in[0] = f.in[0][n:]; len(f.in[0]) == 0 {
		f.in = f.in[1:]
	}
	if len(f.in) == 0 && f.inErr != nil {
		err := f.inErr
		f.inErr = nil
		return n, err
	}
	return n, nil
}

func (f *fakeConn) Write(p []byte) (int, error) {
	if f.outErr != nil && len(f.out) == f.outErrAfter {
		err := f.outErr
		f.outErr = nil
		return 0, err
	}
	f.out = append(f.out, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeConn) Close() error      { f.closed = true; return nil }
func (f *fakeConn) CloseWrite() error { f.closedWrite = true; return nil }

// fakePacketConn keeps the datagrams it is given and returns those of in,
// cut to the buffer of the reader as a socket does.
type fakePacketConn struct {
	net.PacketConn
	in  [][]byte
	out [][]byte
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(f.in) == 0 {
		return 0, nil, io.EOF
	}
	n := copy(p, f.in[0])
	f.in = f.in[1:]
	return n, nil, nil
}

func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.out = append(f.out, append([]byte(nil), p...))
	return len(p), nil
}

// chunks cuts data into pieces of the given sizes, repeating them.
func chunks(data []byte, sizes ...int) [][]byte {
	var out [][]byte
	for i := 0; len(data) > 0; i++ {
		n := sizes[i%len(sizes)]
		if n > len(data) {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

// tableOf builds the table of a password and a layout: "ascii", "" for
// entropy or a custom pattern.
func tableOf(t *testing.T, password, layout string) *obfs.Table {
	t.Helper()
	mode := "prefer_entropy"
	if layout == "ascii" {
		mode, layout = "prefer_ascii", ""
	}
	table, err := obfs.NewTableWithCustom(password, mode, layout)
	require.NoError(t, err)
	return table
}

func TestFinalmaskSudokuSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		m := newMask(t, nil)
		require.Equal(t, []*obfs.Table{tableOf(t, "", "")}, m.tables)
		require.Equal(t, 0, m.padMin)
		require.Equal(t, 0, m.padMax)
	})

	t.Run("ascii modes", func(t *testing.T) {
		for _, mode := range []string{"", "entropy", "prefer_entropy", " Prefer_Entropy "} {
			require.Equal(t, byte(0x80), newMask(t, nil, "ascii", mode).tables[0].PadMarker(), mode)
		}
		for _, mode := range []string{"ascii", "prefer_ascii", "ASCII"} {
			require.Equal(t, byte(0x3f), newMask(t, nil, "ascii", mode).tables[0].PadMarker(), mode)
		}
		// the tables are not looked at in ASCII mode
		m := newMask(t, nil, "password", "secret", "ascii", "ascii", "custom-tables", []any{"xpxvvpvv", "not a table"})
		require.Equal(t, []*obfs.Table{tableOf(t, "secret", "ascii")}, m.tables)
	})

	t.Run("tables", func(t *testing.T) {
		custom := tableOf(t, "secret", "xpxvvpvv")
		require.Equal(t, []*obfs.Table{custom}, newMask(t, nil, "password", "secret", "custom-table", " XP XV VP VV ").tables)
		// the list wins over the single table, which is then not even checked
		m := newMask(t, nil, "password", "secret", "custom-table", "broken", "custom-tables", []any{"vxpvxvvp", "xpxvvpvv"})
		require.Equal(t, []*obfs.Table{tableOf(t, "secret", "vxpvxvvp"), custom}, m.tables)
		// duplicates go, the order stays, an empty entry is the entropy layout
		m = newMask(t, nil, "password", "secret", "custom-tables", []string{"xpxvvpvv", "XPXVVPVV", " ", "vxpvxvvp", ""})
		require.Equal(t, []*obfs.Table{custom, tableOf(t, "secret", ""), tableOf(t, "secret", "vxpvxvvp")}, m.tables)
	})

	t.Run("padding", func(t *testing.T) {
		m := newMask(t, nil, "padding-min", 20, "padding-max", 60)
		require.Equal(t, []int{20, 60}, []int{m.padMin, m.padMax})
		for i := 0; i < 200; i++ {
			chance := m.paddingChance(testRand(t))
			require.True(t, chance >= 20 && chance <= 60)
		}
		m = newMask(t, nil, "padding-min", 150, "padding-max", 300)
		require.Equal(t, []int{100, 100}, []int{m.padMin, m.padMax})
		m = newMask(t, nil, "padding-min", 60, "padding-max", 20)
		require.Equal(t, []int{60, 60}, []int{m.padMin, m.padMax})
		// more than an int holds where it has 32 bits
		m = newMask(t, nil, "padding-min", int64(1)<<31, "padding-max", uint64(1)<<40)
		require.Equal(t, []int{100, 100}, []int{m.padMin, m.padMax})
	})

	// The names Xray-core uses in JSON, the old ones with underscores included.
	t.Run("xray names", func(t *testing.T) {
		tables := []*obfs.Table{tableOf(t, "", "xpxvvpvv"), tableOf(t, "", "vxpvxvvp")}
		for _, settings := range []map[string]any{
			{"custom_table": "xpxvvpvv", "padding_min": 30, "padding_max": 40},
			{"customTable": "xpxvvpvv", "paddingMin": 30, "paddingMax": 40},
		} {
			m := newMask(t, settings)
			require.Equal(t, tables[:1], m.tables)
			require.Equal(t, []int{30, 40}, []int{m.padMin, m.padMax})
		}
		for _, key := range []string{"custom_tables", "customTables"} {
			require.Equal(t, tables, newMask(t, nil, key, []any{"xpxvvpvv", "vxpvxvvp"}).tables)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for name, settings := range map[string]map[string]any{
			"directional mode":     {"ascii": "up_ascii_down_entropy"},
			"unknown mode":         {"ascii": "base64"},
			"short table":          {"custom-table": "xpxvvpv"},
			"long table":           {"custom-table": "xpxvvpvvv"},
			"foreign char":         {"custom-table": "xpxvvpvz"},
			"three x":              {"custom-table": "xxxvvpvv"},
			"three p":              {"custom-table": "xpppvvvx"},
			"bad table in a list":  {"custom-tables": []any{"xpxvvpvv", "vvvvvvvv"}},
			"negative padding":     {"padding-min": -1},
			"padding not a number": {"padding-max": "many"},
			"one key twice":        {"custom_table": "xpxvvpvv", "customTable": "xpxvvpvv"},
		} {
			_, err := New(settings)
			require.Error(t, err, name)
		}
	})

	t.Run("registered for tcp and udp", func(t *testing.T) {
		settings := map[string]any{"password": "secret"}
		tcp, err := mask.BuildTCP("sudoku", settings)
		require.NoError(t, err)
		conn, err := tcp.WrapConn(&fakeConn{})
		require.NoError(t, err)
		require.IsType(t, &Conn{}, conn)
		udp, err := mask.BuildUDP("sudoku", settings)
		require.NoError(t, err)
		_, isCarrier := udp.(mask.UDPCarrier)
		require.False(t, isCarrier)
		pc, err := udp.WrapPacketConn(nil, netip.AddrPort{})
		require.NoError(t, err)
		require.IsType(t, &PacketConn{}, pc)
		_, err = mask.BuildTCP("sudoku", map[string]any{"ascii": "up_ascii_down_entropy"})
		require.Error(t, err)
	})
}

// The tables come from the Sudoku transport; this test is what holds them to
// Xray-core's. Every table the mask builds, an empty password included, is
// checked against the reference in full: the padding and the classes of all
// wire bytes, the hint bytes of every puzzle of every byte value, and what
// any four hints decode to.
func TestFinalmaskSudokuTablesMatchReference(t *testing.T) {
	require.Len(t, refPatterns, 288)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMask(t, tc.settings)
			refs := refTables(password(tc.settings), tc.ref...)
			require.Len(t, m.tables, len(refs))
			for i, ref := range refs {
				table, layout := m.tables[i], ref.layout
				require.Equal(t, layout.paddingPool, table.PaddingPool)
				require.Equal(t, layout.padMarker, table.PadMarker())
				for b := 0; b < 256; b++ {
					isHint := layout.isHint(byte(b))
					require.Equal(t, isHint, table.IsHint(byte(b)), "byte %#x", b)
					group, ok := table.PackedGroup(byte(b))
					require.Equal(t, isHint, ok, "byte %#x", b)
					if ok {
						want, _ := layout.decodeGroup(byte(b))
						require.Equal(t, want, group, "byte %#x", b)
					}
				}

				// the puzzles of every byte value
				puzzles := 0
				for b := 0; b < 256; b++ {
					require.Len(t, table.EncodeTable[b], len(ref.encode[b]), "byte %d", b)
					for j, hints := range table.EncodeTable[b] {
						require.Equal(t, refSort4(ref.encode[b][j]), refSort4(hints), "byte %d", b)
						puzzles++
					}
				}
				require.Len(t, ref.decode, puzzles)

				// every choice of four clues, repeated ones included
				decoded := 0
				for a := byte(0); a < 64; a++ {
					for b := a; b < 64; b++ {
						for c := b; c < 64; c++ {
							for d := c; d < 64; d++ {
								hints := [4]byte{layout.encode(d), layout.encode(b), layout.encode(a), layout.encode(c)}
								want, wantOK := ref.decode[refPackKey(refSort4(hints))]
								got, ok := table.DecodeHints(hints)
								if ok != wantOK || (ok && got != want) {
									t.Fatalf("clues %v: got %d %v, want %d %v", []byte{a, b, c, d}, got, ok, want, wantOK)
								}
								if ok {
									decoded++
								}
							}
						}
					}
				}
				require.Equal(t, puzzles, decoded)

				// every byte in the place of a hint of a puzzle: padding and
				// the hint bytes no sender emits decode to nothing
				for pos := 0; pos < 4; pos++ {
					for b := 0; b < 256; b++ {
						hints := table.EncodeTable[byte(b)][0]
						hints[pos] = byte(b)
						want, wantOK := ref.decode[refPackKey(refSort4(hints))]
						got, ok := table.DecodeHints(hints)
						if ok != wantOK || (ok && got != want) {
							t.Fatalf("hints %v: got %d %v, want %d %v", hints, got, ok, want, wantOK)
						}
					}
				}
			}
		})
	}
}

// The alphabets, spelled out.
func TestFinalmaskSudokuWireBytes(t *testing.T) {
	entropy := tableOf(t, "", "")
	for b := 0; b < 256; b++ {
		require.Equal(t, b&0x90 == 0, entropy.IsHint(byte(b)))
	}
	require.Equal(t, []byte{0x80, 0x10, 0x81, 0x11, 0x82, 0x12, 0x83, 0x13, 0x84, 0x14, 0x85, 0x15, 0x86, 0x16, 0x87, 0x17}, entropy.PaddingPool)
	require.Equal(t, byte(0x80), entropy.PadMarker())

	ascii := tableOf(t, "", "ascii")
	for b := 0; b < 256; b++ {
		require.Equal(t, b&0x40 != 0 || b == '\n', ascii.IsHint(byte(b)))
	}
	for _, puzzles := range ascii.EncodeTable {
		for _, hints := range puzzles {
			for _, b := range hints {
				require.True(t, b == '\n' || (b >= 0x40 && b < 0x7f), "hint %#x", b)
			}
		}
	}
	require.Equal(t, []byte(" !\"#$%&'()*+,-./0123456789:;<=>?"), ascii.PaddingPool)
	require.Equal(t, byte('?'), ascii.PadMarker())

	// x: bits 7 and 5, p: bits 6 and 2, v: bits 4, 3, 1 and 0
	custom := tableOf(t, "", "xpxvvpvv")
	for wire, want := range map[byte]byte{0xa0: 0, 0xa0 | 0x40: 0x20, 0xa0 | 0x04: 0x10, 0xa0 | 0x10: 0x08, 0xa0 | 0x01: 0x01} {
		group, ok := custom.PackedGroup(wire)
		require.True(t, ok)
		require.Equal(t, want, group, "byte %#x", wire)
	}
	require.Len(t, custom.PaddingPool, 44)
	for _, b := range custom.PaddingPool {
		require.True(t, b&0xa0 == 0x80 || b&0xa0 == 0x20, "padding %#x has one x bit", b)
	}
	require.Equal(t, byte(0x2f), custom.PadMarker()) // the smallest: 0x20 with four of the six other bits

	// The packed direction is base64 in the alphabet of the layout: "Man" is
	// the groups 19, 22, 5 and 46; "M" alone is 19 and 16, then the marker.
	for _, tc := range []struct {
		tables []*obfs.Table
		wire   []byte
		want   string
	}{
		{[]*obfs.Table{entropy}, []byte{0x23, 0x26, 0x05, 0x4e}, "Man"},
		{[]*obfs.Table{entropy}, []byte{0x23, 0x20, 0x80, 0x23, 0x26, 0x05, 0x4e}, "MMan"},
		{[]*obfs.Table{entropy}, []byte{0x17, 0x23, 0x81, 0x26, 0x05, 0x10, 0x4e, 0x87}, "Man"}, // padding in between
		{[]*obfs.Table{ascii}, []byte("SVEn"), "Man"},
		{[]*obfs.Table{ascii}, []byte("SP?SVEn"), "MMan"},
		{[]*obfs.Table{ascii, entropy}, []byte{'S', 0x26, 'E', 0x4e}, "Man"},
		// the layout changes with every group, the marker belongs to the next one
		// "Ma" is 19, 22 and 4
		{[]*obfs.Table{ascii, entropy}, []byte{'S', 0x26, 'D', 0x80, 0x23, 'V', 0x05, 'n'}, "MaMan"},
	} {
		conn := &Conn{Conn: &fakeConn{in: [][]byte{tc.wire}}, dec: unpacker{tables: tc.tables}}
		got, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, tc.want, string(got))
	}
}

// Building a mask: the time, and the memory its tables keep.
func BenchmarkFinalmaskSudokuNew(b *testing.B) {
	for _, bc := range []struct {
		name     string
		settings map[string]any
	}{
		{"one layout", map[string]any{"password": "secret"}},
		{"six layouts", map[string]any{"password": "secret", "custom-tables": []any{"xpxvvpvv", "vxpvxvvp", "pxvvxvvp", "vpxvxvpv", "xvpvvxpv", "vvxpxpvv"}}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			masks := make([]*Mask, b.N)
			for i := range masks {
				masks[i], _ = New(bc.settings)
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(b.N), "kept-B/op")
			runtime.KeepAlive(masks)
		})
	}
}

func TestFinalmaskSudokuEncode(t *testing.T) {
	data := randomBytes(3000)
	for _, tc := range cases {
		for _, padding := range []int{0, 35, 100} {
			m := newMask(t, tc.settings)
			tables := refTables(password(tc.settings), tc.ref...)
			enc := encoder{tables: m.tables, rng: testRand(t), chance: padding}
			wire := enc.finish(enc.encode(nil, data))

			switch padding {
			case 0:
				require.Len(t, wire, 4*len(data), tc.name)
			case 100:
				require.Len(t, wire, maxExpansion*len(data)+1, tc.name)
			default:
				require.Greater(t, len(wire), 5*len(data), tc.name)
				require.Less(t, len(wire), 6*len(data), tc.name)
			}

			// what a server reads
			got, err := (&refHintDecoder{tables: tables}).decode(wire, nil)
			require.NoError(t, err, tc.name)
			require.Equal(t, data, got, tc.name)

			// and the client itself, for datagrams
			buf := make([]byte, len(data))
			n, ok := m.decodeDatagram(buf, wire)
			require.True(t, ok, tc.name)
			require.Equal(t, data, buf[:n], tc.name)

			// With several tables each byte uses the next one: a receiver
			// that stays on the first table does not get the data.
			if len(tables) > 1 {
				got, err := (&refHintDecoder{tables: tables[:1]}).decode(wire, nil)
				require.True(t, err != nil || !bytes.Equal(data, got), tc.name)
			}
		}
	}
}

func TestFinalmaskSudokuDatagramDecodeIsStrict(t *testing.T) {
	for _, tc := range cases {
		m := newMask(t, tc.settings)
		data := randomBytes(40)
		enc := encoder{tables: m.tables, rng: testRand(t), chance: 50}
		wire := enc.finish(enc.encode(nil, data))
		buf := make([]byte, 64)

		n, ok := m.decodeDatagram(buf, wire)
		require.True(t, ok)
		require.Equal(t, data, buf[:n])

		_, ok = m.decodeDatagram(buf[:len(data)-1], wire)
		require.False(t, ok, "does not fit")

		// a hint of the layout that is next after the data
		hint := m.tables[len(data)%len(m.tables)].EncodeTable[0][0][0]
		_, ok = m.decodeDatagram(buf, append(wire[:len(wire):len(wire)], hint))
		require.False(t, ok, "a hint too many")
		_, ok = m.decodeDatagram(buf, append(wire[:len(wire):len(wire)], hint, hint, hint, hint))
		require.False(t, ok, "not a puzzle")

		padding := m.tables[0].PaddingPool
		n, ok = m.decodeDatagram(buf, padding)
		require.True(t, ok, "padding alone is an empty datagram")
		require.Zero(t, n)
		n, ok = m.decodeDatagram(buf, nil)
		require.True(t, ok)
		require.Zero(t, n)
	}

	// 0x7f counts as a hint in the ASCII layout but no puzzle has it
	m := newMask(t, nil, "ascii", "ascii")
	enc := encoder{tables: m.tables, rng: testRand(t)}
	wire := enc.encode(nil, []byte{1})
	for i := range wire {
		broken := append([]byte(nil), wire...)
		broken[i] = 0x7f
		_, ok := m.decodeDatagram(make([]byte, 4), broken)
		require.False(t, ok)
	}
}

func TestFinalmaskSudokuConnReadsPackedStream(t *testing.T) {
	data := randomBytes(20000)
	for _, tc := range cases {
		for _, padding := range []int{0, 35, 100} {
			m := newMask(t, tc.settings)
			// the server writes pieces of all sizes, most of them end in the middle of a group
			server := newRefPackedEncoder(refTables(password(tc.settings), tc.ref...), padding)
			var wire []byte
			for _, piece := range chunks(data, 1, 2, 3, 4, 5, 100, 1001, 4096) {
				wire = append(wire, server.encode(piece)...)
			}
			for _, readSize := range []int{1, 7, smallRead - 1, smallRead, 4096, 70000} {
				fake := &fakeConn{in: chunks(wire, 1, 3, 700, 5000, 1)}
				conn, err := m.WrapConn(fake)
				require.NoError(t, err)
				var got []byte
				buf := make([]byte, readSize)
				for {
					n, err := conn.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						require.Equal(t, io.EOF, err)
						break
					}
					require.NotZero(t, n)
				}
				require.True(t, bytes.Equal(data, got), "%s, padding %d, read size %d", tc.name, padding, readSize)
			}
		}
	}
}

func TestFinalmaskSudokuConnWrite(t *testing.T) {
	for _, tc := range cases {
		for _, padding := range []int{0, 35, 100} {
			m := newMask(t, tc.settings, "padding-min", padding, "padding-max", padding)
			fake := &fakeConn{}
			conn, err := m.WrapConn(fake)
			require.NoError(t, err)

			var data, wire []byte
			sizes := []int{1, 5, 2000, 100000, 3}
			for _, size := range sizes {
				piece := randomBytes(size)
				n, err := conn.Write(piece)
				require.NoError(t, err)
				require.Equal(t, size, n)
				data = append(data, piece...)
			}
			n, err := conn.Write(nil)
			require.NoError(t, err)
			require.Zero(t, n)

			// the large write left in pieces
			require.Greater(t, len(fake.out), len(sizes)+5)
			for _, out := range fake.out {
				require.LessOrEqual(t, len(out), maxWireWrite)
				wire = append(wire, out...)
			}
			switch padding {
			case 0:
				require.Len(t, wire, 4*len(data))
			case 100: // every slot is filled, the one that ends each write too
				require.Len(t, wire, maxExpansion*len(data)+len(sizes))
			}
			got, err := (&refHintDecoder{tables: refTables(password(tc.settings), tc.ref...)}).decode(wire, nil)
			require.NoError(t, err)
			require.True(t, bytes.Equal(data, got), "%s, padding %d", tc.name, padding)
		}
	}
}

// The connection must not be bypassed: it has none of the methods a relay
// uses to reach the connection below.
func TestFinalmaskSudokuConnHidesWrappedConn(t *testing.T) {
	fake := &fakeConn{}
	conn, err := newMask(t, nil).WrapConn(fake)
	require.NoError(t, err)

	_, ok := conn.(interface{ Upstream() any })
	require.False(t, ok)
	_, ok = conn.(interface{ ReaderReplaceable() bool })
	require.False(t, ok)
	_, ok = conn.(interface{ WriterReplaceable() bool })
	require.False(t, ok)
	_, ok = conn.(io.ReaderFrom)
	require.False(t, ok)
	_, ok = conn.(io.WriterTo)
	require.False(t, ok)

	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
	require.True(t, fake.closedWrite)
	require.NoError(t, conn.Close())
	require.True(t, fake.closed)

	// the half-close passes a mask that sits between this one and the socket
	fake = &fakeConn{}
	below, err := fragment.New(map[string]any{"length": 5})
	require.NoError(t, err)
	fragmented, err := below.WrapConn(fake)
	require.NoError(t, err)
	_, ok = fragmented.(interface{ CloseWrite() error })
	require.False(t, ok)
	conn, err = newMask(t, nil).WrapConn(fragmented)
	require.NoError(t, err)
	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())
	require.True(t, fake.closedWrite)

	// a connection that cannot be half-closed
	client, server := net.Pipe()
	defer server.Close()
	conn, err = newMask(t, nil).WrapConn(client)
	require.NoError(t, err)
	require.Error(t, conn.(interface{ CloseWrite() error }).CloseWrite())
	require.NoError(t, conn.Close())
	_, err = conn.Write([]byte("closed"))
	require.Error(t, err)
	_, err = conn.Read(make([]byte, 600))
	require.Error(t, err)
	_, err = conn.Read(make([]byte, 6))
	require.Error(t, err)
}

// A failed write ends the stream: the table index has moved past bytes that
// may not have left, a later write would not be understood.
func TestFinalmaskSudokuConnWriteErrorIsFinal(t *testing.T) {
	failure := errors.New("deadline exceeded")
	fake := &fakeConn{outErr: failure, outErrAfter: 1}
	conn, err := newMask(t, nil).WrapConn(fake)
	require.NoError(t, err)

	// the second piece of a large write fails
	n, err := conn.Write(randomBytes(100000))
	require.Equal(t, failure, err)
	require.Equal(t, (maxWireWrite-1)/4, n)
	require.Len(t, fake.out, 1)

	// the wrapped connection would take more now
	for i := 0; i < 2; i++ {
		n, err = conn.Write([]byte("more"))
		require.Equal(t, failure, err)
		require.Zero(t, n)
	}
	require.Len(t, fake.out, 1)
}

// An error the wrapped connection returns together with data is not lost: it
// follows the data.
func TestFinalmaskSudokuConnReadKeepsError(t *testing.T) {
	wire := newRefPackedEncoder(refTables("", ""), 30).encode([]byte("some data"))
	failure := errors.New("reported once")
	for _, size := range []int{1, 4, smallRead, 3000} {
		conn, err := newMask(t, nil).WrapConn(&fakeConn{in: [][]byte{wire}, inErr: failure})
		require.NoError(t, err)
		buf := make([]byte, size)
		var got []byte
		for {
			n, err := conn.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				require.Equal(t, failure, err, "read size %d", size)
				break
			}
		}
		require.Equal(t, "some data", string(got))
		// it is reported once, then the connection is asked again
		_, err = conn.Read(buf)
		require.Equal(t, io.EOF, err)
	}
}

// Two writers and a reader share a connection to a server that echoes.
func TestFinalmaskSudokuConnConcurrentUse(t *testing.T) {
	tc := cases[4]
	m := newMask(t, tc.settings, "padding-min", 10, "padding-max", 60)
	client, server := net.Pipe()
	conn, err := m.WrapConn(client)
	require.NoError(t, err)

	tables := refTables(password(tc.settings), tc.ref...)
	go func() {
		defer server.Close()
		decoder := &refHintDecoder{tables: tables}
		packer := newRefPackedEncoder(tables, 30)
		buf := make([]byte, 16*1024)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			plain, err := decoder.decode(buf[:n], nil)
			if err != nil {
				return
			}
			if len(plain) == 0 {
				continue
			}
			if _, err := server.Write(packer.encode(plain)); err != nil {
				return
			}
		}
	}()

	const messages, size = 50, 1000
	var wg sync.WaitGroup
	for id := byte(1); id <= 2; id++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			for i := 0; i < messages; i++ {
				if _, err := conn.Write(bytes.Repeat([]byte{id}, size)); err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}

	// each write arrives whole
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Second)))
	count := map[byte]int{}
	message := make([]byte, size)
	for i := 0; i < 2*messages; i++ {
		_, err := io.ReadFull(conn, message)
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat(message[:1], size), message)
		count[message[0]]++
	}
	require.Equal(t, map[byte]int{1: messages, 2: messages}, count)
	wg.Wait()
	require.NoError(t, conn.Close())
}

func TestFinalmaskSudokuPacketConn(t *testing.T) {
	listen := func(t *testing.T, m *Mask) (net.PacketConn, net.PacketConn) {
		t.Helper()
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		pc, err := m.WrapPacketConn(socket, netip.AddrPort{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		require.NoError(t, pc.SetDeadline(time.Now().Add(10*time.Second)))
		return pc, socket
	}

	for _, tc := range cases {
		for _, padding := range []int{0, 100} {
			m := newMask(t, tc.settings, "padding-min", padding, "padding-max", padding)
			a, rawA := listen(t, m)
			b, _ := listen(t, m)

			buf := make([]byte, 900) // nine times that fits a datagram on every system
			for _, size := range []int{1, 0, 700, 900} {
				data := randomBytes(size)
				n, err := a.WriteTo(data, b.LocalAddr())
				require.NoError(t, err)
				require.Equal(t, size, n)
				n, from, err := b.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, data, buf[:n])
				require.Equal(t, a.LocalAddr().String(), from.String())
			}

			// what does not decode or does not fit the caller's buffer is
			// skipped, the next good datagram is returned
			good := []byte("good")
			hint := m.tables[0].EncodeTable[0][0][0]
			for _, junk := range [][]byte{{hint}, {hint, hint, hint, hint}} {
				_, err := rawA.WriteTo(junk, b.LocalAddr())
				require.NoError(t, err)
			}
			_, err := a.WriteTo(randomBytes(len(buf)+1), b.LocalAddr())
			require.NoError(t, err)
			_, err = a.WriteTo(good, b.LocalAddr())
			require.NoError(t, err)
			n, _, err := b.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, good, buf[:n])

			// A datagram may grow to the largest one UDP carries, not more.
			// The limit is the same in every build.
			fits := maxDatagram / 4
			if padding == 100 {
				fits = (maxDatagram - 1) / maxExpansion
			}
			sent := &fakePacketConn{}
			pc, err := m.WrapPacketConn(sent, netip.AddrPort{})
			require.NoError(t, err)
			_, err = pc.WriteTo(make([]byte, fits+1), nil)
			require.Error(t, err)
			_, err = pc.WriteTo(make([]byte, maxDatagram), nil)
			require.Error(t, err)
			require.Empty(t, sent.out)
			// 2049 bytes are 8196 on the wire without padding, more than a small pooled buffer
			for _, size := range []int{2049, fits} {
				data := randomBytes(size)
				n, err = pc.WriteTo(data, nil)
				require.NoError(t, err)
				require.Equal(t, size, n)
				require.Len(t, sent.out, 1)
				if padding == 0 {
					require.Len(t, sent.out[0], 4*size)
				} else {
					require.Len(t, sent.out[0], maxExpansion*size+1)
				}
				require.LessOrEqual(t, len(sent.out[0]), maxDatagram)

				// and it is received whole
				received, err := m.WrapPacketConn(&fakePacketConn{in: sent.out}, netip.AddrPort{})
				require.NoError(t, err)
				large := make([]byte, size)
				n, _, err = received.ReadFrom(large)
				require.NoError(t, err)
				require.True(t, bytes.Equal(data, large[:n]))
				sent.out = nil
			}
		}
	}

	// A datagram that fills the read buffer was cut by it. It is dropped even
	// when what is left of it decodes.
	t.Run("cut datagram", func(t *testing.T) {
		m := newMask(t, nil)
		enc := encoder{tables: m.tables, rng: testRand(t)}
		cut := enc.encode(nil, randomBytes(datagramBuffer/4))
		for len(cut) < datagramBuffer+100 {
			cut = append(cut, m.tables[0].PaddingPool[1])
		}
		buf := make([]byte, datagramBuffer)
		_, ok := m.decodeDatagram(buf, cut[:datagramBuffer])
		require.True(t, ok)

		pc, err := m.WrapPacketConn(&fakePacketConn{in: [][]byte{cut, enc.encode(nil, []byte("good"))}}, netip.AddrPort{})
		require.NoError(t, err)
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, "good", string(buf[:n]))
	})

	t.Run("another password", func(t *testing.T) {
		// The puzzles are the same for every password, only the byte a grid
		// stands for differs, and 32 of the 288 grids stand for none: the
		// datagram is dropped or, rarely, arrives as other bytes.
		a, _ := listen(t, newMask(t, nil, "password", "one"))
		b, _ := listen(t, newMask(t, nil, "password", "two"))
		data := randomBytes(100)
		_, err := a.WriteTo(data, b.LocalAddr())
		require.NoError(t, err)
		require.NoError(t, b.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
		buf := make([]byte, 2000)
		n, _, err := b.ReadFrom(buf)
		require.True(t, err != nil || !bytes.Equal(data, buf[:n]))
	})

	t.Run("close", func(t *testing.T) {
		a, _ := listen(t, newMask(t, nil))
		done := make(chan error, 1)
		go func() {
			_, _, err := a.ReadFrom(make([]byte, 2000))
			done <- err
		}()
		require.NoError(t, a.Close())
		require.Error(t, <-done)
		_, err := a.WriteTo([]byte("closed"), a.LocalAddr())
		require.Error(t, err)
	})
}

// The Sudoku transport has a codec of its own over the same tables, with one
// table per connection. Whatever one of the two encodes the other decodes.
func TestFinalmaskSudokuCrossCheckWithSudokuTransport(t *testing.T) {
	data := randomBytes(10000)
	for _, tc := range cases[:3] {
		t.Run(tc.name, func(t *testing.T) {
			m := newMask(t, tc.settings, "padding-min", 20, "padding-max", 60)
			table := m.tables[0]

			// puzzles: the mask encodes, the transport decodes
			fake := &fakeConn{}
			conn, err := m.WrapConn(fake)
			require.NoError(t, err)
			_, err = conn.Write(data)
			require.NoError(t, err)
			got := make([]byte, len(data))
			_, err = io.ReadFull(obfs.NewConn(&fakeConn{in: fake.out}, table, 0, 0, false), got)
			require.NoError(t, err)
			require.True(t, bytes.Equal(data, got))

			// puzzles: the transport encodes, the mask decodes
			fake = &fakeConn{}
			_, err = obfs.NewConn(fake, table, 20, 60, false).Write(data)
			require.NoError(t, err)
			n, ok := m.decodeDatagram(got, bytes.Join(fake.out, nil))
			require.True(t, ok)
			require.True(t, bytes.Equal(data, got[:n]))

			// packed: the transport encodes, the mask decodes
			fake = &fakeConn{}
			packed := obfs.NewPackedConn(fake, table, 20, 60)
			for _, piece := range chunks(data, 1, 2, 3, 500, 4000) {
				_, err = packed.Write(piece)
				require.NoError(t, err)
			}
			conn, err = m.WrapConn(&fakeConn{in: fake.out})
			require.NoError(t, err)
			got, err = io.ReadAll(conn)
			require.NoError(t, err)
			require.True(t, bytes.Equal(data, got))

			// packed: the reference server the mask is tested against
			// encodes, the transport decodes
			server := newRefPackedEncoder(refTables(password(tc.settings), tc.ref...), 40)
			var wire [][]byte
			for _, piece := range chunks(data, 1, 2, 3, 500, 4000) {
				wire = append(wire, server.encode(piece))
			}
			got = make([]byte, len(data))
			_, err = io.ReadFull(obfs.NewPackedConn(&fakeConn{in: wire}, table, 0, 0), got)
			require.NoError(t, err)
			require.True(t, bytes.Equal(data, got))
		})
	}
}
