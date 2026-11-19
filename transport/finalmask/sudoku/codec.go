package sudoku

import (
	"math"

	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"

	"github.com/metacubex/randv2"
)

// maxExpansion is how many wire bytes one byte takes at most: four hints,
// each with a padding slot before it, and one more slot before the group.
// A write ends with one more slot.
const maxExpansion = 9

// perms are the orders the four hints of a byte can leave in.
var perms = func() (out [24][4]byte) {
	n := 0
	for a := byte(0); a < 4; a++ {
		for b := byte(0); b < 4; b++ {
			for c := byte(0); c < 4; c++ {
				// the fourth is the one left: the four add up to 6
				if d := 6 - a - b - c; a != b && a != c && b != c && d < 4 && d != a && d != b && d != c {
					out[n] = [4]byte{a, b, c, d}
					n++
				}
			}
		}
	}
	return out
}()

// encoder turns bytes into puzzles, the direction the client sends in.
type encoder struct {
	tables []*obfs.Table
	rng    *randv2.Rand
	// chance is how many padding slots out of a hundred get a byte.
	chance int
	// index is the table of the next byte.
	index int
}

// pad fills a padding slot with a padding byte of t, or leaves it empty.
func (e *encoder) pad(out []byte, t *obfs.Table) []byte {
	if e.chance <= 0 || (e.chance < 100 && e.rng.IntN(100) >= e.chance) {
		return out
	}
	return append(out, t.PaddingPool[e.rng.IntN(len(t.PaddingPool))])
}

// encode appends the puzzles of in to out. Every byte uses the next table.
func (e *encoder) encode(out, in []byte) []byte {
	for _, b := range in {
		t := e.tables[e.index]
		out = e.pad(out, t)
		puzzles := t.EncodeTable[b]
		draw := e.rng.Uint64()
		puzzle := puzzles[(draw>>32)*uint64(len(puzzles))>>32]
		for _, i := range perms[(draw&math.MaxUint32)*uint64(len(perms))>>32] {
			out = e.pad(out, t)
			out = append(out, puzzle[i])
		}
		if e.index++; e.index == len(e.tables) {
			e.index = 0
		}
	}
	return out
}

// finish appends what ends a write or a datagram: one more padding slot.
func (e *encoder) finish(out []byte) []byte {
	return e.pad(out, e.tables[e.index])
}

// decodeDatagram decodes a datagram of puzzles into dst and returns the number
// of bytes. It reports false when the datagram is not a whole number of valid
// puzzles or does not fit dst. The first byte uses the first table.
func (m *Mask) decodeDatagram(dst, src []byte) (int, bool) {
	var hints [4]byte
	count, n, index := 0, 0, 0
	for _, b := range src {
		t := m.tables[index]
		if !t.IsHint(b) {
			continue
		}
		hints[count] = b
		if count++; count < 4 {
			continue
		}
		count = 0
		value, ok := t.DecodeHints(hints)
		if !ok || n == len(dst) {
			return 0, false
		}
		dst[n] = value
		n++
		if index++; index == len(m.tables) {
			index = 0
		}
	}
	return n, count == 0
}

// unpacker decodes the packed stream the server sends over TCP: each hint
// carries six bits, most significant first, and the table changes with every
// hint. Bits left over when the server ends a write are dropped at the marker
// byte that follows them.
type unpacker struct {
	tables []*obfs.Table
	index  int // table of the next hint
	acc    uint32
	bits   uint
}

// decode moves bytes from src to dst until one of them ends and returns how
// many it wrote and read. It never writes more bytes than it has read, so dst
// and src may be the same buffer.
func (u *unpacker) decode(dst, src []byte) (n, used int) {
	for used < len(src) && n < len(dst) {
		b := src[used]
		used++
		t := u.tables[u.index]
		group, ok := t.PackedGroup(b)
		if !ok {
			if b == t.PadMarker() {
				u.acc, u.bits = 0, 0
			}
			continue
		}
		if u.index++; u.index == len(u.tables) {
			u.index = 0
		}
		u.acc = u.acc<<6 | uint32(group)
		if u.bits += 6; u.bits >= 8 {
			u.bits -= 8
			dst[n] = byte(u.acc >> u.bits)
			n++
			u.acc &= 1<<u.bits - 1
		}
	}
	return n, used
}
