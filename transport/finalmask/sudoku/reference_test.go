package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"math/rand"
	"sort"
)

// The reference is the codec the way Xray-core v26.11.9 writes it
// (transport/internet/finalmask/sudoku: table.go, codec.go,
// conn_tcp_packed.go), kept close to that source: tables as maps from four
// sorted hint bytes to a byte, layouts as functions. It includes the halves
// only a server runs, the hint stream decoder and the packed encoder. The
// tests hold the package against it.

type refLayout struct {
	hintMask    byte
	hintValue   byte
	padMarker   byte
	paddingPool []byte
	encode      func(group byte) byte
	decodeGroup func(b byte) (byte, bool)
}

func (l *refLayout) isHint(b byte) bool {
	if (b & l.hintMask) == l.hintValue {
		return true
	}
	return l.hintMask == 0x40 && b == '\n'
}

func refASCIILayout() *refLayout {
	padding := make([]byte, 0, 32)
	for i := 0; i < 32; i++ {
		padding = append(padding, byte(0x20+i))
	}
	return &refLayout{
		hintMask:    0x40,
		hintValue:   0x40,
		padMarker:   0x3f,
		paddingPool: padding,
		encode: func(group byte) byte {
			b := byte(0x40 | (group & 0x3f))
			if b == 0x7f {
				return '\n'
			}
			return b
		},
		decodeGroup: func(b byte) (byte, bool) {
			if b == '\n' {
				return 0x3f, true
			}
			if (b & 0x40) == 0 {
				return 0, false
			}
			return b & 0x3f, true
		},
	}
}

func refEntropyLayout() *refLayout {
	padding := make([]byte, 0, 16)
	for i := 0; i < 8; i++ {
		padding = append(padding, byte(0x80+i), byte(0x10+i))
	}
	return &refLayout{
		hintMask:    0x90,
		hintValue:   0x00,
		padMarker:   0x80,
		paddingPool: padding,
		encode: func(group byte) byte {
			v := group & 0x3f
			return ((v & 0x30) << 1) | (v & 0x0f)
		},
		decodeGroup: func(b byte) (byte, bool) {
			if (b & 0x90) != 0 {
				return 0, false
			}
			return ((b >> 1) & 0x30) | (b & 0x0f), true
		},
	}
}

func refCustomLayout(pattern string) *refLayout {
	var xBits, pBits, vBits []uint8
	for i, c := range pattern {
		bit := uint8(7 - i)
		switch c {
		case 'x':
			xBits = append(xBits, bit)
		case 'p':
			pBits = append(pBits, bit)
		case 'v':
			vBits = append(vBits, bit)
		}
	}
	xMask := byte(0)
	for _, bit := range xBits {
		xMask |= 1 << bit
	}
	encodeGroupWithDropX := func(group byte, dropX int) byte {
		out := xMask
		if dropX >= 0 {
			out &^= 1 << xBits[dropX]
		}
		val := (group >> 4) & 0x03
		pos := group & 0x0f
		if (val & 0x02) != 0 {
			out |= 1 << pBits[0]
		}
		if (val & 0x01) != 0 {
			out |= 1 << pBits[1]
		}
		for i, bit := range vBits {
			if (pos>>(3-uint8(i)))&0x01 == 1 {
				out |= 1 << bit
			}
		}
		return out
	}
	paddingSet := make(map[byte]struct{}, 64)
	padding := make([]byte, 0, 64)
	for drop := range xBits {
		for val := byte(0); val < 4; val++ {
			for pos := byte(0); pos < 16; pos++ {
				b := encodeGroupWithDropX((val<<4)|pos, drop)
				if bits.OnesCount8(b) >= 5 {
					if _, exists := paddingSet[b]; !exists {
						paddingSet[b] = struct{}{}
						padding = append(padding, b)
					}
				}
			}
		}
	}
	sort.Slice(padding, func(i, j int) bool { return padding[i] < padding[j] })
	return &refLayout{
		hintMask:    xMask,
		hintValue:   xMask,
		padMarker:   padding[0],
		paddingPool: padding,
		encode:      func(group byte) byte { return encodeGroupWithDropX(group, -1) },
		decodeGroup: func(b byte) (byte, bool) {
			if (b & xMask) != xMask {
				return 0, false
			}
			var val, pos byte
			if b&(1<<pBits[0]) != 0 {
				val |= 0x02
			}
			if b&(1<<pBits[1]) != 0 {
				val |= 0x01
			}
			for i, bit := range vBits {
				if b&(1<<bit) != 0 {
					pos |= 1 << (3 - uint8(i))
				}
			}
			return ((val & 0x03) << 4) | (pos & 0x0f), true
		},
	}
}

// refLayoutOf resolves a normalised pattern: "ascii", "" for entropy or a
// custom table.
func refLayoutOf(pattern string) *refLayout {
	switch pattern {
	case "ascii":
		return refASCIILayout()
	case "":
		return refEntropyLayout()
	}
	return refCustomLayout(pattern)
}

type refTable struct {
	encode [256][][4]byte
	decode map[uint32]byte
	layout *refLayout
}

func refPackKey(in [4]byte) uint32 {
	return uint32(in[0])<<24 | uint32(in[1])<<16 | uint32(in[2])<<8 | uint32(in[3])
}

func refSort4(in [4]byte) [4]byte {
	if in[0] > in[1] {
		in[0], in[1] = in[1], in[0]
	}
	if in[2] > in[3] {
		in[2], in[3] = in[3], in[2]
	}
	if in[0] > in[2] {
		in[0], in[2] = in[2], in[0]
	}
	if in[1] > in[3] {
		in[1], in[3] = in[3], in[1]
	}
	if in[1] > in[2] {
		in[1], in[2] = in[2], in[1]
	}
	return in
}

// refAllGrids lists the complete 4x4 sudoku grids in the order of a
// depth-first search.
func refAllGrids() [][16]byte {
	grids := make([][16]byte, 0, 288)
	var g [16]byte
	var dfs func(idx int)
	dfs = func(idx int) {
		if idx == 16 {
			grids = append(grids, g)
			return
		}
		row := idx / 4
		col := idx % 4
		boxRow := (row / 2) * 2
		boxCol := (col / 2) * 2
		for num := byte(1); num <= 4; num++ {
			valid := true
			for i := 0; i < 4; i++ {
				if g[row*4+i] == num || g[i*4+col] == num {
					valid = false
					break
				}
			}
			for r := 0; r < 2 && valid; r++ {
				for c := 0; c < 2; c++ {
					if g[(boxRow+r)*4+(boxCol+c)] == num {
						valid = false
						break
					}
				}
			}
			if !valid {
				continue
			}
			g[idx] = num
			dfs(idx + 1)
			g[idx] = 0
		}
	}
	dfs(0)
	return grids
}

// refBasePatterns lists for every grid the clue sets that no other grid
// shares, as sorted 6-bit groups.
func refBasePatterns() [][][4]byte {
	grids := refAllGrids()
	patterns := make([][][4]byte, len(grids))
	for a := 0; a < 13; a++ {
		for b := a + 1; b < 14; b++ {
			for c := b + 1; c < 15; c++ {
				for d := c + 1; d < 16; d++ {
					counts := make(map[uint32]uint16, len(grids))
					keys := make([]uint32, len(grids))
					groupsByGrid := make([][4]byte, len(grids))
					for gi, g := range grids {
						groups := refSort4([4]byte{
							((g[a] - 1) << 4) | byte(a), ((g[b] - 1) << 4) | byte(b),
							((g[c] - 1) << 4) | byte(c), ((g[d] - 1) << 4) | byte(d),
						})
						keys[gi] = refPackKey(groups)
						groupsByGrid[gi] = groups
						counts[keys[gi]]++
					}
					for gi, key := range keys {
						if counts[key] == 1 {
							patterns[gi] = append(patterns[gi], groupsByGrid[gi])
						}
					}
				}
			}
		}
	}
	return patterns
}

var refPatterns = refBasePatterns()

func refBuildTable(password string, layout *refLayout) *refTable {
	order := make([]int, len(refPatterns))
	for i := range order {
		order[i] = i
	}
	hash := sha256.Sum256([]byte(password))
	seed := int64(binary.BigEndian.Uint64(hash[:8]))
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(order), func(i, j int) {
		order[i], order[j] = order[j], order[i]
	})

	t := &refTable{decode: make(map[uint32]byte, 1<<16), layout: layout}
	for b := 0; b < 256; b++ {
		for _, groups := range refPatterns[order[b]] {
			hints := [4]byte{
				layout.encode(groups[0]), layout.encode(groups[1]),
				layout.encode(groups[2]), layout.encode(groups[3]),
			}
			key := refPackKey(refSort4(hints))
			if old, exists := t.decode[key]; exists && old != byte(b) {
				panic(fmt.Sprintf("decode key collision for byte %d and %d", old, b))
			}
			t.decode[key] = byte(b)
			t.encode[b] = append(t.encode[b], hints)
		}
	}
	return t
}

func refTables(password string, patterns ...string) []*refTable {
	tables := make([]*refTable, 0, len(patterns))
	for _, pattern := range patterns {
		tables = append(tables, refBuildTable(password, refLayoutOf(pattern)))
	}
	return tables
}

// refHintDecoder is the hint stream decoder of a server.
type refHintDecoder struct {
	tables     []*refTable
	tableIndex int
	hintBuf    []byte
}

func (d *refHintDecoder) decode(in []byte, out []byte) ([]byte, error) {
	for _, b := range in {
		t := d.tables[d.tableIndex%len(d.tables)]
		if !t.layout.isHint(b) {
			continue
		}
		d.hintBuf = append(d.hintBuf, b)
		if len(d.hintBuf) < 4 {
			continue
		}
		key := refPackKey(refSort4([4]byte{d.hintBuf[0], d.hintBuf[1], d.hintBuf[2], d.hintBuf[3]}))
		d.hintBuf = d.hintBuf[:0]
		decoded, ok := t.decode[key]
		if !ok {
			return out, fmt.Errorf("invalid sudoku hint tuple")
		}
		out = append(out, decoded)
		d.tableIndex++
	}
	return out, nil
}

// refPackedEncoder is the packed encoder of a server; padding is the chance
// in percent.
type refPackedEncoder struct {
	layouts    []*refLayout
	rng        *rand.Rand
	padding    int
	groupIndex int
}

func newRefPackedEncoder(tables []*refTable, padding int) *refPackedEncoder {
	e := &refPackedEncoder{rng: rand.New(rand.NewSource(1)), padding: padding}
	for _, t := range tables {
		e.layouts = append(e.layouts, t.layout)
	}
	return e
}

func (e *refPackedEncoder) encode(p []byte) []byte {
	out := make([]byte, 0, len(p)*2+8)
	var bitBuf uint64
	var bitCount uint8
	for _, b := range p {
		bitBuf = (bitBuf << 8) | uint64(b)
		bitCount += 8
		for bitCount >= 6 {
			bitCount -= 6
			layout := e.layouts[e.groupIndex%len(e.layouts)]
			group := byte(bitBuf >> bitCount)
			out = e.maybePad(out, layout)
			out = append(out, layout.encode(group&0x3f))
			e.groupIndex++
			if bitCount > 0 {
				bitBuf &= (uint64(1) << bitCount) - 1
			} else {
				bitBuf = 0
			}
		}
	}
	if bitCount > 0 {
		layout := e.layouts[e.groupIndex%len(e.layouts)]
		group := byte(bitBuf << (6 - bitCount))
		out = e.maybePad(out, layout)
		out = append(out, layout.encode(group&0x3f))
		e.groupIndex++
		nextLayout := e.layouts[e.groupIndex%len(e.layouts)]
		out = append(out, nextLayout.padMarker)
	}
	return e.maybePad(out, e.layouts[e.groupIndex%len(e.layouts)])
}

func (e *refPackedEncoder) maybePad(out []byte, layout *refLayout) []byte {
	if e.padding <= 0 || (e.padding < 100 && e.rng.Intn(100) >= e.padding) {
		return out
	}
	for {
		b := layout.paddingPool[e.rng.Intn(len(layout.paddingPool))]
		if b != layout.padMarker {
			return append(out, b)
		}
	}
}
