// Package sudoku is the "sudoku" mask of Xray-core's finalmask, for TCP and
// UDP. It rewrites the traffic into bytes of a chosen shape, low in set bits
// or printable ASCII, so that it does not look like ciphertext.
//
// Every byte the client sends becomes a puzzle: four clues of a 4x4 sudoku
// that has a single solution, each clue one byte on the wire, in random order.
// A table made from the password says which of the 288 solved grids stands for
// which byte value. Padding bytes may be mixed in at a configured rate. What
// the server sends over TCP is packed tighter, six bits to a byte in the same
// shape, since the bulk of the traffic flows that way; over UDP both sides
// send puzzles, every datagram on its own.
//
// There is no handshake and nothing is encrypted or authenticated: the mask
// only changes how the bytes look. The server needs the same mask with the
// same settings.
//
// The tables are those of the Sudoku transport (transport/sudoku), which
// derives them from a key the way Xray-core does from the password. The codec
// is not shared with it: this one changes tables inside a stream and has a
// form for datagrams.
package sudoku

import (
	crand "crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"

	"github.com/metacubex/randv2"
)

func init() {
	mask.RegisterTCP("sudoku", func(settings map[string]any) (mask.TCPMask, error) {
		return New(settings)
	})
	mask.RegisterUDP("sudoku", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// Password seeds the table. It may be empty.
	Password string `mask:"password,omitempty"`
	// ASCII is "prefer_entropy" (the default, also "entropy" or empty) for
	// bytes with few set bits, or "prefer_ascii" (also "ascii") for printable
	// ones.
	ASCII string `mask:"ascii,omitempty"`
	// CustomTable replaces the entropy shape with a pattern of 8 characters,
	// two x, two p and four v, such as "xpxvvpvv". CustomTables is a list of
	// them and takes precedence; with several the shape changes all the time,
	// after every byte the client sends and every six bits the server packs.
	// An empty entry is the entropy shape. Both are ignored in ASCII mode.
	CustomTable  string   `mask:"custom-table,omitempty"`
	CustomTables []string `mask:"custom-tables,omitempty"`
	// PaddingMin and PaddingMax bound, in percent, how often a padding byte
	// precedes a byte that carries data. A TCP connection picks its rate
	// between them once, UDP for every datagram.
	PaddingMin int64 `mask:"padding-min,omitempty"`
	PaddingMax int64 `mask:"padding-max,omitempty"`
}

// Mask is a parsed sudoku mask.
type Mask struct {
	// tables are the tables the sender rotates through, one per layout.
	tables []*obfs.Table
	padMin int
	padMax int
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	if options.PaddingMin < 0 || options.PaddingMax < 0 {
		return nil, fmt.Errorf("negative padding")
	}
	tables, err := newTables(options)
	if err != nil {
		return nil, err
	}
	m := &Mask{tables: tables, padMin: percent(options.PaddingMin), padMax: percent(options.PaddingMax)}
	if m.padMax < m.padMin {
		m.padMax = m.padMin
	}
	return m, nil
}

// newTables builds the tables the settings ask for, in the order they are
// used. All of them map the grids to byte values the same way, by the
// password; they differ in the layout of the bytes on the wire.
func newTables(options Options) ([]*obfs.Table, error) {
	switch strings.ToLower(strings.TrimSpace(options.ASCII)) {
	case "", "entropy", "prefer_entropy":
	case "ascii", "prefer_ascii":
		table, err := obfs.NewTableWithCustom(options.Password, "prefer_ascii", "")
		if err != nil {
			return nil, err
		}
		return []*obfs.Table{table}, nil
	default:
		return nil, fmt.Errorf("invalid ascii mode %q, want prefer_entropy or prefer_ascii", options.ASCII)
	}

	patterns := options.CustomTables
	if len(patterns) == 0 {
		patterns = []string{options.CustomTable}
	}
	var tables []*obfs.Table
	seen := make(map[string]bool, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern != "" {
			var err error
			if pattern, err = normalizePattern(pattern); err != nil {
				return nil, err
			}
		}
		if seen[pattern] {
			continue
		}
		seen[pattern] = true
		// an empty pattern is the entropy layout
		table, err := obfs.NewTableWithCustom(options.Password, "prefer_entropy", pattern)
		if err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, nil
}

// normalizePattern checks a custom table: 8 characters, two x, two p and four
// v in any order and case, spaces are ignored. Most significant bit first,
// the x bits are set in every hint, the p bits carry the value and the v bits
// the cell of a clue.
func normalizePattern(pattern string) (string, error) {
	cleaned := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(pattern)), " ", "")
	if len(cleaned) != 8 {
		return "", fmt.Errorf("custom table %q must be 8 chars, got %d", pattern, len(cleaned))
	}
	if strings.Trim(cleaned, "xpv") != "" {
		return "", fmt.Errorf("custom table %q has a char other than x, p and v", pattern)
	}
	if strings.Count(cleaned, "x") != 2 || strings.Count(cleaned, "p") != 2 {
		return "", fmt.Errorf("custom table %q must contain exactly 2 x, 2 p and 4 v", pattern)
	}
	return cleaned, nil
}

// percent caps a padding setting at 100.
func percent(value int64) int {
	if value > 100 {
		return 100
	}
	return int(value)
}

func (m *Mask) WrapConn(conn net.Conn) (net.Conn, error) {
	rng, err := newRand()
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn: conn,
		dec:  unpacker{tables: m.tables},
		enc:  encoder{tables: m.tables, rng: rng, chance: m.paddingChance(rng)},
	}, nil
}

func (m *Mask) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	rng, err := newRand()
	if err != nil {
		return nil, err
	}
	return &PacketConn{PacketConn: conn, mask: m, rng: rng}, nil
}

// paddingChance picks the padding rate of a connection or a datagram.
func (m *Mask) paddingChance(rng *randv2.Rand) int {
	if m.padMax == m.padMin {
		return m.padMin
	}
	return m.padMin + rng.IntN(m.padMax-m.padMin+1)
}

// newRand returns the source of the choices a sender makes: the puzzle of a
// byte, the order of its clues, the padding. They are what an observer sees,
// so it is a ChaCha8 stream with a fresh 256-bit seed, as in Xray-core. The
// receiver does not depend on them.
func newRand() (*randv2.Rand, error) {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("sudoku: seeding the random source: %w", err)
	}
	return randv2.New(randv2.NewChaCha8(seed)), nil
}
