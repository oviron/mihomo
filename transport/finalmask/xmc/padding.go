package xmc

import (
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

// After the login the two sides take turns sending padding, 39 in all, sized
// after what a Minecraft 26.1.2 client and server exchange until the player
// is in the world: the configuration state, the registries, the start of the
// play state and the join that follows. A turn is one record: its own length
// as a varint, then zero bytes up to that length. Everything is encrypted, so
// the content does not show. The numbers below are Xray-core's.

// delayRange is a pause of a random length between min and max.
type delayRange struct {
	min, max time.Duration
}

func milliseconds(lo, hi int) delayRange {
	return delayRange{time.Duration(lo) * time.Millisecond, time.Duration(hi) * time.Millisecond}
}

func (d delayRange) rand() time.Duration {
	return time.Duration(randInclusive(int64(d.min), int64(d.max)))
}

// randInclusive returns a random number from lo to hi, both included.
func randInclusive(lo, hi int64) int64 {
	return mask.RandBetween(lo, hi+1)
}

// turn is one step of the padding exchange.
type turn struct {
	fromClient bool
	// prefix is the size of the packet that was sent ahead of the record and
	// counts as the beginning of the turn.
	prefix int
	// A turn either follows one of the templates, each the sizes of the
	// writes its record is sent in, or is of any length from min to max.
	templates [][]int
	min, max  int
	// startDelay is the pause before a turn of the client.
	startDelay delayRange
}

// clientChunk is the largest write of a client turn that follows no template.
const clientChunk = 1024

// loginTurns stand for the configuration state and the start of the play
// state. They follow templates: write sizes taken from real logins. The first
// turn begins with the Login Acknowledged packet, 2 bytes.
var loginTurns = []turn{
	{fromClient: true, prefix: 2, templates: [][]int{{26, 16}}},
	{templates: [][]int{{26, 21, 25}}},
	{fromClient: true, templates: [][]int{{25}}, startDelay: milliseconds(2, 22)},
	{templates: [][]int{{ // the registries
		1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118, 1038, 970,
		400, 239, 49, 50, 95, 65, 104, 32320, 2,
	}}},
	{fromClient: true, templates: [][]int{{2}}, startDelay: milliseconds(10, 35)},
	{templates: [][]int{ // the start of the play state
		{4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346},
		{4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390},
		{4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221, 352},
		{4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352},
		{4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325},
		{4941, 259, 270, 274, 263, 258, 327, 170, 210, 375},
		{4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352},
		{4941, 252, 273, 262, 252, 254, 306, 93},
		{4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438},
		{4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393},
		{4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8},
		{4941, 259, 269, 272, 261, 313, 207, 213, 500, 19},
		{4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431},
		{4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413},
		{4941, 215, 251, 249, 317, 260, 270, 249, 52},
		{4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352},
		{4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378},
		{4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8},
		{4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393},
		{4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352},
	}},
}

// joinLengths are the bounds of the turns that stand for joining the world,
// the client's and the server's alternating, the client's first.
var joinLengths = [][2]int{
	{6, 883}, {346, 58638}, {6, 887}, {388, 61077}, {2, 50}, {575, 65584}, {6, 45}, {86, 63563},
	{2, 44}, {42, 51983}, {2, 851}, {309, 25083}, {2, 19}, {74, 63885}, {8, 24}, {30, 66128},
	{2, 19}, {26, 35818}, {6, 19}, {35, 59407}, {6, 19}, {37, 65328}, {2, 19}, {26, 60622},
	{6, 19}, {11, 60808}, {8, 43}, {55, 62027}, {2, 19}, {427, 65622}, {5, 19}, {35, 59401},
	{6, 19},
}

// clientBursts are the three join turns of which a real client makes exactly
// one long. The client picks which when the connection starts, by weight, and
// keeps the other two within their regular bounds.
var clientBursts = []struct {
	join           int // index in joinLengths
	regular, burst [2]int
	weight         int
}{
	{join: 0, regular: [2]int{6, 44}, burst: [2]int{877, 883}, weight: 17},
	{join: 2, regular: [2]int{6, 45}, burst: [2]int{884, 887}, weight: 2},
	{join: 10, regular: [2]int{2, 19}, burst: [2]int{851, 851}, weight: 1},
}

var schedule = buildSchedule()

func buildSchedule() []turn {
	turns := append([]turn(nil), loginTurns...)
	for i, bounds := range joinLengths {
		t := turn{fromClient: i%2 == 0, min: bounds[0], max: bounds[1]}
		if t.fromClient {
			t.startDelay = milliseconds(1, 30)
		}
		turns = append(turns, t)
	}
	return turns
}

// pickBurst chooses the entry of clientBursts that is long in a connection.
func pickBurst() int {
	total := 0
	for _, b := range clientBursts {
		total += b.weight
	}
	n := int(mask.RandBetween(0, int64(total)))
	for i, b := range clientBursts {
		if n < b.weight {
			return i
		}
		n -= b.weight
	}
	return 0
}

// clientChunks picks the sizes of the writes the client sends the record of
// the given turn in.
func clientChunks(index, burst int) []int {
	t := &schedule[index]
	if len(t.templates) > 0 {
		return t.templates[mask.RandBetween(0, int64(len(t.templates)))]
	}
	bounds := [2]int{t.min, t.max}
	for i, b := range clientBursts {
		if len(loginTurns)+b.join == index {
			bounds = b.regular
			if i == burst {
				bounds = b.burst
			}
		}
	}
	var chunks []int
	for length := int(randInclusive(int64(bounds[0]), int64(bounds[1]))); length > 0; {
		n := length
		if n > clientChunk {
			n = clientChunk
		}
		chunks = append(chunks, n)
		length -= n
	}
	return chunks
}

// accepts tells whether a turn may have the given length.
func (t *turn) accepts(length int) bool {
	if len(t.templates) == 0 {
		return length >= t.min && length <= t.max
	}
	for _, template := range t.templates {
		total := t.prefix
		for _, n := range template {
			total += n
		}
		if total == length {
			return true
		}
	}
	return false
}

// writePadding sends a padding record, one write per chunk.
func (w *wire) writePadding(chunks []int) error {
	length := 0
	for _, n := range chunks {
		length += n
	}
	header := appendVarint(nil, int32(length))
	if len(chunks) == 0 || chunks[0] < len(header) {
		return errors.New("the first chunk is shorter than the header")
	}
	for i, n := range chunks {
		if cap(w.out) < n {
			w.out = make([]byte, n)
		}
		w.out = w.out[:n]
		for j := range w.out {
			w.out[j] = 0
		}
		if i == 0 {
			copy(w.out, header)
		}
		if err := w.write(); err != nil {
			return err
		}
	}
	return nil
}

// readPadding reads the record of a turn of the server and checks its length.
func (w *wire) readPadding(t *turn) error {
	length, size, err := readVarint(w.readByte)
	if err != nil {
		return err
	}
	if int(length) < size || !t.accepts(t.prefix+int(length)) {
		return fmt.Errorf("unexpected length %d", length)
	}
	return w.discard(int(length) - size)
}
