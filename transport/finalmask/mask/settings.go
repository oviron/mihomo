package mask

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/structure"
)

// decoder matches a key to a field when they are equal without dashes,
// underscores and case. Fields are tagged in kebab-case; this way the names
// Xray-core uses in JSON (maxSplit, remoteIPs, custom_table) are accepted too
// and a finalmask object copied from an Xray config works as is.
var keyReplacer = strings.NewReplacer("-", "", "_", "")

var decoder = structure.NewDecoder(structure.Option{
	TagName:          "mask",
	WeaklyTypedInput: true,
	KeyReplacer:      keyReplacer,
})

// Decode fills dst, a pointer to a struct with `mask` tags, from settings.
func Decode(settings map[string]any, dst any) error {
	if settings == nil {
		settings = map[string]any{}
	}
	if err := checkDuplicateKeys("", settings); err != nil {
		return err
	}
	return decoder.Decode(settings, dst)
}

// checkDuplicateKeys rejects two spellings of one key in the same map, such
// as max-split next to maxSplit: which of them wins would be up to chance.
func checkDuplicateKeys(path string, value any) error {
	switch v := value.(type) {
	case map[string]any:
		seen := make(map[string]string, len(v))
		for key, item := range v {
			normalized := strings.ToLower(keyReplacer.Replace(key))
			if other, ok := seen[normalized]; ok {
				return fmt.Errorf("%q and %q are the same key%s", other, key, path)
			}
			seen[normalized] = key
			if err := checkDuplicateKeys(" in "+key, item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := checkDuplicateKeys(path, item); err != nil {
				return err
			}
		}
	case []map[string]any:
		for _, item := range v {
			if err := checkDuplicateKeys(path, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// Range is a pair of bounds written as a number or as "from-to". It is the
// Int32Range of Xray-core: the bounds are ordered after parsing.
type Range struct {
	From int32
	To   int32
}

func (r *Range) UnmarshalText(text []byte) error {
	from, to, err := parseRange(string(text))
	if err != nil {
		return err
	}
	if from > to {
		from, to = to, from
	}
	if from < math.MinInt32 || to > math.MaxInt32 {
		return fmt.Errorf("range %q is out of bounds", text)
	}
	r.From, r.To = int32(from), int32(to)
	return nil
}

func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(int(r.From))
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// Rand returns a number in [From, To), or From when the range holds one or
// two numbers, as RandBetween does.
func (r Range) Rand() int64 {
	return RandBetween(int64(r.From), int64(r.To))
}

func parseRange(str string) (int, int, error) {
	str = strings.TrimSpace(str)
	if value, err := strconv.Atoi(str); err == nil {
		return value, value, nil
	}
	if str == "" {
		return 0, 0, nil
	}
	// The second number starts after the first dash that is not a sign.
	if i := strings.Index(str[1:], "-"); i >= 0 {
		left, err := strconv.Atoi(str[:i+1])
		right, err2 := strconv.Atoi(str[i+2:])
		if err == nil && err2 == nil {
			return left, right, nil
		}
	}
	return 0, 0, fmt.Errorf("invalid range %q, want a number or \"from-to\"", str)
}

// ParseRange parses "from-to" or a single number without ordering the bounds.
func ParseRange(str string) (from, to int, err error) {
	return parseRange(str)
}

// RandBetween returns a random number in [from, to). When the range holds one
// or two numbers it returns from. This is crypto.RandBetween of Xray-core,
// kept as is because the masks rely on it.
func RandBetween(from, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return from
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + n.Int64()
}

// RandBytesBetween fills b with random bytes in [from, to].
func RandBytesBetween(b []byte, from, to byte) {
	_, _ = rand.Read(b)
	if from > to {
		from, to = to, from
	}
	if to-from == 255 {
		return
	}
	for i := range b {
		b[i] = from + b[i]%(to-from+1)
	}
}

// ParseBytes reads the "packet" value of a mask. typ is "" or "array" (a list
// of byte values, or base64 text as encoding/json reads a []byte), "str",
// "hex" or "base64".
func ParseBytes(value any, typ string) ([]byte, error) {
	switch strings.ToLower(typ) {
	case "", "array":
		switch v := value.(type) {
		case nil:
			return nil, nil
		case []byte:
			return v, nil
		case string:
			return base64.StdEncoding.DecodeString(v)
		case []any:
			out := make([]byte, len(v))
			for i, item := range v {
				if item == nil {
					continue // a null is a zero byte, as encoding/json reads it
				}
				n, err := toInt(item)
				if err != nil || n < 0 || n > 255 {
					return nil, fmt.Errorf("packet[%d] is not a byte: %v", i, item)
				}
				out[i] = byte(n)
			}
			return out, nil
		}
		return nil, fmt.Errorf("packet must be a list of bytes, got %T", value)
	case "str":
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("packet of type str must be a string, got %T", value)
		}
		return []byte(s), nil
	case "hex":
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("packet of type hex must be a string, got %T", value)
		}
		return hex.DecodeString(s)
	case "base64":
		s, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("packet of type base64 must be a string, got %T", value)
		}
		return base64.StdEncoding.DecodeString(s)
	default:
		return nil, fmt.Errorf("unknown packet type %q", typ)
	}
}

func toInt(value any) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		return int64(v), nil
	case float32:
		if v != float32(int64(v)) {
			return 0, fmt.Errorf("not an integer")
		}
		return int64(v), nil
	case float64:
		if v != float64(int64(v)) {
			return 0, fmt.Errorf("not an integer")
		}
		return int64(v), nil
	}
	return 0, fmt.Errorf("not a number")
}

// BufferSize is the size of the buffers the UDP masks read datagrams into:
// the largest UDP datagram. A masked datagram can be several times what the
// caller's buffer holds, and one that is cut short may still decode, into
// something shorter than what was sent.
const BufferSize = 65535

// GetBuffer returns a buffer of BufferSize bytes, to be given back with PutBuffer.
func GetBuffer() []byte {
	return pool.Get(BufferSize)
}

func PutBuffer(buf []byte) {
	_ = pool.Put(buf)
}
