package custom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

// maxSize is the largest header, in bytes: what a slice can hold on every
// platform. Sizes are added up and compared with it before anything is
// allocated, so that a header that cannot exist is an error and not a panic.
const maxSize = math.MaxInt32

var errTooLarge = fmt.Errorf("larger than the %d bytes a header may have", maxSize)

// appendBytes is append that keeps a header within maxSize.
func appendBytes(dst, b []byte) ([]byte, error) {
	if len(b) > maxSize-len(dst) {
		return nil, errTooLarge
	}
	return append(dst, b...), nil
}

// item is one piece of a header. At most one of rand, packet, reuse and expr
// is set; an item with none of them yields nothing.
type item struct {
	delay            mask.Range // TCP: flush and wait this long, in milliseconds, before the item
	rand             int        // that many random bytes within randMin..randMax, at most maxSize
	randMin, randMax byte
	packet           []byte
	reuse            string // the value of a captured variable
	expr             *expr
	capture          string // keep the bytes of the item under this name
}

// expr is a transform: an operation over arguments.
type expr struct {
	op   string
	args []arg
}

type argKind int

const (
	argBytes argKind = iota
	argU64
	argVar
	argMetadata
	argExpr
)

type arg struct {
	kind  argKind
	bytes []byte
	u64   uint64
	name  string // the variable or the metadata key
	expr  *expr
}

// value is what a transform or an argument yields: bytes or a number. Which
// of them is known from the operation, see check.
type value struct {
	bytes []byte
	u64   uint64
}

// operations lists, for every operation, its arguments ('b' bytes, 'n' a
// number, "*" any number of bytes) and whether it yields bytes.
var operations = map[string]struct {
	args  string
	bytes bool
}{
	"concat":   {"*", true},
	"slice":    {"bnn", true}, // source, offset, length
	"pad":      {"bnb", true}, // source, length, fill
	"truncate": {"bn", true},  // source, length
	"be16":     {"n", true},
	"be32":     {"n", true},
	"le16":     {"n", true},
	"le32":     {"n", true},
	"le64":     {"n", true},
	"xor16":    {"nn", false},
	"xor32":    {"nn", false},
	"add":      {"nn", false},
	"sub":      {"nn", false},
	"and":      {"nn", false},
	"or":       {"nn", false},
	"shl":      {"nn", false},
	"shr":      {"nn", false},
}

// metadataKeys tells for every metadata name whether it is taken from the
// remote address. The src_ and dst_ names are those of a server looking at a
// client: src is the remote address and dst the local one, on a client too.
var metadataKeys = map[string]bool{
	"local_port":     false,
	"local_ip4_u32":  false,
	"dst_port_u16":   false,
	"dst_ip4_u32":    false,
	"remote_port":    true,
	"remote_ip4_u32": true,
	"src_port_u16":   true,
	"src_ip4_u32":    true,
}

// sizes holds the lengths of the variables captured so far when a header is
// measured without being evaluated.
type sizes map[string]int

func (s sizes) get(name string) (int, bool) {
	n, ok := s[name]
	return n, ok
}

// scope is what items are evaluated in: the captured variables and the
// addresses of the connection, which the metadata comes from.
type scope struct {
	vars          map[string][]byte
	local, remote net.Addr
}

func (s *scope) varSize(name string) (int, bool) {
	v, ok := s.vars[name]
	return len(v), ok
}

func (s *scope) metadata(key string) (uint64, error) {
	remote, ok := metadataKeys[key]
	if !ok {
		return 0, fmt.Errorf("unknown metadata %q", key)
	}
	addr, side := s.local, "local"
	if remote {
		addr, side = s.remote, "remote"
	}
	var ip net.IP
	port := -1
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a != nil {
			ip, port = a.IP, a.Port
		}
	case *net.UDPAddr:
		if a != nil {
			ip, port = a.IP, a.Port
		}
	}
	if port < 0 {
		return 0, fmt.Errorf("metadata %s needs the %s TCP or UDP address of the connection, which is not known here (%T)", key, side, addr)
	}
	if strings.Contains(key, "_port") {
		return uint64(port), nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("metadata %s: the %s address %s is not IPv4", key, side, addr)
	}
	return uint64(binary.BigEndian.Uint32(ip4)), nil
}

// check verifies the name of the operation and the number and the types of
// its arguments, and reports whether the transform yields bytes. With vars
// not nil a variable has to be captured before it is reused. metadata tells
// whether the addresses of the connection will be known.
func (e *expr) check(vars sizes, metadata bool) (isBytes bool, err error) {
	sig, ok := operations[e.op]
	if !ok {
		return false, fmt.Errorf("unknown transform op %q", e.op)
	}
	if sig.args != "*" && len(e.args) != len(sig.args) {
		return false, fmt.Errorf("%s takes %d args, got %d", e.op, len(sig.args), len(e.args))
	}
	for i, a := range e.args {
		got := false
		switch a.kind {
		case argBytes:
			got = true
		case argVar:
			got = true
			if _, ok := vars[a.name]; vars != nil && !ok {
				return false, fmt.Errorf("variable %q is reused before it is captured", a.name)
			}
		case argMetadata:
			if _, ok := metadataKeys[a.name]; !ok {
				return false, fmt.Errorf("unknown metadata %q", a.name)
			}
			if !metadata {
				return false, fmt.Errorf("metadata %q: a header that is read from a datagram is checked without the addresses", a.name)
			}
		case argExpr:
			if got, err = a.expr.check(vars, metadata); err != nil {
				return false, err
			}
		}
		if want := sig.args == "*" || sig.args[i] == 'b'; got != want {
			if want {
				return false, fmt.Errorf("arg %d of %s must be bytes, not a number", i+1, e.op)
			}
			return false, fmt.Errorf("arg %d of %s must be a number, not bytes", i+1, e.op)
		}
	}
	return sig.bytes, nil
}

// checkExpr is check for the transform of an item, which has to yield bytes.
func (it *item) checkExpr(vars sizes, metadata bool) error {
	if it.expr == nil {
		return nil
	}
	isBytes, err := it.expr.check(vars, metadata)
	if err == nil && !isBytes {
		err = fmt.Errorf("%s yields a number, wrap it in be16, be32, le16, le32 or le64", it.expr.op)
	}
	return err
}

// packWidth is the number of bytes be16 .. le64 produce, 0 for other operations.
func packWidth(op string) int {
	switch op {
	case "be16", "le16":
		return 2
	case "be32", "le32":
		return 4
	case "le64":
		return 8
	}
	return 0
}

// eval computes the transform. check has passed, so the arguments are of the
// right number and types.
func (e *expr) eval(s *scope) (value, error) {
	args := make([]value, len(e.args))
	for i := range e.args {
		v, err := e.args[i].eval(s)
		if err != nil {
			return value{}, err
		}
		args[i] = v
	}
	var out []byte
	switch e.op {
	case "concat":
		for _, a := range args {
			var err error
			if out, err = appendBytes(out, a.bytes); err != nil {
				return value{}, fmt.Errorf("concat: %w", err)
			}
		}
	case "slice":
		src, offset, length := args[0].bytes, args[1].u64, args[2].u64
		if end := offset + length; end < offset || end > uint64(len(src)) {
			return value{}, fmt.Errorf("slice out of bounds")
		}
		out = src[offset : offset+length]
	case "truncate":
		src, length := args[0].bytes, args[1].u64
		if length > uint64(len(src)) {
			return value{}, fmt.Errorf("truncate out of bounds")
		}
		out = src[:length]
	case "pad":
		src, length, fill := args[0].bytes, args[1].u64, args[2].bytes
		if len(fill) == 0 {
			return value{}, fmt.Errorf("pad fill must not be empty")
		}
		if length < uint64(len(src)) {
			return value{}, fmt.Errorf("pad target shorter than source")
		}
		if length > maxSize {
			return value{}, fmt.Errorf("pad: %w", errTooLarge)
		}
		out = make([]byte, length)
		for at := copy(out, src); at < len(out); {
			at += copy(out[at:], fill)
		}
	case "be16", "be32", "le16", "le32", "le64":
		v, width := args[0].u64, packWidth(e.op)
		if width < 8 && v>>(8*width) != 0 {
			return value{}, fmt.Errorf("%s overflow", e.op)
		}
		out = make([]byte, width)
		for i := range out {
			if e.op[0] == 'b' {
				out[i] = byte(v >> (8 * (width - 1 - i)))
			} else {
				out[i] = byte(v >> (8 * i))
			}
		}
	default:
		n, err := e.evalNumber(args[0].u64, args[1].u64)
		return value{u64: n}, err
	}
	return value{bytes: out}, nil
}

// evalNumber computes the operations that take two numbers and yield one.
func (e *expr) evalNumber(l, r uint64) (uint64, error) {
	switch e.op {
	case "xor16", "xor32":
		limit := uint64(0xFFFF)
		if e.op == "xor32" {
			limit = 0xFFFFFFFF
		}
		if l > limit || r > limit {
			return 0, fmt.Errorf("%s overflow", e.op)
		}
		return l ^ r, nil
	case "add":
		if l > ^uint64(0)-r {
			return 0, fmt.Errorf("add overflow")
		}
		return l + r, nil
	case "sub":
		if l < r {
			return 0, fmt.Errorf("sub underflow")
		}
		return l - r, nil
	case "and":
		return l & r, nil
	case "or":
		return l | r, nil
	}
	// shl, shr
	if r >= 64 {
		return 0, fmt.Errorf("shift out of range")
	}
	if e.op == "shr" {
		return l >> r, nil
	}
	if l > ^uint64(0)>>r {
		return 0, fmt.Errorf("shl overflow")
	}
	return l << r, nil
}

func (a *arg) eval(s *scope) (value, error) {
	switch a.kind {
	case argBytes:
		return value{bytes: a.bytes}, nil
	case argU64:
		return value{u64: a.u64}, nil
	case argVar:
		saved, ok := s.vars[a.name]
		if !ok {
			return value{}, fmt.Errorf("unknown variable %q", a.name)
		}
		return value{bytes: saved}, nil
	case argMetadata:
		n, err := s.metadata(a.name)
		return value{u64: n}, err
	default:
		return a.expr.eval(s)
	}
}

// size is the length of what the transform yields, told without evaluating
// it. That is how the reading side learns how much to take, so a length has
// to be written as a plain number there.
func (e *expr) size(varSize func(string) (int, bool)) (int, error) {
	if width := packWidth(e.op); width > 0 {
		return width, nil
	}
	length := -1
	switch e.op {
	case "concat":
		var total int64
		for _, a := range e.args {
			n := len(a.bytes)
			switch a.kind {
			case argVar:
				var ok bool
				if n, ok = varSize(a.name); !ok {
					return 0, fmt.Errorf("unknown variable %q", a.name)
				}
			case argExpr:
				var err error
				if n, err = a.expr.size(varSize); err != nil {
					return 0, err
				}
			}
			if total += int64(n); total > maxSize {
				return 0, fmt.Errorf("concat: %w", errTooLarge)
			}
		}
		return int(total), nil
	case "slice":
		length = 2
	case "pad", "truncate":
		length = 1
	}
	if length < 0 || length >= len(e.args) {
		return 0, fmt.Errorf("%s does not yield bytes", e.op)
	}
	a := e.args[length]
	if a.kind != argU64 {
		return 0, fmt.Errorf("the length of %s must be a plain u64 for the header to be measured", e.op)
	}
	if a.u64 > maxSize {
		return 0, fmt.Errorf("%s: %w", e.op, errTooLarge)
	}
	return int(a.u64), nil
}

// eval produces the bytes of the item on the writing side.
func (it *item) eval(s *scope) ([]byte, error) {
	var out []byte
	switch {
	case it.rand > 0:
		out = make([]byte, it.rand)
		mask.RandBytesBetween(out, it.randMin, it.randMax)
	case len(it.packet) > 0:
		out = it.packet
	case it.reuse != "":
		saved, ok := s.vars[it.reuse]
		if !ok {
			return nil, fmt.Errorf("unknown variable %q", it.reuse)
		}
		out = saved
	case it.expr != nil:
		v, err := it.expr.eval(s)
		if err != nil {
			return nil, err
		}
		out = v.bytes
	}
	if it.capture != "" {
		s.vars[it.capture] = out
	}
	return out, nil
}

// size is the number of bytes the item takes on the reading side.
func (it *item) size(varSize func(string) (int, bool)) (int, error) {
	switch {
	case it.rand > 0:
		return it.rand, nil
	case len(it.packet) > 0:
		return len(it.packet), nil
	case it.reuse != "":
		n, ok := varSize(it.reuse)
		if !ok {
			return 0, fmt.Errorf("unknown variable %q", it.reuse)
		}
		return n, nil
	case it.expr != nil:
		return it.expr.size(varSize)
	}
	return 0, nil
}

// match checks the bytes read for the item and captures them. Random bytes
// match anything, the other kinds have to be equal to what the item says.
func (it *item) match(data []byte, s *scope) error {
	var want []byte
	switch {
	case it.rand > 0:
		want = data
	case len(it.packet) > 0:
		want = it.packet
	case it.reuse != "":
		want = s.vars[it.reuse]
	case it.expr != nil:
		v, err := it.expr.eval(s)
		if err != nil {
			return err
		}
		want = v.bytes
	}
	if !bytes.Equal(want, data) {
		return fmt.Errorf("got %x, want %x", data, want)
	}
	if it.capture != "" {
		s.vars[it.capture] = append([]byte(nil), data...)
	}
	return nil
}

// evalItems produces a whole header.
func evalItems(items []item, s *scope) ([]byte, error) {
	var out []byte
	for i := range items {
		b, err := items[i].eval(s)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		if out, err = appendBytes(out, b); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// matchItems checks a header that starts data, item by item.
func matchItems(items []item, data []byte, s *scope) error {
	for i := range items {
		n, err := items[i].size(s.varSize)
		if err == nil && n > len(data) {
			err = fmt.Errorf("the datagram is too short")
		}
		if err == nil {
			err = items[i].match(data[:n], s)
		}
		if err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		data = data[n:]
	}
	return nil
}

// measure adds up the sizes of the items of a header without evaluating it
// and records in vars the sizes of the variables it captures. Items that
// cannot be measured are left out; the first such error is returned.
func measure(items []item, vars sizes) (int, error) {
	var total int64
	var err error
	for i := range items {
		n, itemErr := items[i].size(vars.get)
		if itemErr != nil {
			if err == nil {
				err = fmt.Errorf("item %d: %w", i, itemErr)
			}
			continue
		}
		if total += int64(n); total > maxSize {
			return 0, errTooLarge
		}
		if items[i].capture != "" {
			vars[items[i].capture] = n
		}
	}
	return int(total), err
}

func cloneVars(vars map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(vars))
	for name, v := range vars {
		out[name] = v
	}
	return out
}
