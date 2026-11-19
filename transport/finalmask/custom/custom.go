// Package custom is the "header-custom" mask of Xray-core's finalmask: bytes
// described in the settings that both sides exchange before the data (TCP) or
// put in front of the datagrams (UDP), to make the traffic start like another
// protocol. The server needs the matching description.
//
// The bytes are a list of items. An item is one of
//
//	packet: [22, 3, 1]    these bytes; type: str, hex or base64 reads them from a string
//	rand: 8               random bytes, rand-range: 97-122 keeps them within the range
//	reuse: name           the bytes captured under the name
//	transform: {op: be16, args: [{u64: 443}]}    a computed value
//
// and may carry capture: name, which keeps its bytes, sent or received, for
// later items of either side. In TCP it may also carry delay: 10-20
// (milliseconds), alone or with a kind: what was gathered so far is sent,
// then comes the pause, then the item.
//
// A transform applies op to args, each of which is one of bytes (with type),
// u64, reuse, metadata or a nested transform. concat, slice (source, offset,
// length), pad (source, length, fill), truncate (source, length), be16, be32,
// le16, le32 and le64 yield bytes; xor16, xor32, add, sub, and, or, shl and
// shr yield a number, which has to go through be16 .. le64 to become bytes.
// metadata is a number taken from the addresses of the connection:
// local_port, remote_port, local_ip4_u32, remote_ip4_u32, and under the names
// a server would use dst_port_u16, dst_ip4_u32 (the local address) and
// src_port_u16, src_ip4_u32 (the remote one).
//
// TCP settings are clients and servers, two lists of item lists. The client
// sends clients[0], reads servers[0] and checks it, sends clients[1] and so
// on, then reads the servers that are left; after that the connection carries
// the data untouched. errors, what a server answers to a wrong client, is
// accepted and not used.
//
// UDP settings are client and server, two item lists, and mode. With "prefix"
// (the default) every datagram sent starts with the client header, and every
// datagram received has to start with the server header, which is cut off;
// other datagrams are dropped. With "standalone" the data is not changed:
// before it goes to a peer the client sends the client header as a datagram
// of its own and waits for one that is the server header; this is repeated
// when five seconds have passed.
package custom

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

func init() {
	mask.RegisterTCP("header-custom", func(settings map[string]any) (mask.TCPMask, error) {
		return NewTCP(settings)
	})
	mask.RegisterUDP("header-custom", func(settings map[string]any) (mask.UDPMask, error) {
		return NewUDP(settings)
	})
}

// The items and the transform args are decoded one by one from their own
// maps: whether a packet or bytes key is there matters even when its value
// is null, which a struct field cannot tell.

type tcpOptions struct {
	Clients [][]any `mask:"clients,omitempty"`
	Servers [][]any `mask:"servers,omitempty"`
	Errors  [][]any `mask:"errors,omitempty"`
}

type udpOptions struct {
	Mode   string `mask:"mode,omitempty"`
	Client []any  `mask:"client,omitempty"`
	Server []any  `mask:"server,omitempty"`
}

type itemOptions struct {
	Delay     mask.Range        `mask:"delay,omitempty"`
	Rand      int64             `mask:"rand,omitempty"`
	RandRange *mask.Range       `mask:"rand-range,omitempty"`
	Capture   string            `mask:"capture,omitempty"`
	Type      string            `mask:"type,omitempty"`
	Reuse     string            `mask:"reuse,omitempty"`
	Transform *transformOptions `mask:"transform,omitempty"`
	Packet    any               `mask:"packet,omitempty"`
}

type transformOptions struct {
	Op   string `mask:"op,omitempty"`
	Args []any  `mask:"args,omitempty"`
}

type argOptions struct {
	Type      string            `mask:"type,omitempty"`
	Bytes     any               `mask:"bytes,omitempty"`
	U64       any               `mask:"u64,omitempty"`
	Reuse     string            `mask:"reuse,omitempty"`
	Metadata  string            `mask:"metadata,omitempty"`
	Transform *transformOptions `mask:"transform,omitempty"`
}

// NewTCP builds the TCP mask from its settings.
func NewTCP(settings map[string]any) (*TCP, error) {
	var options tcpOptions
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	parse := func(name string, raw [][]any) ([][]item, error) {
		out := make([][]item, len(raw))
		for i := range raw {
			items, err := parseItems(raw[i])
			if err != nil {
				return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
			}
			out[i] = items
		}
		return out, nil
	}
	clients, err := parse("clients", options.Clients)
	if err != nil {
		return nil, err
	}
	servers, err := parse("servers", options.Servers)
	if err != nil {
		return nil, err
	}
	if _, err = parse("errors", options.Errors); err != nil {
		return nil, err
	}

	m := &TCP{}
	next := 0
	read := func() {
		m.steps = append(m.steps, step{read: true, name: fmt.Sprintf("servers[%d]", next), items: servers[next]})
		next++
	}
	for i := range clients {
		m.steps = append(m.steps, step{name: fmt.Sprintf("clients[%d]", i), items: clients[i]})
		if next < len(servers) {
			read()
		}
	}
	for next < len(servers) {
		read()
	}
	vars := sizes{}
	for _, st := range m.steps {
		if err := checkItems(st.items, vars, st.read); err != nil {
			return nil, fmt.Errorf("%s: %w", st.name, err)
		}
	}
	return m, nil
}

// NewUDP builds the UDP mask from its settings.
func NewUDP(settings map[string]any) (*UDP, error) {
	var options udpOptions
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &UDP{ttl: stateTTL, probeInterval: probeInterval}
	switch options.Mode {
	case "", "prefix":
	case "standalone":
		m.standalone = true
	default:
		return nil, fmt.Errorf("unknown mode %q, want prefix or standalone", options.Mode)
	}
	var err error
	if m.client, err = parseItems(options.Client); err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	if m.server, err = parseItems(options.Server); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	// The size of the server header has to be known to tell it from the data;
	// it may reuse what the client header captures. So has the size of the
	// client header in prefix mode. In standalone mode the client header is
	// only evaluated, each time from nothing.
	clientVars := sizes{}
	if m.standalone {
		if err = checkItems(m.client, sizes{}, false); err == nil {
			// its size is not needed, but tells when it can't fit a datagram
			if n, sizeErr := measure(m.client, clientVars); sizeErr == nil {
				m.clientSize = n
			}
		}
	} else if err = checkExprs(m.client, true); err == nil {
		m.clientSize, err = measure(m.client, clientVars)
	}
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	if err = checkExprs(m.server, false); err == nil {
		m.serverSize, err = measure(m.server, clientVars)
	}
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	// A header travels in a datagram. What the standalone client header
	// comes to is only known when it is evaluated, see evalItems there.
	if m.clientSize > maxDatagram || m.serverSize > maxDatagram {
		return nil, fmt.Errorf("a header of more than %d bytes does not fit a UDP datagram", maxDatagram)
	}
	return m, nil
}

// maxDatagram is the largest payload of a UDP datagram.
const maxDatagram = 65507

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func checkVarName(name string) error {
	if name != "" && !varName.MatchString(name) {
		return fmt.Errorf("invalid variable name %q", name)
	}
	return nil
}

func count(set ...bool) (n int) {
	for _, s := range set {
		if s {
			n++
		}
	}
	return n
}

var keyReplacer = strings.NewReplacer("-", "", "_", "")

// decodeMap decodes one item or transform arg and tells whether it has the
// key, be its value null or not. A null in place of the map is an empty map.
func decodeMap(v any, dst any, key string) (present bool, err error) {
	raw, ok := v.(map[string]any)
	if !ok && v != nil {
		return false, fmt.Errorf("expected a map, got %T", v)
	}
	for name := range raw {
		if strings.EqualFold(keyReplacer.Replace(name), key) {
			present = true
		}
	}
	return present, mask.Decode(raw, dst)
}

// parseBytes reads a packet or the bytes of a transform arg. As in Xray-core
// a null is no bytes whatever the type, and a missing value is no bytes for
// a list and an error for the types that are written as a string.
func parseBytes(value any, present bool, typ string) ([]byte, error) {
	switch strings.ToLower(typ) {
	case "", "array":
	case "str", "hex", "base64":
		if !present {
			return nil, fmt.Errorf("type %q without a value", typ)
		}
	default:
		return nil, fmt.Errorf("unknown type %q", typ)
	}
	if value == nil {
		return nil, nil
	}
	return mask.ParseBytes(value, typ)
}

func parseItems(raw []any) ([]item, error) {
	items := make([]item, len(raw))
	for i := range raw {
		it, err := parseItem(raw[i])
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		items[i] = it
	}
	return items, nil
}

func parseItem(raw any) (item, error) {
	var o itemOptions
	hasPacket, err := decodeMap(raw, &o, "packet")
	if err != nil {
		return item{}, err
	}
	it := item{delay: o.Delay, capture: o.Capture, reuse: o.Reuse, randMax: 255}
	if err = checkVarName(o.Capture); err != nil {
		return it, err
	}
	if err = checkVarName(o.Reuse); err != nil {
		return it, err
	}
	// A packet counts as the kind of the item even when it is null or empty:
	// such an item yields nothing, and may capture that.
	kinds := count(hasPacket, o.Rand > 0, o.Reuse != "", o.Transform != nil)
	if kinds > 1 || (kinds == 0 && o.Capture != "") {
		return it, fmt.Errorf("an item is exactly one of packet, rand, reuse and transform")
	}
	if o.Rand > math.MaxInt32 || o.Rand < math.MinInt32 {
		return it, fmt.Errorf("rand %d is not a 32 bit number", o.Rand)
	}
	if o.Rand > 0 {
		it.rand = int(o.Rand)
	}
	if r := o.RandRange; r != nil {
		if r.From < 0 || r.To > 255 {
			return it, fmt.Errorf("rand-range %s is not within 0-255", r)
		}
		it.randMin, it.randMax = byte(r.From), byte(r.To)
	}
	if it.packet, err = parseBytes(o.Packet, hasPacket, o.Type); err != nil {
		return it, fmt.Errorf("packet: %w", err)
	}
	it.expr, err = parseTransform(o.Transform)
	return it, err
}

func parseTransform(o *transformOptions) (*expr, error) {
	if o == nil {
		return nil, nil
	}
	if o.Op == "" {
		return nil, fmt.Errorf("transform op is required")
	}
	if len(o.Args) == 0 {
		return nil, fmt.Errorf("transform args are required")
	}
	e := &expr{op: o.Op, args: make([]arg, len(o.Args))}
	for i := range o.Args {
		a, err := parseArg(o.Args[i])
		if err != nil {
			return nil, fmt.Errorf("arg %d of %s: %w", i+1, o.Op, err)
		}
		e.args[i] = a
	}
	return e, nil
}

func parseArg(raw any) (arg, error) {
	var o argOptions
	hasBytes, err := decodeMap(raw, &o, "bytes")
	if err != nil {
		return arg{}, err
	}
	// As with a packet, bytes that are null or empty are still the value.
	if count(hasBytes, o.U64 != nil, o.Reuse != "", o.Metadata != "", o.Transform != nil) != 1 {
		return arg{}, fmt.Errorf("a transform arg is exactly one of bytes, u64, reuse, metadata and transform")
	}
	switch {
	case hasBytes:
		b, err := parseBytes(o.Bytes, true, o.Type)
		return arg{kind: argBytes, bytes: b}, err
	case o.U64 != nil:
		n, err := parseU64(o.U64)
		return arg{kind: argU64, u64: n}, err
	case o.Reuse != "":
		return arg{kind: argVar, name: o.Reuse}, checkVarName(o.Reuse)
	case o.Metadata != "":
		return arg{kind: argMetadata, name: o.Metadata}, nil
	}
	e, err := parseTransform(o.Transform)
	return arg{kind: argExpr, expr: e}, err
}

func parseU64(v any) (uint64, error) {
	rv := reflect.ValueOf(v)
	switch {
	case rv.CanInt() && rv.Int() >= 0:
		return uint64(rv.Int()), nil
	case rv.CanUint():
		return rv.Uint(), nil
	case rv.CanFloat():
		if f := rv.Float(); f >= 0 && f < 1<<64 && f == math.Trunc(f) {
			return uint64(f), nil
		}
	}
	return 0, fmt.Errorf("u64 must be a whole number that is not negative, got %v", v)
}

// checkItems goes over a header in the order its items are processed, with
// the sizes of the variables captured before it in vars, and rejects what
// would fail every time: a malformed transform, a variable reused before it
// is captured, a header too large to exist and, in a header that is read, an
// item whose size cannot be told in advance.
func checkItems(items []item, vars sizes, read bool) error {
	var total int64
	for i := range items {
		it := &items[i]
		err := it.checkExpr(vars, true)
		if _, ok := vars[it.reuse]; it.reuse != "" && !ok {
			err = fmt.Errorf("variable %q is reused before it is captured", it.reuse)
		}
		n := 0
		if err == nil {
			var sizeErr error
			if n, sizeErr = it.size(vars.get); read || errors.Is(sizeErr, errTooLarge) {
				err = sizeErr
			}
		}
		if total += int64(n); err == nil && total > maxSize {
			err = errTooLarge
		}
		if err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		if it.capture != "" {
			vars[it.capture] = n // 0 when the size is only known once the item is evaluated
		}
	}
	return nil
}

// checkExprs checks the transforms of a header whose variables may come from
// earlier datagrams.
func checkExprs(items []item, metadata bool) error {
	for i := range items {
		if err := items[i].checkExpr(nil, metadata); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}
