package custom

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type obj = map[string]any

func u64(n any) obj                     { return obj{"u64": n} }
func meta(name string) obj              { return obj{"metadata": name} }
func reuse(name string) obj             { return obj{"reuse": name} }
func raw(b ...any) obj                  { return obj{"bytes": b} }
func nested(op string, args ...obj) obj { return obj{"transform": tr(op, args...)["transform"]} }

// tr is an item made of a transform.
func tr(op string, args ...obj) obj {
	list := make([]any, len(args))
	for i, a := range args {
		list[i] = a
	}
	return obj{"transform": obj{"op": op, "args": list}}
}

// evalHeader evaluates a header the way a standalone client does.
func evalHeader(t *testing.T, s *scope, items ...any) ([]byte, error) {
	t.Helper()
	m, err := NewUDP(obj{"mode": "standalone", "client": items})
	require.NoError(t, err)
	if s == nil {
		s = &scope{}
	}
	s.vars = map[string][]byte{}
	return evalItems(m.client, s)
}

func TestTransforms(t *testing.T) {
	for name, c := range map[string]struct {
		item obj
		want []byte
	}{
		"be16 of xor16": {tr("be16", nested("xor16", u64(0x1234), u64(0xFFFF))), []byte{0xED, 0xCB}},
		"be32 of xor32": {tr("be32", nested("xor32", u64(0x12345678), u64(uint32(0xFFFFFFFF)))), []byte{0xED, 0xCB, 0xA9, 0x87}},
		"little endian": {
			tr("concat", nested("le16", u64(0x1234)), nested("le32", u64(uint32(0xA1B2C3D4))), nested("le64", u64(uint64(0x0102030405060708)))),
			[]byte{0x34, 0x12, 0xD4, 0xC3, 0xB2, 0xA1, 8, 7, 6, 5, 4, 3, 2, 1},
		},
		"le64 of the largest number": {tr("le64", u64(uint64(1<<64-1))), []byte{255, 255, 255, 255, 255, 255, 255, 255}},
		"pad and truncate": {
			tr("concat", nested("pad", raw(0xAA, 0xBB), u64(5), raw(0xCC, 0xDD)), nested("truncate", raw(1, 2, 3, 4), u64(2))),
			[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xCC, 1, 2},
		},
		"pad to the same length": {tr("pad", raw(1, 2), u64(2), raw(9)), []byte{1, 2}},
		"arithmetic": {
			tr("concat",
				nested("be16", nested("add", u64(1), u64(2))),
				nested("be16", nested("sub", u64(10), u64(3))),
				nested("be16", nested("and", u64(0xF0F0), u64(0x0FF0))),
				nested("be16", nested("or", nested("shl", u64(1), u64(8)), nested("shr", u64(0x80), u64(7))))),
			[]byte{0, 3, 0, 7, 0, 0xF0, 1, 1},
		},
		"slice":              {tr("slice", raw(1, 2, 3, 4), u64(1), u64(2)), []byte{2, 3}},
		"computed length":    {tr("slice", raw(1, 2, 3, 4), u64(0), nested("add", u64(1), u64(2))), []byte{1, 2, 3}},
		"concat keeps order": {tr("concat", obj{"bytes": "ab", "type": "str"}, obj{"bytes": "6364", "type": "hex"}, obj{"bytes": "ZWY=", "type": "base64"}), []byte("abcdef")},
	} {
		got, err := evalHeader(t, nil, c.item)
		require.NoError(t, err, name)
		require.Equal(t, c.want, got, name)
	}

	for name, item := range map[string]obj{
		"pad with an empty fill":    tr("pad", raw(0xAA), u64(4), obj{"bytes": []any{}}),
		"pad shorter than source":   tr("pad", raw(1, 2, 3), u64(2), raw(0)),
		"pad too large":             tr("pad", raw(1), nested("shl", u64(1), u64(40)), raw(0)),
		"truncate out of bounds":    tr("truncate", raw(1, 2), u64(3)),
		"slice out of bounds":       tr("slice", raw(1, 2, 3), u64(2), u64(2)),
		"slice offset wraps around": tr("slice", raw(1, 2, 3), u64(uint64(1<<64-1)), u64(2)),
		"sub underflow":             tr("be16", nested("sub", u64(1), u64(2))),
		"add overflow":              tr("le64", nested("add", u64(uint64(1<<64-1)), u64(1))),
		"shift out of range":        tr("be16", nested("shl", u64(1), u64(64))),
		"shr out of range":          tr("be16", nested("shr", u64(1), u64(64))),
		"shl overflow":              tr("le64", nested("shl", u64(3), u64(63))),
		"be16 overflow":             tr("be16", u64(0x10000)),
		"le32 overflow":             tr("le32", u64(uint64(1<<32))),
		"xor16 overflow":            tr("be32", nested("xor16", u64(0x10000), u64(1))),
		"xor32 overflow":            tr("le64", nested("xor32", u64(1), u64(uint64(1<<32)))),
	} {
		_, err := evalHeader(t, nil, item)
		require.Error(t, err, name)
	}
}

func TestItems(t *testing.T) {
	// A captured value is reused within the header and stays in the scope.
	s := &scope{}
	got, err := evalHeader(t, s,
		obj{"rand": 4, "randRange": "42-42", "capture": "txid"},
		obj{"reuse": "txid"},
		obj{"packet": "-", "type": "str"},
		tr("concat", reuse("txid"), raw(0)),
		obj{}, // an item of no kind yields nothing
	)
	require.NoError(t, err)
	require.Equal(t, []byte("********-****\x00"), got)
	require.Equal(t, []byte("****"), s.vars["txid"])

	// A packet and bytes that are null are there and empty.
	s = &scope{}
	got, err = evalHeader(t, s, obj{"packet": nil, "capture": "e"}, tr("concat", reuse("e"), obj{"bytes": nil}, raw(7)), obj{"reuse": "e"})
	require.NoError(t, err)
	require.Equal(t, []byte{7}, got)
	require.Contains(t, s.vars, "e")
	require.Empty(t, s.vars["e"])

	// rand-range bounds the random bytes, by default they are any.
	got, err = evalHeader(t, nil, obj{"rand": 4096, "rand-range": "97-99"}, obj{"rand": 4096})
	require.NoError(t, err)
	require.Len(t, got, 8192)
	seen := map[byte]bool{}
	for _, b := range got[:4096] {
		require.Contains(t, []byte("abc"), b)
		seen[b] = true
	}
	require.Len(t, seen, 3)
	seen = map[byte]bool{}
	for _, b := range got[4096:] {
		seen[b] = true
	}
	require.Greater(t, len(seen), 200)

	// The four spellings of a packet.
	got, err = evalHeader(t, nil,
		obj{"packet": []any{1, 2}},
		obj{"packet": []any{3}, "type": "array"},
		obj{"packet": "45", "type": "str"},
		obj{"packet": "0607", "type": "hex"},
		obj{"packet": "CAk=", "type": "base64"},
	)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, '4', '5', 6, 7, 8, 9}, got)
}

func TestMetadata(t *testing.T) {
	udp := &scope{
		local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 3478},
		remote: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 54321},
	}
	tcp := &scope{
		local:  &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1).To4(), Port: 3478},
		remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9).To4(), Port: 54321},
	}
	pair := func(port, ip string) obj {
		return tr("concat", nested("be16", meta(port)), nested("be32", meta(ip)))
	}
	for _, s := range []*scope{udp, tcp} {
		for _, names := range [][2]string{{"remote_port", "remote_ip4_u32"}, {"src_port_u16", "src_ip4_u32"}} {
			got, err := evalHeader(t, s, pair(names[0], names[1]))
			require.NoError(t, err)
			require.Equal(t, []byte{0xD4, 0x31, 203, 0, 113, 9}, got, names[0])
		}
		for _, names := range [][2]string{{"local_port", "local_ip4_u32"}, {"dst_port_u16", "dst_ip4_u32"}} {
			got, err := evalHeader(t, s, pair(names[0], names[1]))
			require.NoError(t, err)
			require.Equal(t, []byte{0x0D, 0x96, 10, 0, 0, 1}, got, names[0])
		}
	}

	// The port of an IPv6 address is known, its IPv4 form is not.
	v6 := &scope{local: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 7}, remote: &net.UDPAddr{IP: net.IPv6loopback, Port: 9}}
	got, err := evalHeader(t, v6, tr("be16", meta("local_port")))
	require.NoError(t, err)
	require.Equal(t, []byte{0, 7}, got)
	_, err = evalHeader(t, v6, tr("be32", meta("local_ip4_u32")))
	require.ErrorContains(t, err, "not IPv4")

	// Without TCP or UDP addresses there is no metadata.
	for _, s := range []*scope{{}, {remote: (*net.UDPAddr)(nil)}, {remote: &net.UnixAddr{Name: "x"}}} {
		_, err = evalHeader(t, s, tr("be16", meta("remote_port")))
		require.ErrorContains(t, err, "metadata remote_port")
	}
}

func TestSettings(t *testing.T) {
	item := func(i obj) obj { return obj{"client": []any{i}} }
	for name, settings := range map[string]obj{
		"unknown mode":               {"mode": "suffix"},
		"mode is case sensitive":     {"mode": "Standalone"},
		"two kinds":                  item(obj{"rand": 2, "reuse": "a"}),
		"empty packet is a kind":     item(obj{"packet": []any{}, "rand": 2}),
		"capture of nothing":         item(obj{"capture": "a"}),
		"bad capture name":           item(obj{"rand": 2, "capture": "1a"}),
		"bad reuse name":             item(obj{"reuse": "a-b"}),
		"rand-range above 255":       item(obj{"rand": 2, "rand-range": "0-256"}),
		"rand-range below 0":         item(obj{"rand": 2, "rand-range": "-1-5"}),
		"rand-range of another kind": item(obj{"packet": []any{1}, "rand-range": "300-400"}),
		"rand of more than 32 bits":  item(obj{"rand": int64(1) << 31}),
		"null packet and a kind":     item(obj{"packet": nil, "rand": 2}),
		"type of nothing":            item(obj{"delay": 5, "type": "hex"}),
		"unknown type of nothing":    item(obj{"rand": 2, "type": "octal"}),
		"an item that is no map":     {"client": []any{"rand"}},
		"null bytes and a number":    item(tr("be16", obj{"bytes": nil, "u64": 1})),
		"an arg that is no map":      item(obj{"transform": obj{"op": "be16", "args": []any{1}}}),
		"a null arg":                 item(obj{"transform": obj{"op": "be16", "args": []any{nil}}}),
		"unknown packet type":        item(obj{"packet": "00", "type": "octal"}),
		"type without a packet":      item(obj{"rand": 2, "type": "str"}),
		"bad hex":                    item(obj{"packet": "0g", "type": "hex"}),
		"not a byte":                 item(obj{"packet": []any{256}}),
		"transform without op":       item(obj{"transform": obj{"args": []any{u64(1)}}}),
		"transform without args":     item(obj{"transform": obj{"op": "concat"}}),
		"arg of two kinds":           item(tr("be16", obj{"u64": 1, "metadata": "local_port"})),
		"arg of no kind":             item(tr("be16", obj{"type": "hex"})),
		"negative u64":               item(tr("be16", u64(-1))),
		"fractional u64":             item(tr("be16", u64(1.5))),
		"bad name in an arg":         item(tr("concat", reuse("a b"))),
		"bad nested transform":       item(tr("be16", obj{"transform": obj{"op": "add"}})),
		// what Xray-core finds out only when the header is used
		"unknown op":                   item(tr("be24", u64(1))),
		"op is case sensitive":         item(tr("BE16", u64(1))),
		"too few args":                 item(tr("slice", raw(1, 2), u64(0))),
		"too many args":                item(tr("be16", u64(1), u64(2))),
		"number where bytes go":        item(tr("concat", raw(1), u64(2))),
		"bytes where a number goes":    item(tr("be16", raw(1))),
		"variable where a number goes": {"client": []any{obj{"rand": 2, "capture": "a"}, tr("be16", reuse("a"))}},
		"metadata where bytes go":      item(tr("concat", meta("local_port"))),
		"nested type mismatch":         item(tr("be16", nested("concat", raw(1)))),
		"a number is not a header":     item(tr("xor16", u64(1), u64(2))),
		"unknown metadata":             item(tr("be16", meta("local_ip6"))),
		"prefix: unknown variable":     item(obj{"reuse": "a"}),
		"prefix: unknown in concat":    item(tr("concat", reuse("a"))),
		"prefix: computed length":      item(tr("slice", raw(1, 2), u64(0), nested("add", u64(1), u64(1)))),
		"prefix: length too large":     item(tr("truncate", raw(1, 2), u64(uint64(1<<63)))),
		"prefix: header too large":     {"client": []any{obj{"rand": 1 << 30}, obj{"rand": 1 << 30}}},
		"standalone: length too large": {"mode": "standalone", "client": []any{tr("pad", raw(1), u64(uint64(1<<31)), raw(0))}},
		"standalone: header too large": {"mode": "standalone", "client": []any{obj{"rand": 1 << 30}, obj{"rand": 1 << 30}}},
		"standalone: unknown variable": {"mode": "standalone", "client": []any{tr("slice", reuse("a"), u64(0), u64(1))}},
		"server: unknown variable":     {"server": []any{obj{"reuse": "a"}}},
		"server: computed length":      {"server": []any{tr("pad", raw(1), nested("add", u64(1), u64(1)), raw(0))}},
		"server: metadata":             {"server": []any{tr("be16", meta("remote_port"))}},
		"server: size of a client variable is unknown": {"mode": "standalone",
			"client": []any{obj{"transform": tr("slice", raw(1, 2), u64(0), nested("add", u64(1), u64(1)))["transform"], "capture": "a"}},
			"server": []any{obj{"reuse": "a"}}},
		"same key twice": {"client": []any{obj{"rand": 2, "rand-range": "1-2", "randRange": "1-2"}}},
	} {
		_, err := NewUDP(settings)
		require.Error(t, err, name)
	}

	for name, settings := range map[string]obj{
		"empty":      {},
		"standalone": {"mode": "standalone", "client": []any{obj{"rand": 4, "capture": "a"}}, "server": []any{obj{"reuse": "a"}, tr("concat", reuse("a"))}},
		// In prefix mode a variable may come from a datagram received earlier,
		// as long as the size of the header does not depend on it.
		"prefix: variable of the server": {
			"client": []any{tr("slice", reuse("s"), u64(0), u64(2))},
			"server": []any{obj{"rand": 4, "capture": "s"}},
		},
		"delay is ignored": {"client": []any{obj{"rand": 4, "delay": "10-20"}}},
		"negative rand":    {"client": []any{obj{"rand": -4}}},
		// What Xray-core accepts: a packet or bytes that are null or empty are
		// there all the same, a null item is an item of no kind, and the type
		// of a transform arg only matters for bytes.
		"null packet":         {"mode": "standalone", "client": []any{obj{"packet": nil, "capture": "a"}, obj{"Packet": nil, "type": "hex"}}, "server": []any{obj{"reuse": "a"}}},
		"empty packet":        {"client": []any{obj{"packet": []any{}, "capture": "a"}, obj{"packet": "", "type": "str", "capture": "b"}}},
		"null bytes":          {"client": []any{tr("concat", obj{"bytes": nil}, obj{"bytes": nil, "type": "base64"}, obj{"bytes": []any{}})}},
		"null item":           {"client": []any{nil, obj{"rand": 2}}},
		"type of another arg": {"client": []any{tr("be16", obj{"u64": 1, "type": "octal"})}},
		"array type":          {"client": []any{obj{"rand": 2, "type": "Array"}}},
		"a large rand":        {"mode": "standalone", "client": []any{obj{"rand": 65507}}},
	} {
		_, err := NewUDP(settings)
		require.NoError(t, err, name)
	}

	// A header has to fit a UDP datagram.
	for name, settings := range map[string]obj{
		"standalone client": {"mode": "standalone", "client": []any{obj{"rand": 1<<31 - 1}}},
		"prefix client":     {"client": []any{obj{"rand": 65508}}},
		"server":            {"server": []any{obj{"rand": 40000}, obj{"rand": 40000}}},
	} {
		_, err := NewUDP(settings)
		require.ErrorContains(t, err, "does not fit a UDP datagram", name)
	}

	// 128 pads of 16 MiB each are more than a slice can hold on a 32 bit platform.
	pads := make([]obj, 128)
	for i := range pads {
		pads[i] = nested("pad", raw(1), u64(1<<24), raw(0))
	}
	for name, settings := range map[string]obj{
		"bad client item":         {"clients": []any{[]any{obj{"rand": 2, "reuse": "a"}}}},
		"bad server item":         {"servers": []any{[]any{obj{"capture": "a"}}}},
		"bad error item":          {"errors": []any{[]any{obj{"packet": "zz", "type": "hex"}}}},
		"not a list of lists":     {"clients": []any{obj{"rand": 2}}},
		"reuse before capture":    {"clients": []any{[]any{obj{"reuse": "a"}, obj{"rand": 2, "capture": "a"}}}},
		"reuse of a later step":   {"clients": []any{[]any{obj{"reuse": "a"}}}, "servers": []any{[]any{obj{"rand": 2, "capture": "a"}}}},
		"reuse in a transform":    {"clients": []any{[]any{tr("truncate", reuse("a"), u64(1))}}},
		"server computed length":  {"servers": []any{[]any{tr("truncate", raw(1, 2), nested("add", u64(1), u64(0)))}}},
		"server number":           {"servers": []any{[]any{tr("add", u64(1), u64(0))}}},
		"unknown op":              {"clients": []any{[]any{tr("md5", raw(1))}}},
		"client header too large": {"clients": []any{[]any{tr("concat", pads...)}}},
		"client list too large":   {"clients": []any{[]any{obj{"rand": 1 << 30}, obj{"rand": 1 << 30}}}},
		"server item too large":   {"servers": []any{[]any{tr("pad", raw(1), u64(uint64(1<<32)), raw(0))}}},
	} {
		_, err := NewTCP(settings)
		require.Error(t, err, name)
	}

	for name, settings := range map[string]obj{
		"empty":                         {},
		"errors are accepted":           {"errors": []any{[]any{obj{"packet": "HTTP/1.1 400 Bad Request\r\n\r\n", "type": "str"}}}},
		"a client may compute a length": {"clients": []any{[]any{tr("truncate", raw(1, 2), nested("add", u64(1), u64(0)))}}},
		"large items":                   {"clients": []any{[]any{obj{"rand": 1 << 30}, tr("pad", raw(1), u64(1<<29), raw(0))}}, "servers": []any{[]any{obj{"rand": 1 << 30}}}},
		"null sequence and null item":   {"clients": []any{nil, []any{nil, obj{"packet": nil, "capture": "a"}}}, "servers": []any{nil, []any{obj{"reuse": "a"}}}},
		"variables cross the steps": {
			"clients": []any{[]any{obj{"rand": 2, "capture": "c"}}, []any{obj{"reuse": "s"}, obj{"delay": 5}}},
			"servers": []any{[]any{obj{"reuse": "c"}, obj{"rand": 2, "capture": "s"}}, []any{tr("concat", reuse("c"), reuse("s"))}},
		},
	} {
		_, err := NewTCP(settings)
		require.NoError(t, err, name)
	}
}
