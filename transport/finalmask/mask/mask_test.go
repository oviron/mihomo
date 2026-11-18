package mask

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"testing"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func TestRange(t *testing.T) {
	type options struct {
		A Range   `mask:"a,omitempty"`
		B Range   `mask:"b,omitempty"`
		C *Range  `mask:"c,omitempty"`
		L []Range `mask:"l,omitempty"`
	}
	var o options
	require.NoError(t, Decode(map[string]any{"a": 5, "b": "20-10", "l": []any{"1-2", 3, "-5--1"}}, &o))
	require.Equal(t, Range{From: 5, To: 5}, o.A)
	require.Equal(t, Range{From: 10, To: 20}, o.B, "the bounds are ordered")
	require.Nil(t, o.C)
	require.Equal(t, []Range{{1, 2}, {3, 3}, {-5, -1}}, o.L)
	require.Equal(t, "10-20", o.B.String())

	for _, bad := range []any{"x", "1-", "1-2-3", "1-2147483648", "-2147483649"} {
		require.Error(t, Decode(map[string]any{"a": bad}, &options{}), bad)
	}

	// [from, to), and from when there is nothing to choose
	require.Equal(t, int64(7), Range{From: 7, To: 7}.Rand())
	require.Equal(t, int64(7), Range{From: 7, To: 8}.Rand())
	seen := map[int64]bool{}
	for i := 0; i < 200; i++ {
		seen[Range{From: 1, To: 4}.Rand()] = true
	}
	require.Equal(t, map[int64]bool{1: true, 2: true, 3: true}, seen)
}

// A key is matched whatever its spelling, and two spellings of one key in a
// map are an error.
func TestDecodeKeys(t *testing.T) {
	type inner struct {
		MaxSplit int `mask:"max-split,omitempty"`
	}
	type options struct {
		RemoteIPs []string `mask:"remote-ips,omitempty"`
		Inner     inner    `mask:"inner,omitempty"`
		List      []inner  `mask:"list,omitempty"`
	}
	for _, key := range []string{"remote-ips", "remoteIPs", "remote_ips", "RemoteIps"} {
		var o options
		require.NoError(t, Decode(map[string]any{key: []any{"192.0.2.1"}, "inner": map[string]any{"maxSplit": 3}}, &o), key)
		require.Equal(t, []string{"192.0.2.1"}, o.RemoteIPs, key)
		require.Equal(t, 3, o.Inner.MaxSplit)
	}
	require.NoError(t, Decode(nil, &options{}))
	require.ErrorContains(t, Decode(map[string]any{"remoteIPs": []any{}, "remote-ips": []any{}}, &options{}), "same key")
	require.ErrorContains(t, Decode(map[string]any{"inner": map[string]any{"max-split": 1, "max_split": 2}}, &options{}), "same key")
	require.ErrorContains(t, Decode(map[string]any{"list": []any{map[string]any{"maxSplit": 1, "max-split": 2}}}, &options{}), "same key")
}

func TestParseBytes(t *testing.T) {
	for _, tc := range []struct {
		value any
		typ   string
		want  []byte
	}{
		{nil, "", nil},
		{[]any{1, 2, 255}, "", []byte{1, 2, 255}},
		{[]any{1.0, uint8(2)}, "array", []byte{1, 2}},
		{"aGk=", "", []byte("hi")}, // what encoding/json takes for a []byte
		{"hello", "str", []byte("hello")},
		{"C0ffEE", "hex", []byte{0xc0, 0xff, 0xee}},
		{"aGk=", "BASE64", []byte("hi")},
	} {
		got, err := ParseBytes(tc.value, tc.typ)
		require.NoError(t, err, tc)
		require.Equal(t, tc.want, got, tc)
	}
	for _, tc := range []struct {
		value any
		typ   string
	}{
		{[]any{256}, ""}, {[]any{-1}, ""}, {[]any{1.5}, ""}, {[]any{"a"}, ""}, {42, ""},
		{"zz", "hex"}, {5, "str"}, {"!", "base64"}, {"a", "utf16"}, {nil, "hex"}, {nil, "utf16"},
	} {
		_, err := ParseBytes(tc.value, tc.typ)
		require.Error(t, err, tc)
	}
}

func TestRandBytesBetween(t *testing.T) {
	b := make([]byte, 1000)
	RandBytesBetween(b, 70, 65)
	for _, v := range b {
		require.GreaterOrEqual(t, v, byte(65))
		require.LessOrEqual(t, v, byte(70))
	}
}

// handshake runs a TLS handshake of a client with the config against a
// server that has the given certificate.
func handshake(t *testing.T, config *tls.Config, cert tls.Certificate) error {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	}()
	return tls.Client(client, config).Handshake()
}

func TestTLSOptions(t *testing.T) {
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	sum := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(sum[:])
	otherPin := hex.EncodeToString(make([]byte, 32))

	decode := func(raw map[string]any) (*tls.Config, error) {
		var o struct {
			TLS TLSOptions `mask:"tls-config,omitempty"`
		}
		require.NoError(t, Decode(map[string]any{"tlsConfig": raw}, &o))
		return o.TLS.Config("default.example.org")
	}

	config, err := decode(nil)
	require.NoError(t, err)
	require.Equal(t, "default.example.org", config.ServerName)
	require.False(t, config.InsecureSkipVerify)
	require.Error(t, handshake(t, config, cert), "a self-signed certificate is not trusted")

	config, err = decode(map[string]any{"serverName": "named.example.org", "alpn": "h2, http/1.1"})
	require.NoError(t, err)
	require.Equal(t, "named.example.org", config.ServerName)
	require.Equal(t, []string{"h2", "http/1.1"}, config.NextProtos)
	config, err = decode(map[string]any{"alpn": []any{"h3"}})
	require.NoError(t, err)
	require.Equal(t, []string{"h3"}, config.NextProtos)

	// one of several pins is enough, with colons or without
	config, err = decode(map[string]any{"pinnedPeerCertSha256": otherPin + ", " + pin})
	require.NoError(t, err)
	require.NoError(t, handshake(t, config, cert))
	config, err = decode(map[string]any{"pinned-peer-cert-sha256": otherPin})
	require.NoError(t, err)
	require.Error(t, handshake(t, config, cert))

	// names alone still need a trusted certificate
	config, err = decode(map[string]any{"verifyPeerCertByName": "a.example.org,b.example.org"})
	require.NoError(t, err)
	require.Error(t, handshake(t, config, cert))

	for name, raw := range map[string]map[string]any{
		"allow insecure":         {"allowInsecure": true},
		"no system roots":        {"disableSystemRoot": true},
		"certificates":           {"certificates": []any{map[string]any{"certificateFile": "ca.pem"}}},
		"fingerprint":            {"fingerprint": "chrome"},
		"bad pin":                {"pinnedPeerCertSha256": "abcd"},
		"alpn of numbers":        {"alpn": []any{1}},
		"alpn of the wrong type": {"alpn": 5},
	} {
		_, err := decode(raw)
		require.Error(t, err, name)
	}
	// a field that is set to nothing is not a request for anything
	_, err = decode(map[string]any{"allowInsecure": false, "fingerprint": "", "certificates": []any{}})
	require.NoError(t, err)
}
