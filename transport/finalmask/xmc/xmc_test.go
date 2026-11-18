package xmc

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err)
	return b
}

func testSettings(password string, usernames ...string) map[string]any {
	var profiles []any
	for _, name := range usernames {
		digest := sha256.Sum256([]byte(name))
		profiles = append(profiles, map[string]any{
			"username":           name,
			"uuid":               hex.EncodeToString(digest[:16]),
			"textures-value":     strings.Repeat("texture-value-", 40),
			"textures-signature": strings.Repeat("texture-signature-", 24),
		})
	}
	return map[string]any{"password": password, "profiles": profiles}
}

func TestSettings(t *testing.T) {
	m, err := New(map[string]any{
		"password": "secret-password",
		"hostname": "mc.example.org",
		"profiles": []any{
			map[string]any{
				"username": "Player_1", "uuid": "0123456789abcdef0123456789abcdef",
				"textures-value": "value", "textures-signature": "signature",
			},
			// the names of Xray-core's JSON and the dashed form of the UUID
			map[string]any{
				"username": "abc", "uuid": "01234567-89ab-cdef-0123-456789abcdef",
				"texturesValue": "v", "texturesSignature": "s",
			},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "mc.example.org", m.hostname)
	id := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	require.Equal(t, []profile{
		{username: "Player_1", uuid: id, texturesValue: "value", texturesSignature: "signature"},
		{username: "abc", uuid: id, texturesValue: "v", texturesSignature: "s"},
	}, m.profiles)
	require.Len(t, m.key.der, 162)

	// The longest password that fits into the encrypted verify token.
	_, err = New(testSettings(strings.Repeat("p", 113), "player"))
	require.NoError(t, err)

	with := func(change func(settings, profile map[string]any)) map[string]any {
		settings := testSettings("secret-password", "player")
		change(settings, settings["profiles"].([]any)[0].(map[string]any))
		return settings
	}
	for name, settings := range map[string]map[string]any{
		"no password":       with(func(s, _ map[string]any) { delete(s, "password") }),
		"long password":     with(func(s, _ map[string]any) { s["password"] = strings.Repeat("p", 114) }),
		"no profiles":       with(func(s, _ map[string]any) { delete(s, "profiles") }),
		"empty profiles":    with(func(s, _ map[string]any) { s["profiles"] = []any{} }),
		"long hostname":     with(func(s, _ map[string]any) { s["hostname"] = strings.Repeat("h", 4097) }),
		"short username":    with(func(_, p map[string]any) { p["username"] = "ab" }),
		"long username":     with(func(_, p map[string]any) { p["username"] = "abcdefghijklmnopq" }),
		"username charset":  with(func(_, p map[string]any) { p["username"] = "play er" }),
		"no uuid":           with(func(_, p map[string]any) { delete(p, "uuid") }),
		"bad uuid":          with(func(_, p map[string]any) { p["uuid"] = "0123456789abcdef" }),
		"no textures value": with(func(_, p map[string]any) { delete(p, "textures-value") }),
		"no signature":      with(func(_, p map[string]any) { p["textures-signature"] = "" }),
		"long textures":     with(func(_, p map[string]any) { p["textures-value"] = strings.Repeat("v", 4097) }),
		"unknown type":      with(func(s, _ map[string]any) { s["profiles"] = "player" }),
	} {
		_, err := New(settings)
		require.Error(t, err, name)
	}
}

// The vectors were computed with the derivation of Xray-core 26.11.9 fed with
// separately built seeds; the first password and its hash are those of
// Xray-core's own test.
func TestKeyDerivation(t *testing.T) {
	for _, test := range []struct {
		password   string
		privateKey string // SHA-256 of the PKCS#1 private key
		publicKey  string // SHA-256 of the PKIX public key
	}{
		{
			"deterministic-rsa-key-golden",
			"3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f",
			"8ba32fc7659e866c673236080355d879efdbb0ed0e55f090014ba34cfd21504b",
		},
		{
			"password",
			"fb063a96a65d69b4227924d56f7cbb7fd21e8e9ccd2fea8545d8ae817f7c2be7",
			"81678ee9a5d1893de3f7f4812086a7b4c65b05766a83964cecb256409a0255e2",
		},
		{
			"0123456789abcdef0123456789abcdef",
			"efda06d26ce8171685268d802caf990a86788abc9ecc27f9fe3e2e9f4005dcc9",
			"c0589e1e67582a3d1d9ca036296f45e8678291bedf88e58d18edec7e4b3cb2da",
		},
		{
			// 36 bytes: the key a server gets once its derivation is fixed
			"b831381d-6324-4d53-ad4f-8cda48b30811",
			"76a411670cfa0edf820ed3886c8776f4f04a70e785c280a6b9993d4860ab833f",
			"cf51262aa03626af2ff9e498f5badc7452fb2bbea9d51f1e3320651db4f8c22f",
		},
	} {
		key, err := deriveKey(test.password)
		require.NoError(t, err)
		sum := sha256.Sum256(key.der)
		require.Equal(t, test.publicKey, hex.EncodeToString(sum[:]), test.password)
		require.Equal(t, 1024, key.public.N.BitLen())

		private := testPrivateKey(test.password)
		require.NoError(t, private.Validate())
		require.Equal(t, key.public.N, private.N)
		sum = sha256.Sum256(x509.MarshalPKCS1PrivateKey(private))
		require.Equal(t, test.privateKey, hex.EncodeToString(sum[:]), test.password)
	}

}

// The key of a password is derived once while the password is among the last
// few that were used; the cache does not grow beyond that.
func TestKeyCache(t *testing.T) {
	first, err := keyFor("cached password 0")
	require.NoError(t, err)
	again, err := keyFor("cached password 0")
	require.NoError(t, err)
	require.Same(t, first, again)

	var last *serverKey
	for i := 1; i <= keyCacheSize; i++ {
		last, err = keyFor(fmt.Sprintf("cached password %d", i))
		require.NoError(t, err)
	}
	keysMu.Lock()
	require.Len(t, keys, keyCacheSize)
	keysMu.Unlock()
	again, err = keyFor(fmt.Sprintf("cached password %d", keyCacheSize))
	require.NoError(t, err)
	require.Same(t, last, again)
	// the oldest password was dropped; its key is derived again
	again, err = keyFor("cached password 0")
	require.NoError(t, err)
	require.NotSame(t, first, again)
	require.Equal(t, first.der, again.der)
	keysMu.Lock()
	require.Len(t, keys, keyCacheSize)
	keysMu.Unlock()
}

// The spellings of a UUID are those google/uuid, which Xray-core uses, reads.
func TestUUIDSpellings(t *testing.T) {
	want := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	for _, spelling := range []string{
		"0123456789abcdef0123456789abcdef",
		"0123456789ABCDEF0123456789abcdef",
		"01234567-89ab-cdef-0123-456789abcdef",
		"01234567-89AB-CDEF-0123-456789ABCDEF",
		"{01234567-89ab-cdef-0123-456789abcdef}",
		"urn:uuid:01234567-89ab-cdef-0123-456789abcdef",
		"URN:UUID:01234567-89ab-cdef-0123-456789abcdef",
		"Urn:Uuid:01234567-89AB-cdef-0123-456789abcdef",
	} {
		id, err := parseUUID(spelling)
		require.NoError(t, err, spelling)
		require.EqualValues(t, want, id, spelling)
	}
	for _, spelling := range []string{
		"",
		"0123456789abcdef",
		"0123456789abcdef0123456789abcdeg",
		"01234567-89ab-cdef-0123-456789abcde",
		"0123456789ab-cdef-0123-456789abcdef-",
		"01234567089ab-cdef-0123-456789abcdef",
		"{0123456789abcdef0123456789abcdef}",
		"(01234567-89ab-cdef-0123-456789abcdef)",
		"urn:uuid:0123456789abcdef0123456789abcdef",
		"urn-uuid-01234567-89ab-cdef-0123-456789abcdef",
		"urn:uuid:{01234567-89ab-cdef-0123-456789abcdef}",
	} {
		_, err := parseUUID(spelling)
		require.Error(t, err, spelling)
	}
}

// testPrivateKey is the key of a server with the given password.
func testPrivateKey(password string) *rsa.PrivateKey {
	p, q := derivePrime(password+"-p-prime"), derivePrime(password+"-q-prime")
	one := big.NewInt(1)
	totient := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: rsaExponent},
		D:         new(big.Int).ModInverse(big.NewInt(rsaExponent), totient),
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	return key
}

// The lengths were tried against the Xray-core 26.11.9 release.
func TestPasswordLengthsXrayRejects(t *testing.T) {
	for _, n := range []int{1, 8, 16, 17, 24, 25, 32, 41, 48, 57, 64, 73, 80, 89, 96, 105, 112} {
		require.False(t, xrayRejectsPasswordLength(n), n)
	}
	for _, n := range []int{33, 36, 40, 49, 56, 65, 72, 81, 88, 97, 104, 113} {
		require.True(t, xrayRejectsPasswordLength(n), n)
	}
}

func TestCFB8(t *testing.T) {
	// NIST SP 800-38A, F.3.7 CFB8-AES128.
	key := unhex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := unhex(t, "000102030405060708090a0b0c0d0e0f")
	plaintext := unhex(t, "6bc1bee22e409f96e93d7e117393172aae2d")
	ciphertext := unhex(t, "3b79424c9c0dd436bace9e0ed4586a4f32b9")
	enc, err := newCFB8(key, iv, false)
	require.NoError(t, err)
	got := make([]byte, len(plaintext))
	enc.crypt(got, plaintext)
	require.Equal(t, ciphertext, got)
	dec, err := newCFB8(key, iv, true)
	require.NoError(t, err)
	dec.crypt(got, got)
	require.Equal(t, plaintext, got)

	// A long stream against the definition of the mode on top of
	// crypto/cipher: the first byte of full block CFB with the shift
	// register as the IV.
	plaintext = make([]byte, 3*cfb8Slide+100)
	_, _ = rand.Read(plaintext)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	want := make([]byte, len(plaintext))
	register := append([]byte(nil), iv...)
	for i := range plaintext {
		cipher.NewCFBEncrypter(block, register).XORKeyStream(want[i:i+1], plaintext[i:i+1])
		register = append(register[1:], want[i])
	}
	enc, _ = newCFB8(key, iv, false)
	got = make([]byte, len(plaintext))
	for from := 0; from < len(plaintext); { // in pieces of growing size
		to := from + 1 + from/7
		if to > len(plaintext) {
			to = len(plaintext)
		}
		enc.crypt(got[from:to], plaintext[from:to])
		from = to
	}
	require.Equal(t, want, got)

	// Decryption in place, with stretches skipped instead of decrypted.
	dec, _ = newCFB8(key, iv, true)
	dec.crypt(got[:1000], got[:1000])
	dec.skip(got[1000:1005])
	dec.crypt(got[1005:2000], got[1005:2000])
	dec.skip(got[2000:3000])
	dec.crypt(got[3000:], got[3000:])
	require.Equal(t, plaintext[:1000], got[:1000])
	require.Equal(t, plaintext[1005:2000], got[1005:2000])
	require.Equal(t, plaintext[3000:], got[3000:])
}

func byteReader(data []byte) func() (byte, error) {
	return bytes.NewReader(data).ReadByte
}

func TestVarint(t *testing.T) {
	for encoded, value := range map[string]int32{
		"00":         0,
		"01":         1,
		"7f":         127,
		"8001":       128,
		"ff01":       255,
		"ddc701":     25565,
		"ffff7f":     2097151,
		"ffffffff07": 2147483647,
		"ffffffff0f": -1,
		"8080808008": -2147483648,
	} {
		want := unhex(t, encoded)
		require.Equal(t, want, appendVarint(nil, value), value)
		require.Equal(t, len(want), varintSize(value), value)
		got, size, err := readVarint(byteReader(append(want, 0xff)))
		require.NoError(t, err, value)
		require.Equal(t, value, got)
		require.Equal(t, len(want), size)
	}
	for name, encoded := range map[string]string{
		"padded zero":     "8000",
		"padded one":      "8100",
		"padded to five":  "ff80808000",
		"fifth byte bits": "ffffffff1f",
		"six bytes":       "ffffffffff01",
	} {
		_, _, err := readVarint(byteReader(unhex(t, encoded)))
		require.Error(t, err, name)
	}
	_, size, err := readVarint(byteReader(unhex(t, "8080")))
	require.Equal(t, io.EOF, err)
	require.Equal(t, 2, size)
}

func testWire(data []byte) (*wire, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &wire{r: bufio.NewReader(bytes.NewReader(data)), w: out}, out
}

func TestPacketCodec(t *testing.T) {
	// Login Acknowledged has no fields.
	require.Equal(t, []byte{0x01, 0x03}, appendPacket(nil, idLoginAcknowledged))
	// A payload packet.
	hello := append([]byte{0x0f, 0x02, 0x08}, "xmc:datahello"...)
	require.Equal(t, hello, appendPacket(nil, idPayloadFromClient, payloadChannelField, []byte("hello")))

	w, out := testWire(append(append([]byte(nil), hello...), 0x01, 0x03))
	id, data, started, err := w.readPacket()
	require.NoError(t, err)
	require.True(t, started)
	require.EqualValues(t, idPayloadFromClient, id)
	payload := fields{data: data}
	require.Equal(t, payloadChannel, payload.str())
	require.Equal(t, []byte("hello"), payload.data)
	id, data, _, err = w.readPacket()
	require.NoError(t, err)
	require.EqualValues(t, idLoginAcknowledged, id)
	require.Empty(t, data)
	// The end of the stream between two packets is a plain EOF.
	_, _, started, err = w.readPacket()
	require.Equal(t, io.EOF, err)
	require.False(t, started)

	require.NoError(t, w.writePacket(idKeepAlive, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	require.Equal(t, []byte{0x09, 0x04, 1, 2, 3, 4, 5, 6, 7, 8}, out.Bytes())

	frame := func(length int, body ...byte) []byte {
		return append(appendVarint(nil, int32(length)), append(body, make([]byte, length-len(body))...)...)
	}
	for name, test := range map[string]struct {
		stream []byte
		ok     bool
	}{
		"largest data":         {frame(1+maxPacketData, 0x01), true},
		"data too large":       {frame(2+maxPacketData, 0x01), false},
		"largest body":         {frame(maxPacketBody, 0xff, 0xff, 0xff, 0xff, 0x07), true},
		"body too large":       {frame(maxPacketBody+1, 0xff, 0xff, 0xff, 0xff, 0x07), false},
		"empty body":           {[]byte{0x00, 0x00}, false},
		"negative length":      {unhex(t, "ffffffff0f"), false},
		"non-canonical length": {[]byte{0x81, 0x00, 0x03}, false},
		"truncated ID":         {[]byte{0x01, 0x80}, false},
		"truncated length":     {[]byte{0x80}, false},
		"truncated body":       {[]byte{0x05, 0x01, 0x02}, false},
	} {
		w, _ := testWire(test.stream)
		_, _, started, err := w.readPacket()
		require.True(t, started, name)
		if test.ok {
			require.NoError(t, err, name)
		} else {
			require.Error(t, err, name)
			require.NotEqual(t, io.EOF, err, name)
		}
	}
}

func TestFields(t *testing.T) {
	var data []byte
	data = appendVarint(data, 775)
	data = appendPrefixed(data, "host")
	data = append(data, 0x63, 0xdd, 1, 0)
	data = appendPrefixed(data, strings.Repeat("s", maxString))
	data = appendPrefixed(data, strings.Repeat("b", maxByteArray))
	f := fields{data: data}
	require.EqualValues(t, 775, f.varint())
	require.Equal(t, "host", f.str())
	require.Equal(t, []byte{0x63, 0xdd}, f.take(2))
	require.True(t, f.boolean())
	require.False(t, f.boolean())
	require.Len(t, f.str(), maxString)
	require.Len(t, f.bytes(), maxByteArray)
	require.NoError(t, f.err)
	require.Empty(t, f.data)
	f.varint()
	require.Error(t, f.err)

	for name, read := range map[string]func(f *fields){
		"long string":      func(f *fields) { f.data = appendPrefixed(nil, strings.Repeat("s", maxString+1)); f.str() },
		"long byte array":  func(f *fields) { f.data = appendPrefixed(nil, strings.Repeat("b", maxByteArray+1)); f.bytes() },
		"negative length":  func(f *fields) { f.data = unhex(t, "ffffffff0f"); f.str() },
		"truncated string": func(f *fields) { f.data = []byte{0x05, 'a', 'b'}; f.str() },
		"bad boolean":      func(f *fields) { f.data = []byte{0x02}; f.boolean() },
		"short take":       func(f *fields) { f.data = make([]byte, 15); f.take(16) },
	} {
		var f fields
		read(&f)
		require.Error(t, f.err, name)
		// nothing is read after a failure
		f.data = []byte{0x01}
		require.EqualValues(t, 0, f.varint(), name)
	}
}

func sumOf(numbers []int) int {
	total := 0
	for _, n := range numbers {
		total += n
	}
	return total
}

func TestPaddingSchedule(t *testing.T) {
	require.Len(t, schedule, 39)
	// The lengths of the template turns, as Xray-core's tests list them.
	templates := [][]int{
		{44}, {72}, {25}, {41172}, {2},
		{
			7464, 8267, 8790, 8153, 7375, 7347, 8184, 6633, 7670, 8241,
			7857, 7254, 8407, 8283, 6804, 8177, 8177, 7929, 8296, 8177,
		},
	}
	for i := range schedule {
		tn := &schedule[i]
		require.Equal(t, i%2 == 0, tn.fromClient, "turn %d", i)
		if i < len(templates) {
			require.Len(t, tn.templates, len(templates[i]), "turn %d", i)
			for j, template := range tn.templates {
				require.Equal(t, templates[i][j], tn.prefix+sumOf(template), "turn %d template %d", i, j)
				require.True(t, tn.accepts(templates[i][j]))
				require.False(t, tn.accepts(templates[i][j]+1))
			}
			continue
		}
		require.Empty(t, tn.templates, "turn %d", i)
		require.Equal(t, joinLengths[i-len(templates)], [2]int{tn.min, tn.max}, "turn %d", i)
		require.GreaterOrEqual(t, tn.min, 2, "a record holds its header")
		require.True(t, tn.accepts(tn.min) && tn.accepts(tn.max))
		require.False(t, tn.accepts(tn.min-1) || tn.accepts(tn.max+1))
		if tn.fromClient {
			require.Equal(t, milliseconds(1, 30), tn.startDelay)
		}
	}
	require.Equal(t, [2]int{6, 883}, joinLengths[0])
	require.Equal(t, [2]int{6, 19}, joinLengths[32])
	require.Equal(t, 30, len(schedule[3].templates[0]))

	// What the client sends is what the server accepts, in writes of at
	// most 1024 bytes, with exactly one of the three bursts.
	bursts := map[int]int{}
	for round := 0; round < 200; round++ {
		burst := pickBurst()
		bursts[burst]++
		long := 0
		for i := 0; i < len(schedule); i += 2 {
			tn := &schedule[i]
			chunks := clientChunks(i, burst)
			length := sumOf(chunks)
			require.True(t, tn.accepts(tn.prefix+length), "turn %d length %d", i, length)
			require.GreaterOrEqual(t, chunks[0], varintSize(int32(length)))
			for _, n := range chunks {
				require.LessOrEqual(t, n, clientChunk)
			}
			if length > 800 {
				long++
				require.Equal(t, len(templates)+clientBursts[burst].join, i)
			}
			for _, b := range clientBursts {
				if i == len(templates)+b.join && length < 800 {
					require.LessOrEqual(t, length, b.regular[1])
					require.GreaterOrEqual(t, length, b.regular[0])
				}
			}
		}
		require.Equal(t, 1, long, "bursts in a connection")
	}
	require.Greater(t, bursts[0], bursts[1]+bursts[2])
	require.Len(t, clientChunks(0, 0), 2)

	delay := milliseconds(2, 22)
	seen := map[int64]bool{}
	for i := 0; i < 100; i++ {
		d := delay.rand()
		require.GreaterOrEqual(t, d, delay.min)
		require.LessOrEqual(t, d, delay.max)
		seen[d.Milliseconds()] = true
	}
	require.Greater(t, len(seen), 5)
	require.Zero(t, delayRange{}.rand())
}

// writeRecorder keeps the writes apart.
type writeRecorder struct {
	writes [][]byte
}

func (r *writeRecorder) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestPaddingRecord(t *testing.T) {
	rec := &writeRecorder{}
	w := &wire{w: rec}
	// The first turn: 44 bytes, of which 2 were the Login Acknowledged
	// packet; the record of 42 leaves in writes of 26 and 16 bytes.
	require.NoError(t, w.writePadding(clientChunks(0, 0)))
	require.Equal(t, [][]byte{append([]byte{42}, make([]byte, 25)...), make([]byte, 16)}, rec.writes)

	// A length that takes two bytes, in three writes.
	rec.writes = nil
	require.NoError(t, w.writePadding([]int{1024, 1024, 452}))
	require.Len(t, rec.writes, 3)
	stream := bytes.Join(rec.writes, nil)
	require.Equal(t, append([]byte{0xc4, 0x13}, make([]byte, 2498)...), stream)
	require.Error(t, w.writePadding([]int{1, 200}), "the header does not fit the first write")
	require.Error(t, w.writePadding(nil))

	// The reader takes the lengths the turn allows and leaves what follows.
	ranged := &turn{min: 2400, max: 2600}
	r, _ := testWire(append(stream, 0x01, 0x03))
	require.NoError(t, r.readPadding(ranged))
	id, _, _, err := r.readPacket()
	require.NoError(t, err)
	require.EqualValues(t, idLoginAcknowledged, id)

	for name, test := range map[string]struct {
		turn   *turn
		stream []byte
	}{
		"too long":             {&turn{min: 2, max: 2499}, stream},
		"too short":            {&turn{min: 2501, max: 4000}, stream},
		"not a template":       {&turn{templates: [][]int{{2000, 501}, {2499}}}, stream},
		"truncated":            {ranged, stream[:len(stream)-1]},
		"non-canonical header": {&turn{min: 1, max: 10}, []byte{0x82, 0x00}},
		"shorter than header":  {&turn{min: 1, max: 10}, []byte{0x00}},
		"no header":            {ranged, nil},
	} {
		r, _ := testWire(test.stream)
		require.Error(t, r.readPadding(test.turn), name)
	}
	r, _ = testWire(stream)
	require.NoError(t, r.readPadding(&turn{templates: [][]int{{2000}, {2000, 500}}}))
	r, _ = testWire(stream)
	require.NoError(t, r.readPadding(&turn{prefix: 2, templates: [][]int{{2500}}}))
}
