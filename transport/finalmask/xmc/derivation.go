package xmc

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/log"
)

// The server proves that it knows the password by owning the RSA key both
// sides derive from it: the 1024 bit modulus is the product of two 512 bit
// primes, each the first suitable prime at or after a number taken from
// SHA-256(password + "-p-prime" + "-" + counter) for p and the same with
// "-q-prime" for q, the counter running from 0.

const (
	rsaModulusLength = 128 // bytes
	rsaExponent      = 65537
	// PKCS#1 v1.5 encryption takes at most the modulus length minus 11 bytes.
	// The client encrypts the server's verify token, 4 bytes from Xray-core,
	// followed by the password.
	verifyTokenLength = 4
	maxPasswordLength = rsaModulusLength - 11 - verifyTokenLength
)

// serverKey is the public key the server must present.
type serverKey struct {
	public *rsa.PublicKey
	der    []byte // PKIX, the form the server sends it in
}

// derivePrime returns the first prime p at or after the 512 bit number the
// hash stream of seed starts with, such that p-1 is coprime to the public
// exponent. The two highest bits of the number are set, so that the product
// of two such primes has exactly 1024 bits.
func derivePrime(seed string) *big.Int {
	var start []byte
	for counter := 0; len(start) < rsaModulusLength/2; counter++ {
		sum := sha256.Sum256([]byte(seed + "-" + strconv.Itoa(counter)))
		start = append(start, sum[:]...)
	}
	start = start[:rsaModulusLength/2]
	start[0] |= 0xc0
	start[len(start)-1] |= 1

	p := new(big.Int).SetBytes(start)
	one, two, e := big.NewInt(1), big.NewInt(2), big.NewInt(rsaExponent)
	rem := new(big.Int)
	for {
		// e is prime: p-1 is coprime to it unless it is a multiple of it
		if p.ProbablyPrime(20) && rem.Mod(rem.Sub(p, one), e).Sign() != 0 {
			return p
		}
		p.Add(p, two)
	}
}

// deriveKey derives the server's public key from the password.
func deriveKey(password string) (*serverKey, error) {
	p := derivePrime(password + "-p-prime")
	q := derivePrime(password + "-q-prime")
	public := &rsa.PublicKey{N: new(big.Int).Mul(p, q), E: rsaExponent}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return &serverKey{public: public, der: der}, nil
}

// xrayRejectsPasswordLength tells whether a server running Xray-core 26.11.9
// refuses to start a session for a password of n bytes. Its derivation builds
// both seeds by appending to one byte slice of the password; when the
// allocator left that slice 8 spare bytes the seeds are one array, p equals q,
// q is moved to the next prime and Go rejects a key whose primes are that
// close. Go rounds a slice of more than 32 bytes up to a multiple of 16.
func xrayRejectsPasswordLength(n int) bool {
	return n > 32 && (n-1)%16 < 8
}

// The derivation takes a prime search, and the settings of a proxy are parsed
// more than once when a configuration is loaded: the last few keys are kept.
// They are found by a hash of the password, so that passwords no longer in
// use are not held here.
const keyCacheSize = 16

type cachedKey struct {
	password [sha256.Size]byte
	key      *serverKey
}

var (
	keysMu sync.Mutex
	keys   []cachedKey // the oldest first
)

func keyFor(password string) (*serverKey, error) {
	digest := sha256.Sum256([]byte(password))
	keysMu.Lock()
	defer keysMu.Unlock()
	for _, cached := range keys {
		if cached.password == digest {
			return cached.key, nil
		}
	}
	key, err := deriveKey(password)
	if err != nil {
		return nil, err
	}
	if len(keys) == keyCacheSize {
		keys = append(keys[:0], keys[1:]...)
	}
	keys = append(keys, cachedKey{password: digest, key: key})
	if xrayRejectsPasswordLength(len(password)) {
		log.Warnln("[finalmask] xmc: a server running Xray-core 26.11.9 cannot use a password of %d bytes: "+
			"its key derivation breaks for lengths 33-40, 49-56, 65-72, 81-88, 97-104 and 113, "+
			"which includes a 36 character UUID. Use a password of another length", len(password))
	}
	return key, nil
}
