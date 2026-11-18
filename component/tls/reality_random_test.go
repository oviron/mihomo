package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasX25519MLKEM768(t *testing.T) {
	for name, want := range map[string]bool{
		"chrome":     true,
		"chrome155":  true,
		"firefox":    true,
		"safari":     true,
		"ios":        false,
		"edge":       false,
		"android":    false,
		"chrome120":  false,
		"firefox120": false,
	} {
		assert.Equal(t, want, hasX25519MLKEM768(fingerprints[name]), name)
	}
}

func TestHybridFingerprint(t *testing.T) {
	for i := 0; i < 20; i++ { // ios is always replaced, by one that has the key share
		picked := hybridFingerprint(fingerprints["ios"])
		assert.True(t, hasX25519MLKEM768(picked), picked.Client)
		assert.Contains(t, []string{"Chrome", "Safari", "Firefox"}, picked.Client)
	}
	for _, name := range []string{"chrome", "safari", "firefox"} { // the rest is kept
		picked := hybridFingerprint(fingerprints[name])
		assert.Equal(t, fingerprints[name].Client+fingerprints[name].Version, picked.Client+picked.Version)
	}
}

func TestRealityFingerprint(t *testing.T) {
	ios := fingerprints["ios"]
	hybrid := &RealityConfig{SupportX25519MLKEM768: true}

	str := func(id UClientHelloID) string { return id.Str() }

	// a fingerprint the user named is never replaced
	assert.Equal(t, str(ios), str(RealityFingerprint("ios", ios, hybrid)))
	// neither is "random" for servers that take a classical key share
	assert.Equal(t, str(ios), str(RealityFingerprint("random", ios, &RealityConfig{})))

	for i := 0; i < 3; i++ { // one pick per process, with the hybrid key share
		picked := RealityFingerprint("random", ios, hybrid)
		assert.True(t, hasX25519MLKEM768(picked), str(picked))
		assert.Equal(t, str(randomHybridFingerprint()), str(picked))
	}
}
