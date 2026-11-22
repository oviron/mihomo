package tls

import (
	"github.com/metacubex/mihomo/common/once"
	"github.com/metacubex/mihomo/log"

	utls "github.com/metacubex/utls"
	"github.com/mroth/weightedrand/v2"
)

// hasX25519MLKEM768 reports whether the ClientHello of the fingerprint carries
// an X25519MLKEM768 key share.
func hasX25519MLKEM768(fingerprint UClientHelloID) bool {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return false
	}
	for _, extension := range spec.Extensions {
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			for _, share := range ks.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					return true
				}
			}
		}
	}
	return false
}

// hybridFingerprint returns picked when its ClientHello carries X25519MLKEM768
// and otherwise picks, with the weights of "random", among those that do.
func hybridFingerprint(picked UClientHelloID) UClientHelloID {
	if hasX25519MLKEM768(picked) {
		return picked
	}
	var choices []weightedrand.Choice[string, int]
	// The weights of randomFingerprint as upstream has them since a9e5c456,
	// without ios; ios has no X25519MLKEM768 key share and is never kept here.
	for _, choice := range []weightedrand.Choice[string, int]{
		weightedrand.NewChoice("chrome", 6),
		weightedrand.NewChoice("safari", 3),
		weightedrand.NewChoice("firefox", 1),
	} {
		if hasX25519MLKEM768(fingerprints[choice.Item]) {
			choices = append(choices, choice)
		}
	}
	chooser, err := weightedrand.NewChooser(choices...)
	if err != nil {
		return picked
	}
	name := chooser.Pick()
	log.Debugln("random HelloID for REALITY with X25519MLKEM768:%s", name)
	return fingerprints[name]
}

// randomHybridFingerprint is hybridFingerprint of the "random" pick, made
// once per process like that pick.
var randomHybridFingerprint = once.OnceValue(func() UClientHelloID {
	return hybridFingerprint(randomFingerprint())
})

// RealityFingerprint returns the fingerprint to use for REALITY. It is the one
// already picked, except for "random" with SupportX25519MLKEM768: a server
// that needs the hybrid key share refuses a ClientHello without one, so the
// pick is kept to the fingerprints that have it.
func RealityFingerprint(name string, picked UClientHelloID, realityConfig *RealityConfig) UClientHelloID {
	if name == "random" && realityConfig != nil && realityConfig.SupportX25519MLKEM768 {
		return randomHybridFingerprint()
	}
	return picked
}
