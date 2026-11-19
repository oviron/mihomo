//go:build !go1.27

package tls

import "errors"

// MLDSA65Supported reports whether this build can check the ML-DSA-65
// signature of a REALITY server. crypto/mldsa comes with Go 1.27.
const MLDSA65Supported = false

// MLDSA65PublicKeySize is the size of the key in reality-opts.mldsa65-verify.
const MLDSA65PublicKeySize = 1952

func verifyMLDSA65(publicKey, message, signature []byte) error {
	return errors.New("ML-DSA-65 needs mihomo built with Go 1.27 or newer")
}
