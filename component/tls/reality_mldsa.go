//go:build go1.27

package tls

import (
	"crypto/mldsa"
	"errors"
)

// MLDSA65Supported reports whether this build can check the ML-DSA-65
// signature of a REALITY server.
const MLDSA65Supported = true

// MLDSA65PublicKeySize is the size of the key in reality-opts.mldsa65-verify.
const MLDSA65PublicKeySize = mldsa.MLDSA65PublicKeySize

func verifyMLDSA65(publicKey, message, signature []byte) error {
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey)
	if err != nil {
		return err
	}
	if len(signature) == 0 {
		return errors.New("no ML-DSA-65 signature")
	}
	return mldsa.Verify(key, message, signature, nil)
}
