package ca

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprintList(t *testing.T) {
	leaf := CalculateFingerprint(leafCert.Raw)
	intermediate := CalculateFingerprint(intermediateCert.Raw)
	other := CalculateFingerprint(smimeLeafCert.Raw)
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	// the next certificate is pinned next to the current one, OpenSSL colons allowed
	colons := strings.ToUpper(leaf[:2]) + ":" + leaf[2:]
	for _, list := range []string{other + "," + leaf, leaf + ", " + other, " " + other + " ,\n" + colons + ",", leaf + ","} {
		verifier, err := NewFingerprintVerifier(list, certTime)
		require.NoError(t, err, list)
		assert.NoError(t, verifier(chain, wrongLeafServerName), list)
	}

	verifier, err := NewFingerprintVerifier(other+","+other, certTime)
	require.NoError(t, err)
	assert.ErrorIs(t, verifier(chain, leafServerName), errNotMatch)

	// a pinned CA still has to sign a chain that is valid for the name
	verifier, err = NewFingerprintVerifier(other+","+intermediate, certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, leafServerName))
	err = verifier(chain, wrongLeafServerName)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, errNotMatch)

	_, err = NewFingerprintVerifier(leaf+",not-a-hash", certTime)
	assert.Error(t, err)
}

func TestFingerprintWithNameList(t *testing.T) {
	verifier, err := NewFingerprintVerifier(CalculateFingerprint(intermediateCert.Raw), certTime)
	require.NoError(t, err)
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	assert.NoError(t, verifier(chain, wrongLeafServerName+","+leafServerName))
	assert.NoError(t, verifier(chain, leafServerName+" , "+wrongLeafServerName))
	assert.Error(t, verifier(chain, wrongLeafServerName+","+wrongLeafServerName))
}

func TestNameCertVerifierList(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	chain := []*x509.Certificate{leafCert, intermediateCert}

	assert.NoError(t, NewNameCertVerifier(wrongLeafServerName+","+leafServerName, roots, certTime)(chain))
	assert.NoError(t, NewNameCertVerifier(leafServerName+", "+wrongLeafServerName, roots, certTime)(chain))
	assert.Error(t, NewNameCertVerifier(wrongLeafServerName+","+wrongLeafServerName, roots, certTime)(chain))
	assert.Error(t, NewNameCertVerifier(leafServerName+","+wrongLeafServerName, x509.NewCertPool(), certTime)(chain))
	assert.NoError(t, NewNameCertVerifier(" "+leafServerName+" ,", roots, certTime)(chain))
}
