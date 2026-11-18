package outbound

import (
	"encoding/base64"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/stretchr/testify/require"
)

func TestRealityOptions(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	config, err := RealityOptions{PublicKey: publicKey}.Parse()
	require.NoError(t, err)
	require.Nil(t, config.ClientVersion)
	require.Nil(t, config.Mldsa65Verify)

	config, err = RealityOptions{PublicKey: publicKey, ClientVersion: "26.11.9"}.Parse()
	require.NoError(t, err)
	require.Equal(t, [3]byte{26, 11, 9}, *config.ClientVersion)

	for _, version := range []string{"26.11", "26.11.9.1", "26.11.x", "256.0.0"} {
		_, err = RealityOptions{PublicKey: publicKey, ClientVersion: version}.Parse()
		require.Error(t, err, version)
	}

	verify := base64.RawURLEncoding.EncodeToString(make([]byte, tlsC.MLDSA65PublicKeySize))
	_, err = RealityOptions{Mldsa65Verify: verify}.Parse() // not silently without REALITY
	require.Error(t, err)
	config, err = RealityOptions{PublicKey: publicKey, Mldsa65Verify: verify}.Parse()
	if tlsC.MLDSA65Supported {
		require.NoError(t, err)
		require.Len(t, config.Mldsa65Verify, tlsC.MLDSA65PublicKeySize)
		_, err = RealityOptions{PublicKey: publicKey, Mldsa65Verify: verify[:100]}.Parse()
		require.Error(t, err)
	} else {
		require.ErrorContains(t, err, "Go 1.27")
	}
}
