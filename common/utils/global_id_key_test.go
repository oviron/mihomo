package utils

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyedGlobalID(t *testing.T) {
	key, err := parseGlobalIDKey(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	require.NoError(t, err)
	other, err := parseGlobalIDKey("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	require.NoError(t, err)

	// the same key and client address give the same ID in every process
	assert.Equal(t, [8]byte{0x36, 0x10, 0xba, 0x15, 0x60, 0x47, 0x6f, 0xea}, keyedGlobalID(key, "192.168.1.2:50000"))
	assert.NotEqual(t, keyedGlobalID(key, "192.168.1.2:50000"), keyedGlobalID(key, "192.168.1.2:50001"))
	assert.NotEqual(t, keyedGlobalID(key, "192.168.1.2:50000"), keyedGlobalID(other, "192.168.1.2:50000"))

	key, err = parseGlobalIDKey("")
	assert.NoError(t, err)
	assert.Nil(t, key)
	for _, value := range []string{"short", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "AQEB"} {
		_, err = parseGlobalIDKey(value)
		assert.Error(t, err, value)
	}
}
