package encryption

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The record length bounds are those of Xray-core v26.11.9.
func TestDecodeHeaderBounds(t *testing.T) {
	header := func(l int) []byte { return []byte{23, 3, 3, byte(l >> 8), byte(l)} }
	for _, l := range []int{17, 8192 + 16, 16640} {
		got, err := DecodeHeader(header(l))
		assert.NoError(t, err, l)
		assert.Equal(t, l, got)
	}
	for _, l := range []int{0, 16, 16641, 17000, 65535} {
		_, err := DecodeHeader(header(l))
		assert.True(t, errors.Is(err, ErrInvalidHeader), l)
	}
	_, err := DecodeHeader([]byte{22, 3, 3, 0, 32})
	assert.True(t, errors.Is(err, ErrInvalidHeader))
}
