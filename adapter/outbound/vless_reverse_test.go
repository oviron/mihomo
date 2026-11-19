package outbound

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The messages are those of Xray-core's app/reverse Control: field 1 is the
// state, field 99 random bytes.
func TestParseVlessReverseControl(t *testing.T) {
	random := []byte{0x9a, 0x06, 0x03, 1, 2, 3}
	cases := []struct {
		name     string
		message  []byte
		draining bool
		ok       bool
	}{
		{"active: the default state is not on the wire", random, false, true},
		{"draining", append([]byte{0x08, 0x01}, random...), true, true},
		{"explicitly active", append([]byte{0x08, 0x00}, random...), false, true},
		{"empty", nil, false, true},
		{"cut field", []byte{0x9a, 0x06, 0x09, 1}, false, false},
		{"cut varint", []byte{0x08}, false, false},
		{"not a message of this kind", []byte{0x0d, 1, 2, 3, 4}, false, false},
	}
	for _, tc := range cases {
		draining, ok := parseVlessReverseControl(tc.message)
		assert.Equal(t, tc.ok, ok, tc.name)
		assert.Equal(t, tc.draining, draining, tc.name)
	}
}
