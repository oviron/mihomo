package utils

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/blake3"
)

// GlobalIDKeyEnv names the environment variable with a 32-byte key in
// unpadded URL-safe base64, the format of Xray-core's XRAY_XUDP_BASEKEY.
//
// With the key set, GlobalID is a keyed BLAKE3 hash like in Xray-core, so a
// restarted process sends the same XUDP GlobalID for the same client address
// and the server keeps the UDP mapping. Without it the ID is seeded per
// process.
//
// Every installation needs a key of its own: a server takes a second flow
// with the same GlobalID for a reconnect of the first one and detaches it.
const GlobalIDKeyEnv = "MIHOMO_XUDP_BASEKEY"

var globalIDKey = loadGlobalIDKey()

func parseGlobalIDKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be 32 bytes in unpadded URL-safe base64", GlobalIDKeyEnv)
	}
	return key, nil
}

// loadGlobalIDKey falls back to the per-process seed on a malformed key: the
// variable is read by everything that links this package.
func loadGlobalIDKey() []byte {
	key, err := parseGlobalIDKey(os.Getenv(GlobalIDKeyEnv))
	if err != nil {
		log.Errorln("%s, the key is ignored", err)
	}
	return key
}

func keyedGlobalID(key []byte, material string) (id [8]byte) {
	h := blake3.New(len(id), key)
	_, _ = h.Write([]byte(material))
	copy(id[:], h.Sum(nil))
	return
}
