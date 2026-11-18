package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id,omitempty"`

	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`

	// Mldsa65Verify is the "Verify" key printed by `xray mldsa65` for the
	// server's mldsa65Seed.
	Mldsa65Verify string `proxy:"mldsa65-verify,omitempty"`

	// ClientVersion is the Xray-core version to report to the server, like
	// "26.11.9". Servers with minClientVer refuse the default 1.8.2.
	ClientVersion string `proxy:"client-version,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		if o.Mldsa65Verify != "" {
			if !tlsC.MLDSA65Supported {
				return nil, errors.New("REALITY mldsa65-verify needs mihomo built with Go 1.27 or newer")
			}
			config.Mldsa65Verify, err = base64.RawURLEncoding.DecodeString(o.Mldsa65Verify)
			if err != nil || len(config.Mldsa65Verify) != tlsC.MLDSA65PublicKeySize {
				return nil, errors.New("invalid REALITY mldsa65-verify")
			}
		}

		if o.ClientVersion != "" {
			var version [3]byte
			parts := strings.Split(o.ClientVersion, ".")
			if len(parts) != len(version) {
				return nil, errors.New("invalid REALITY client version")
			}
			for i, part := range parts {
				n, err := strconv.ParseUint(part, 10, 8)
				if err != nil {
					return nil, errors.New("invalid REALITY client version")
				}
				version[i] = byte(n)
			}
			config.ClientVersion = &version
		}

		return config, nil
	}
	if o.Mldsa65Verify != "" {
		return nil, errors.New("REALITY mldsa65-verify needs public-key")
	}
	return nil, nil
}
