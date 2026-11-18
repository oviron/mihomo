// Package finalmask is the client side of Xray-core's finalmask
// (streamSettings.finalmask, Xray-core v26.11.9): masks applied to the TCP
// connection or the UDP socket an outbound opens to its server, below TLS and
// below any UDP based transport.
//
//	finalmask:
//	  tcp:
//	    - type: fragment
//	      settings: {packets: tlshello, length: 100-200, delay: 10-20}
//	  udp:
//	    - type: noise
//	      settings: {noise: [{rand: 50-100}]}
//	    - type: salamander
//	      settings: {password: secret}
//	  quic-params: {congestion: bbr}
//
// Keys are the kebab-case form of the names Xray-core uses in JSON; the
// original names are accepted as well. As in Xray-core the last mask of a list
// is the one closest to the wire.
package finalmask

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

// Config is a parsed finalmask option.
type Config struct {
	// tcp and udp are in the order the masks are applied to a new connection:
	// the one closest to the wire first.
	tcp     []mask.TCPMask
	udp     []mask.UDPMask
	carrier mask.UDPCarrier

	// directOnly tells that the carrier opens sockets of its own kind.
	directOnly bool

	// MKCPLegacy tells that the UDP list has a mkcp-legacy mask.
	MKCPLegacy bool
	// Quic is the quic-params section, nil when absent.
	Quic *QuicParams
}

type rawConfig struct {
	TCP        []rawMask      `mask:"tcp,omitempty"`
	UDP        []rawMask      `mask:"udp,omitempty"`
	QuicParams map[string]any `mask:"quic-params,omitempty"`
}

type rawMask struct {
	Type     string         `mask:"type,omitempty"`
	Settings map[string]any `mask:"settings,omitempty"`
}

// ValidateProxy checks the finalmask option of a raw proxy mapping, if it has
// one. The key is looked up the way the proxy decoder matches it.
func ValidateProxy(mapping map[string]any) error {
	for key, raw := range mapping {
		if !strings.EqualFold(key, "finalmask") || raw == nil {
			continue
		}
		option, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("finalmask: expected a map, got %T", raw)
		}
		config, err := Parse(option)
		if err != nil {
			return err
		}
		if config.directOnly {
			// the names as the proxy decoder matches them
			for name, value := range mapping {
				switch strings.ToLower(strings.ReplaceAll(name, "_", "-")) {
				case "dialer-proxy", "interface-name", "routing-mark":
					if value != nil && !reflect.ValueOf(value).IsZero() {
						return fmt.Errorf("finalmask: the last udp mask opens sockets of its own kind and can't be used with %s", name)
					}
				}
			}
		}
	}
	return nil
}

// Parse builds the masks of a raw finalmask option.
func Parse(raw map[string]any) (*Config, error) {
	var rc rawConfig
	if err := mask.Decode(raw, &rc); err != nil {
		return nil, fmt.Errorf("finalmask: %w", err)
	}
	config := &Config{}

	for i := len(rc.TCP) - 1; i >= 0; i-- {
		name := strings.ToLower(rc.TCP[i].Type)
		if name == "filter" { // filters the clients of a server, nothing to do on a client
			continue
		}
		m, err := mask.BuildTCP(name, rc.TCP[i].Settings)
		if err != nil {
			return nil, fmt.Errorf("finalmask: tcp[%d] %s: %w", i, name, err)
		}
		config.tcp = append(config.tcp, m)
	}

	for i := len(rc.UDP) - 1; i >= 0; i-- {
		name := strings.ToLower(rc.UDP[i].Type)
		if name == "filter" {
			continue
		}
		m, err := mask.BuildUDP(name, rc.UDP[i].Settings)
		if err != nil {
			return nil, fmt.Errorf("finalmask: udp[%d] %s: %w", i, name, err)
		}
		if name == "mkcp-legacy" {
			config.MKCPLegacy = true
		}
		if carrier, ok := m.(mask.UDPCarrier); ok {
			if i != len(rc.UDP)-1 {
				return nil, fmt.Errorf("finalmask: udp[%d] %s opens the socket itself and must be the last mask of the list", i, name)
			}
			config.carrier = carrier
			_, config.directOnly = m.(mask.DirectOnly)
			continue
		}
		config.udp = append(config.udp, m)
	}

	if rc.QuicParams != nil {
		quic, err := parseQuicParams(rc.QuicParams)
		if err != nil {
			return nil, fmt.Errorf("finalmask: quic-params: %w", err)
		}
		config.Quic = quic
	}
	return config, nil
}

// HasTCP tells whether TCP connections are masked.
func (c *Config) HasTCP() bool {
	return c != nil && len(c.tcp) > 0
}

// HasUDP tells whether UDP sockets are masked.
func (c *Config) HasUDP() bool {
	return c != nil && (len(c.udp) > 0 || c.carrier != nil)
}
