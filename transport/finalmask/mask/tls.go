package mask

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/tls"
)

// TLSOptions is the tls-config of a mask that makes HTTPS connections of its
// own (to a rendezvous server, to a DNS over HTTPS resolver): the tlsConfig
// of Xray-core, as far as a client needs it. A config that sets any other
// field is rejected rather than read past: it would ask for a check of the
// server that is not made. That goes for allowInsecure too, which Xray-core
// itself no longer accepts.
type TLSOptions struct {
	ServerName string `mask:"server-name,omitempty"`
	// ALPN is a list, or a comma separated string.
	ALPN any `mask:"alpn,omitempty"`
	// PinnedPeerCertSha256 is a comma separated list of hex SHA-256 hashes of
	// certificates: the server's own, or one that signed it.
	PinnedPeerCertSha256 string `mask:"pinned-peer-cert-sha256,omitempty"`
	// VerifyPeerCertByName is a comma separated list of names the server
	// certificate may be issued for, instead of the server name.
	VerifyPeerCertByName string         `mask:"verify-peer-cert-by-name,omitempty"`
	Other                map[string]any `mask:",remain"`
}

// isEmpty tells that a value of a config asks for nothing: it is absent,
// false, zero, or an empty string, list or map.
func isEmpty(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Slice, reflect.Map, reflect.String:
		return v.Len() == 0
	}
	return v.IsZero()
}

func splitList(list string) []string {
	var items []string
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// Protocols returns the ALPN list.
func (o TLSOptions) Protocols() ([]string, error) {
	switch alpn := o.ALPN.(type) {
	case nil:
		return nil, nil
	case string:
		return splitList(alpn), nil
	case []string:
		return alpn, nil
	case []any:
		list := make([]string, 0, len(alpn))
		for _, item := range alpn {
			protocol, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("tls-config: alpn must be a list of strings")
			}
			list = append(list, protocol)
		}
		return list, nil
	}
	return nil, fmt.Errorf("tls-config: alpn must be a list of strings")
}

// Config builds the TLS config of a client. serverName is used when the
// options name none.
func (o TLSOptions) Config(serverName string) (*tls.Config, error) {
	for key, value := range o.Other {
		if isEmpty(value) {
			continue
		}
		return nil, fmt.Errorf("tls-config: %q is not supported", key)
	}
	alpn, err := o.Protocols()
	if err != nil {
		return nil, err
	}
	if o.ServerName != "" {
		serverName = o.ServerName
	}
	config, err := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{ServerName: serverName, NextProtos: alpn}})
	if err != nil {
		return nil, err
	}
	pins, names := splitList(o.PinnedPeerCertSha256), splitList(o.VerifyPeerCertByName)
	if len(pins) == 0 && len(names) == 0 {
		return config, nil
	}

	// The certificate passes when one of the pins, or without pins one of the
	// names, accepts it.
	var verifiers []func(state tls.ConnectionState) error
	for _, pin := range pins {
		verify, err := ca.NewFingerprintVerifier(pin, config.Time)
		if err != nil {
			return nil, fmt.Errorf("tls-config: pinned-peer-cert-sha256: %w", err)
		}
		checkNames := names
		if len(checkNames) == 0 {
			checkNames = []string{""} // the name of the connection
		}
		for _, name := range checkNames {
			name := name
			verifiers = append(verifiers, func(state tls.ConnectionState) error {
				checked := name
				if checked == "" {
					// An IP address is not sent as the server name and so is
					// not in the state, but the certificate is checked for it.
					if checked = state.ServerName; checked == "" {
						checked = serverName
					}
				}
				return verify(state.PeerCertificates, checked)
			})
		}
	}
	if len(pins) == 0 {
		for _, name := range names {
			verify := ca.NewNameCertVerifier(name, config.RootCAs, config.Time)
			verifiers = append(verifiers, func(state tls.ConnectionState) error {
				return verify(state.PeerCertificates)
			})
		}
	}
	config.InsecureSkipVerify = true // the check is VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		var errs []string
		for _, verify := range verifiers {
			err := verify(state)
			if err == nil {
				return nil
			}
			errs = append(errs, err.Error())
		}
		return errors.New(strings.Join(errs, "; "))
	}
	return config, nil
}
