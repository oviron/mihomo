package ca

import (
	"crypto/x509"
	"strings"
	"time"
)

// This file lets `fingerprint` and `name-cert-verify` take comma separated
// lists, as pinnedPeerCertSha256 and verifyPeerCertByName of Xray-core do:
// a list of pins survives a certificate rotation, a list of names fits a
// server reached under several of them.

func splitList(s string) []string {
	var items []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// newFingerprintListVerifier accepts a chain that any of the pins accepts.
func newFingerprintListVerifier(pins []string, time func() time.Time) (func(certs []*x509.Certificate, serverName string) error, error) {
	verifiers := make([]func(certs []*x509.Certificate, serverName string) error, 0, len(pins))
	for _, pin := range pins {
		verifier, err := NewFingerprintVerifier(pin, time)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, verifier)
	}
	return func(certs []*x509.Certificate, serverName string) error {
		err := errNotMatch
		for _, verifier := range verifiers {
			verifyErr := verifier(certs, serverName)
			if verifyErr == nil {
				return nil
			}
			if err == errNotMatch { // keep the error of a pin that matched but did not verify
				err = verifyErr
			}
		}
		return err
	}, nil
}

// anyServerName lets a fingerprint verifier take a list of names for the
// chain check behind a pinned CA: one valid name is enough.
func anyServerName(verifier func(certs []*x509.Certificate, serverName string) error) func(certs []*x509.Certificate, serverName string) error {
	return func(certs []*x509.Certificate, serverName string) error {
		names := splitList(serverName)
		if len(names) < 2 {
			return verifier(certs, serverName)
		}
		var err error
		for _, name := range names {
			if err = verifier(certs, name); err == nil {
				return nil
			}
		}
		return err
	}
}

// newNameListVerifier accepts a chain that is valid for any of the names.
func newNameListVerifier(names []string, roots *x509.CertPool, now func() time.Time) func([]*x509.Certificate) error {
	return func(certificates []*x509.Certificate) error {
		var err error
		for _, name := range names {
			if err = NewNameCertVerifier(name, roots, now)(certificates); err == nil {
				return nil
			}
		}
		return err
	}
}
