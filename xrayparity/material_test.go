//go:build xray_parity

package xrayparity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

const serverName = "example.org"

// material is the key material shared by the tests, made once per run.
type material struct {
	certPEM, keyPEM []byte
	certSHA256      string // hex of the leaf certificate, for pinning
	tlsCert         tls.Certificate

	realityPrivate, realityPublic string
	mldsaSeed, mldsaVerify        string
	echConfigList, echServerKeys  string
}

var (
	materialOnce sync.Once
	materialVal  *material
)

func getMaterial(t *testing.T) *material {
	t.Helper()
	materialOnce.Do(func() {
		m := &material{}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: serverName},
			DNSNames:     []string{serverName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			// REALITY fits its own certificate, with the ML-DSA-65 signature when
			// one is set, into the size of the target's, so keep this one large
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 4500)}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		m.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		m.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		sum := sha256.Sum256(der)
		m.certSHA256 = hex.EncodeToString(sum[:])
		m.tlsCert, err = tls.X509KeyPair(m.certPEM, m.keyPEM)
		if err != nil {
			t.Fatal(err)
		}

		out := xrayTool(t, "x25519")
		m.realityPrivate = field(t, out, "PrivateKey")
		m.realityPublic = field(t, out, "Password")

		out = xrayTool(t, "mldsa65")
		m.mldsaSeed = field(t, out, "Seed")
		m.mldsaVerify = field(t, out, "Verify")

		out = xrayTool(t, "tls", "ech", "--serverName", serverName)
		m.echConfigList = field(t, out, "ECH config list")
		m.echServerKeys = field(t, out, "ECH server keys")

		materialVal = m
	})
	if materialVal == nil {
		t.Fatal("key material was not generated")
	}
	return materialVal
}

func (m *material) files() map[string][]byte {
	return map[string][]byte{"cert.pem": m.certPEM, "key.pem": m.keyPEM}
}

// realityTarget is a local TLS 1.3 site for the REALITY server to borrow the
// handshake from, so the tests need no internet. It returns its port.
func realityTarget(t *testing.T) int {
	t.Helper()
	addr := "0.0.0.0:0"
	if runtime.GOOS == "darwin" {
		addr = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html><a href="/a">a</a><a href="/b">b</a></html>`))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{getMaterial(t).tlsCert},
			MinVersion:   tls.VersionTLS13,
			// listed by hand: the go directive of this module is older than the
			// release that turned the hybrid group on by default
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
			NextProtos:       []string{"h2", "http/1.1"},
		},
	}
	go func() { _ = server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return l.Addr().(*net.TCPAddr).Port
}
