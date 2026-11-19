// The REALITY target below must offer X25519MLKEM768, which the go directive
// of this module would otherwise turn off in crypto/tls.
//
//go:debug tlsmlkem=1
package xraytest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// This file is the frame of the transport checks: a table of server stream
// settings (Xray JSON) against client proxies (mihomo YAML), with the key
// material both sides need.

const trServerName = "example.org"

const (
	trTLSServer     = `"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"%CERT%","keyFile":"%KEY%"}]%TLS%}`
	trRealityServer = `"security":"reality","realitySettings":{"show":true,"target":"127.0.0.1:%TARGET%","serverNames":["example.org"],"privateKey":"%PRIV%","shortIds":["0123456789abcdef"]%REALITY%}`

	trTLSClient = `
tls: true
servername: example.org
skip-cert-verify: true
`
	trRealityClient = `
tls: true
servername: example.org
client-fingerprint: chrome
reality-opts:
  public-key: %PUB%
  short-id: 0123456789abcdef
  support-x25519mlkem768: true
`
)

// trMaterial is the key material shared by the transport checks, made once.
type trMaterial struct {
	certFile, keyFile string
	certSHA256        string // hex of the leaf certificate, for pinning
	tlsCert           tls.Certificate

	realityPrivate, realityPublic string
	mldsaSeed, mldsaVerify        string
	echConfigList, echServerKeys  string
}

var (
	trMaterialOnce sync.Once
	trMaterialVal  *trMaterial
)

// trXrayTool runs a one-shot xray subcommand and returns its output.
func trXrayTool(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(xrayBin(t), args...).CombinedOutput()
	require.NoError(t, err, string(out))
	return string(out)
}

// trField returns the value that follows "name:" in the output of an xray
// tool, on the same line or on the next one.
func trField(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, name) {
			continue
		}
		if _, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		if i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	t.Fatalf("no %q in:\n%s", name, out)
	return ""
}

func trGetMaterial(t *testing.T) *trMaterial {
	t.Helper()
	xrayBin(t) // skip before anything is made
	trMaterialOnce.Do(func() {
		m := &trMaterial{}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: trServerName},
			DNSNames:     []string{trServerName, "second.example.org"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			// REALITY fits its own certificate, with the ML-DSA-65 signature when
			// one is set, into the size of the target's, so keep this one large
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 4500)}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		sum := sha256.Sum256(der)
		m.certSHA256 = hex.EncodeToString(sum[:])
		m.tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)

		dir, err := os.MkdirTemp("", "xraytest-transport")
		require.NoError(t, err)
		m.certFile = filepath.Join(dir, "cert.pem")
		m.keyFile = filepath.Join(dir, "key.pem")
		require.NoError(t, os.WriteFile(m.certFile, certPEM, 0o644))
		require.NoError(t, os.WriteFile(m.keyFile, keyPEM, 0o644))

		out := trXrayTool(t, "x25519")
		m.realityPrivate = trField(t, out, "PrivateKey")
		m.realityPublic = trField(t, out, "Password")

		out = trXrayTool(t, "mldsa65")
		m.mldsaSeed = trField(t, out, "Seed")
		m.mldsaVerify = trField(t, out, "Verify")

		out = trXrayTool(t, "tls", "ech", "--serverName", trServerName)
		m.echConfigList = trField(t, out, "ECH config list")
		m.echServerKeys = trField(t, out, "ECH server keys")

		trMaterialVal = m
	})
	if trMaterialVal == nil {
		t.Fatal("key material was not generated")
	}
	return trMaterialVal
}

// trRealityTarget is a local TLS 1.3 site for the REALITY server to borrow the
// handshake from, so the checks need no internet. It returns its port.
func trRealityTarget(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html><a href="/a">a</a><a href="/b">b</a></html>`))
		}),
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{trGetMaterial(t).tlsCert},
			MinVersion:       tls.VersionTLS13,
			NextProtos:       []string{"h2", "http/1.1"},
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		},
		ErrorLog: nil,
	}
	go func() { _ = server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// trCase is one server/client pair. In both configs %NAME% placeholders are
// filled from the key material.
type trCase struct {
	name     string
	protocol string // inbound protocol, vless by default
	stream   string // contents of streamSettings, without the braces
	client   string // mihomo proxy YAML, without name, server and port
	// serverLog, when set, must appear in the Xray log after the round trip.
	serverLog string
	// gap, when set, says why the pair is known not to work: the round trip
	// must fail, and the case fails once it starts to pass.
	gap string
	// gapErr, when set, must be part of the error of a gap case, so that the
	// case cannot pass on some unrelated failure.
	gapErr string
	// parseErr, when set, must be part of the error of building the proxy.
	parseErr string
	// check replaces the default round trip.
	check func(t *testing.T, x *xray, proxy C.Proxy, tg targets)
}

func trFill(t *testing.T, s string, port, target int) string {
	m := trGetMaterial(t)
	return strings.NewReplacer(
		"%PORT%", strconv.Itoa(port),
		"%TARGET%", strconv.Itoa(target),
		"%CERT%", m.certFile,
		"%KEY%", m.keyFile,
		"%PRIV%", m.realityPrivate,
		"%PUB%", m.realityPublic,
		"%SEED%", m.mldsaSeed,
		"%VERIFY%", m.mldsaVerify,
		"%ECHKEYS%", m.echServerKeys,
		"%ECHLIST%", m.echConfigList,
		"%PIN%", m.certSHA256,
		"%UUID%", userUUID,
		"%TLS%", "", "%REALITY%", "",
	).Replace(s)
}

func trInbound(t *testing.T, protocol, stream string, port int) obj {
	t.Helper()
	var settings obj
	switch protocol {
	case "", "vless":
		protocol = "vless"
		settings = obj{"clients": []obj{{"id": userUUID}}, "decryption": "none"}
	case "vless-vision":
		protocol = "vless"
		settings = obj{"clients": []obj{{"id": userUUID, "flow": "xtls-rprx-vision"}}, "decryption": "none"}
	case "vmess":
		settings = obj{"clients": []obj{{"id": userUUID}}}
	case "trojan":
		settings = obj{"clients": []obj{{"password": userUUID}}}
	case "hysteria":
		settings = obj{"version": 2, "clients": []obj{{"auth": userUUID}}}
	case "shadowsocks":
		settings = obj{"method": "aes-128-gcm", "password": userUUID, "network": "tcp"}
	case "socks":
		settings = obj{"auth": "noauth"}
	case "http":
		settings = obj{}
	}
	var streamSettings obj
	require.NoError(t, json.Unmarshal([]byte("{"+stream+"}"), &streamSettings), stream)
	return obj{"listen": "127.0.0.1", "port": port, "protocol": protocol, "settings": settings, "streamSettings": streamSettings}
}

// trStartXray starts Xray trusting the certificate of the key material, which
// REALITY needs to probe the local target. The variable is set only while the
// process is being started.
func trStartXray(t *testing.T, inbounds ...obj) *xray {
	t.Helper()
	const name = "SSL_CERT_FILE"
	old, had := os.LookupEnv(name)
	require.NoError(t, os.Setenv(name, trGetMaterial(t).certFile))
	defer func() {
		if had {
			_ = os.Setenv(name, old)
		} else {
			_ = os.Unsetenv(name)
		}
	}()
	return startXray(t, inbounds...)
}

func trParseProxy(proxyYAML string, port int) (C.Proxy, error) {
	mapping := map[string]any{}
	if err := yaml.Unmarshal([]byte(proxyYAML), &mapping); err != nil {
		return nil, err
	}
	mapping["name"] = "xray"
	mapping["server"] = "127.0.0.1"
	mapping["port"] = port
	return adapter.ParseProxy(mapping)
}

// trRoundTrip sends size random bytes to the echo target on a new stream and
// expects them back.
func trRoundTrip(proxy C.ProxyAdapter, tg targets, size int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := proxy.DialContext(ctx, tcpMetadata(tg.tcp))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	sent := make([]byte, size)
	_, _ = rand.Read(sent)
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(sent)
		writeErr <- err
	}()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if err := <-writeErr; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if string(sent) != string(got) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// trCheck pushes a small and a large payload, each on its own stream.
func trCheck(t *testing.T, proxy C.ProxyAdapter, tg targets) {
	t.Helper()
	for _, size := range []int{16, 3 << 20} {
		require.NoError(t, trRoundTrip(proxy, tg, size, 30*time.Second), "round trip of %d bytes", size)
	}
}

func trRun(t *testing.T, cases []trCase) {
	tg := startTargets(t)
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			target := 0
			if strings.Contains(c.stream, "%TARGET%") {
				target = trRealityTarget(t)
			}
			port := freePort(t)
			x := trStartXray(t, trInbound(t, c.protocol, trFill(t, c.stream, port, target), port))
			client := c.client
			if !strings.Contains(client, "type:") {
				client = "type: vless\nuuid: %UUID%\n" + client
			}
			proxy, err := trParseProxy(trFill(t, client, port, target), port)
			if c.parseErr != "" {
				require.ErrorContains(t, err, c.parseErr)
				return
			}
			require.NoError(t, err, "parse proxy")
			t.Cleanup(func() { _ = proxy.Close() })
			if c.gap != "" {
				err = trRoundTrip(proxy, tg, 16, 5*time.Second)
				require.Error(t, err, "works now, drop the gap mark: %s", c.gap)
				if c.gapErr != "" {
					require.ErrorContains(t, err, c.gapErr)
				}
				t.Logf("known gap (%s): %v", c.gap, err)
				if c.serverLog != "" {
					x.waitCount(t, c.serverLog, 1)
				}
				return
			}
			if c.check != nil {
				c.check(t, x, proxy, tg)
			} else {
				trCheck(t, proxy, tg)
			}
			if c.serverLog != "" {
				require.Contains(t, x.log.String(), c.serverLog)
			}
		})
	}
}
