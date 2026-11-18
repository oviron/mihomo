package outbound

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// storageServer is an HTTPS server that offers the given ALPN protocols and
// answers with the protocol of the request.
func storageServer(t *testing.T, alpn []string) string {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn})
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + l.Addr().String()
}

// The storage is spoken to in the protocol its TLS handshake settles on, also
// when the ALPN list is that of a browser fingerprint.
func TestXDriveHTTPClient(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	plainServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})}
	go func() { _ = plainServer.Serve(plain) }()
	defer plainServer.Close()

	servers := map[string]string{
		"HTTP/2.0 from a server with h2":      storageServer(t, []string{"h2", "http/1.1"}),
		"HTTP/1.1 from a server without h2":   storageServer(t, []string{"http/1.1"}),
		"HTTP/1.1 from a server without ALPN": storageServer(t, nil),
		"HTTP/1.1 from a server without TLS":  "http://" + plain.Addr().String(),
	}
	for _, fingerprint := range []string{"", "chrome", "firefox"} {
		client := xdriveHTTPClient(dialer.NewDialer(), &VlessOption{SkipCertVerify: true, ClientFingerprint: fingerprint}, nil)
		for want, url := range servers {
			for i := 0; i < 3; i++ { // the first request probes, the rest reuse
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+"/object", nil)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err, "%s, fingerprint %q", want, fingerprint)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, strings.Fields(want)[0], string(body), "%s, fingerprint %q", want, fingerprint)
			}
		}
		client.CloseIdleConnections()
	}
}
