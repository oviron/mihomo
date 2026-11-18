package gun

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

func TestAuthority(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	hosts := make(chan string, 2)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hosts <- r.Host
		}),
	}
	go func() { _ = server.Serve(l) }()
	defer server.Close()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	for _, c := range []struct{ authority, want string }{
		{"", "sni.example.org"},
		{"front.example.org", "front.example.org"},
	} {
		transport := NewTransport(dial, nil, &Config{ServiceName: "gun", Host: "sni.example.org", Authority: c.authority})
		conn, err := transport.Dial()
		require.NoError(t, err)
		select {
		case host := <-hosts:
			require.Equal(t, c.want, host)
		case <-time.After(5 * time.Second):
			t.Fatal("no request")
		}
		_ = conn.Close()
		_ = transport.Close()
	}
}

func TestUserAgentAlias(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	agents := make(chan string, 4)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Protocols: protocols,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { agents <- r.UserAgent() }),
	}
	go func() { _ = server.Serve(l) }()
	defer server.Close()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	for agent, want := range map[string]string{"": "grpc-go/1.36.0", "chrome": "Chrome/", "firefox": "Firefox/", "edge": "Edg/", "my-agent": "my-agent", "golang": "grpc-go/1.36.0"} {
		transport := NewTransport(dial, nil, &Config{ServiceName: "gun", Host: "example.org", UserAgent: agent})
		conn, err := transport.Dial()
		require.NoError(t, err)
		select {
		case got := <-agents:
			require.Contains(t, got, want, agent)
		case <-time.After(5 * time.Second):
			t.Fatal("no request")
		}
		_ = conn.Close()
		_ = transport.Close()
	}
}
