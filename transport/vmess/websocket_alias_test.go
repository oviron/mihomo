package vmess

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestOf returns the upgrade request the client sends for the config.
func requestOf(t *testing.T, cfg *WebsocketConfig) *http.Request {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	requests := make(chan *http.Request, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			requests <- req
		}
	}()
	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = StreamWebsocketConn(ctx, conn, cfg) // fails, the server only records
	select {
	case req := <-requests:
		return req
	case <-time.After(3 * time.Second):
		t.Fatal("no request")
		return nil
	}
}

// User-Agent: chrome and the like stand for the headers of that browser, as in
// Xray-core. Without a User-Agent the request is what it always was.
func TestBrowserAlias(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		plain := requestOf(t, &WebsocketConfig{Host: "example.org", Port: "80", Path: "/", Headers: http.Header{}, V2rayHttpUpgrade: upgrade})
		assert.Empty(t, plain.Header.Get("Sec-Fetch-Mode"))
		assert.NotContains(t, plain.Header.Get("User-Agent"), "Mozilla")

		chrome := requestOf(t, &WebsocketConfig{Host: "example.org", Port: "80", Path: "/", Headers: http.Header{"User-Agent": {"chrome"}}, V2rayHttpUpgrade: upgrade})
		assert.Contains(t, chrome.Header.Get("User-Agent"), "Chrome/")
		assert.Equal(t, "websocket", chrome.Header.Get("Sec-Fetch-Mode"))

		firefox := requestOf(t, &WebsocketConfig{Host: "example.org", Port: "80", Path: "/", Headers: http.Header{"User-Agent": {"firefox"}}, V2rayHttpUpgrade: upgrade})
		assert.Contains(t, firefox.Header.Get("User-Agent"), "Firefox/")

		custom := requestOf(t, &WebsocketConfig{Host: "example.org", Port: "80", Path: "/", Headers: http.Header{"User-Agent": {"my-agent/1.0"}}, V2rayHttpUpgrade: upgrade})
		assert.Equal(t, "my-agent/1.0", custom.Header.Get("User-Agent"))
		assert.Empty(t, custom.Header.Get("Sec-Fetch-Mode"))
	}
}
