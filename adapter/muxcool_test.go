package adapter

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestParseProxyMuxCool(t *testing.T) {
	vless := func(extra map[string]any) map[string]any {
		mapping := map[string]any{
			"name": "vless", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		}
		for k, v := range extra {
			mapping[k] = v
		}
		return mapping
	}
	mux := map[string]any{"enabled": true}

	proxy, err := ParseProxy(vless(map[string]any{"mux": mux}))
	require.NoError(t, err)
	require.NoError(t, proxy.Close())

	// off unless enabled
	proxy, err = ParseProxy(vless(map[string]any{"mux": map[string]any{"concurrency": 8}, "smux": map[string]any{"enabled": true}}))
	require.NoError(t, err)
	require.NoError(t, proxy.Close())

	_, err = ParseProxy(vless(map[string]any{"mux": mux, "smux": map[string]any{"enabled": true}}))
	require.ErrorContains(t, err, "mux and smux")

	_, err = ParseProxy(vless(map[string]any{"mux": map[string]any{"enabled": true, "xudp-proxy-udp443": "maybe"}}))
	require.ErrorContains(t, err, "xudp-proxy-udp443")

	// Mux.Cool is a protocol of the server; a proxy without one cannot take it
	_, err = ParseProxy(map[string]any{"name": "direct", "type": "direct", "mux": mux})
	require.ErrorContains(t, err, "mux is not supported")
}

func TestParseProxyVlessReverse(t *testing.T) {
	mapping := func() map[string]any {
		return map[string]any{
			"name": "bridge", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "reverse": map[string]any{"tag": "from-server"},
		}
	}
	// there is nothing to hand the connections to without a tunnel
	_, err := ParseProxy(mapping())
	require.ErrorContains(t, err, "tunnel")

	// a subscription must not be able to open this network to its server
	_, err = ParseProxy(mapping(), WithTunnelForAPI(testTunnel{}), WithProviderName("subscription"))
	require.ErrorContains(t, err, "provider")

	m := mapping()
	m["reverse"] = map[string]any{"tag": ""}
	_, err = ParseProxy(m, WithTunnelForAPI(testTunnel{}))
	require.ErrorContains(t, err, "tag")

	proxy, err := ParseProxy(mapping(), WithTunnelForAPI(testTunnel{}))
	require.NoError(t, err)
	require.NoError(t, proxy.Close())
}

// The bridge connects only while its proxy is the one the tunnel runs with:
// not for a configuration that is still being loaded and may be rejected, and
// not after the proxy was replaced.
func TestVlessReverseWaitsForItsProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	tunnel := &proxiesTunnel{}
	proxy, err := ParseProxy(map[string]any{
		"name": "bridge", "type": "vless", "server": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "reverse": map[string]any{"tag": "from-server"},
		"mux": map[string]any{"enabled": true}, // the proxy is found under its wrappers
	}, WithTunnelForAPI(tunnel))
	require.NoError(t, err)
	defer proxy.Close()

	select {
	case <-accepted:
		t.Fatal("the bridge connected for a proxy that is not in use")
	case <-time.After(5 * time.Second):
	}

	tunnel.set(map[string]C.Proxy{"bridge": proxy})
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the bridge did not connect for the proxy in use")
	}

	// another proxy took the name: the connection is given up
	tunnel.set(map[string]C.Proxy{})
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.Copy(io.Discard, conn)
	require.NoError(t, err, "the bridge must close its connection")
}

type proxiesTunnel struct {
	testTunnel
	mu      sync.Mutex
	proxies map[string]C.Proxy
}

func (t *proxiesTunnel) set(proxies map[string]C.Proxy) {
	t.mu.Lock()
	t.proxies = proxies
	t.mu.Unlock()
}

func (t *proxiesTunnel) Proxies() map[string]C.Proxy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.proxies
}

type testTunnel struct{}

func (testTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata)        { _ = conn.Close() }
func (testTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) { packet.Drop() }
func (testTunnel) NatTable() C.NatTable                                     { return nil }
