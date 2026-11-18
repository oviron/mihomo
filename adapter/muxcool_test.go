package adapter

import (
	"net"
	"testing"

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

type testTunnel struct{}

func (testTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata)        { _ = conn.Close() }
func (testTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) { packet.Drop() }
func (testTunnel) NatTable() C.NatTable                                     { return nil }
