package xraytest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTransportGRPC(t *testing.T) {
	grpc := func(settings, security string) string {
		return `"network":"grpc","grpcSettings":{` + settings + `},` + security
	}
	trRun(t, []trCase{
		{
			name:   "tls",
			stream: grpc(`"serviceName":"gun"`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n",
		},
		{
			name:   "reality",
			stream: grpc(`"serviceName":"gun"`, trRealityServer),
			client: trRealityClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n",
		},
		{
			name:   "multi-mode-server",
			stream: grpc(`"serviceName":"gun","multiMode":true`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n",
		},
		{
			name:   "custom-path",
			stream: grpc(`"serviceName":"/api/v1/Stream|Multi"`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: /api/v1/Stream}\n",
		},
		{
			name:   "service-name-to-escape",
			gap:    "Xray escapes the service name, mihomo sends it as written; write it escaped",
			stream: grpc(`"serviceName":"my gun"`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: my gun}\n",
		},
		{
			name:   "service-name-escaped-by-hand",
			stream: grpc(`"serviceName":"my gun"`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: my%20gun}\n",
		},
		{
			name:   "authority",
			stream: grpc(`"serviceName":"gun"`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun, authority: front.example.org}\n",
		},
		{
			name:   "keepalive-and-user-agent",
			stream: grpc(`"serviceName":"gun","idle_timeout":10,"health_check_timeout":5`, trTLSServer),
			client: trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun, grpc-user-agent: chrome, ping-interval: 10}\n",
		},
		{
			name:   "plain",
			stream: `"network":"grpc","grpcSettings":{"serviceName":"gun"}`,
			client: "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n",
		},
	})
}

func TestTransportWebSocket(t *testing.T) {
	trRun(t, []trCase{
		{
			name:   "tls",
			stream: `"network":"ws","wsSettings":{"path":"/ws","host":"ws.example.org"},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: /ws, headers: {Host: ws.example.org}}\n",
		},
		{
			name:   "plain-early-data",
			stream: `"network":"ws","wsSettings":{"path":"/ws?ed=2560"}`,
			client: "network: ws\nws-opts: {path: \"/ws?ed=2560\"}\n",
		},
		{
			name:   "early-data-options",
			stream: `"network":"ws","wsSettings":{"path":"/ws"},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: /ws, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol}\n",
		},
		{
			name:   "heartbeat-server",
			stream: `"network":"ws","wsSettings":{"path":"/ws","heartbeatPeriod":1},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: /ws}\n",
		},
		{
			name:   "utls-chrome",
			stream: `"network":"ws","wsSettings":{"path":"/ws"},` + trTLSServer,
			client: trTLSClient + "client-fingerprint: chrome\nnetwork: ws\nws-opts: {path: /ws}\n",
		},
	})
}

func TestTransportHTTPUpgrade(t *testing.T) {
	trRun(t, []trCase{
		{
			name:   "tls",
			stream: `"network":"httpupgrade","httpupgradeSettings":{"path":"/up","host":"up.example.org"},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: /up, headers: {Host: up.example.org}, v2ray-http-upgrade: true}\n",
		},
		{
			name:   "tls-early-data-fast-open",
			stream: `"network":"httpupgrade","httpupgradeSettings":{"path":"/up?ed=2560"},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: /up, v2ray-http-upgrade: true, v2ray-http-upgrade-fast-open: true}\n",
		},
		{
			name:   "tls-early-data-ed-in-path",
			stream: `"network":"httpupgrade","httpupgradeSettings":{"path":"/up?ed=2560"},` + trTLSServer,
			client: trTLSClient + "network: ws\nws-opts: {path: \"/up?ed=2560\", v2ray-http-upgrade: true}\n",
		},
	})
}

func TestTransportRAW(t *testing.T) {
	trRun(t, []trCase{
		{
			name:   "plain",
			stream: `"network":"raw"`,
			client: "",
		},
		{
			name:   "sockopt",
			stream: `"network":"raw",` + trTLSServer,
			client: trTLSClient + "sockopt: {tcp-user-timeout: 10000, tcp-max-seg: 1200, tcp-window-clamp: 65535, tcp-congestion: reno, tcp-keep-alive-idle: 30, tcp-keep-alive-interval: 10}\n",
		},
		{
			name:   "sockopt-xhttp",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh}\nsockopt: {tcp-user-timeout: 10000, tcp-max-seg: 1200}\n",
		},
		{
			name:   "http-header",
			stream: `"network":"raw","rawSettings":{"header":{"type":"http","request":{"path":["/a","/b"],"headers":{"Host":["a.example.org"]}}}}`,
			client: "network: http\nhttp-opts: {method: GET, path: [/a], headers: {Host: [a.example.org]}}\n",
		},
		{
			name:   "http-header-defaults",
			stream: `"network":"raw","rawSettings":{"header":{"type":"http"}}`,
			client: "network: http\nhttp-opts: {}\n",
		},
		{
			name:   "http-header-tls",
			stream: `"network":"raw","rawSettings":{"header":{"type":"http","request":{"path":["/a"]}}},` + trTLSServer,
			client: trTLSClient + "network: http\nhttp-opts: {path: [/a]}\n",
		},
	})
}

func TestTransportMKCP(t *testing.T) {
	vmess := "type: vmess\nuuid: %UUID%\nalterId: 0\ncipher: auto\n"
	trRun(t, []trCase{
		{
			name:     "vmess-no-mask",
			gap:      "mihomo always applies the legacy mKCP packet authenticator, Xray 26 has it as the mkcp-legacy mask only",
			protocol: "vmess",
			stream:   `"network":"kcp","kcpSettings":{}`,
			client:   vmess + "network: kcp\n",
		},
		{
			name:     "vmess-legacy-mask",
			protocol: "vmess",
			stream:   `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`,
			client:   vmess + "network: kcp\n",
		},
		{
			name:     "vmess-legacy-mask-seed",
			protocol: "vmess",
			stream:   `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"value":"secret"}}]}`,
			client:   vmess + "network: kcp\nmkcp-opts: {seed: secret}\n",
		},
		{
			name:     "vmess-tuned",
			protocol: "vmess",
			stream:   `"network":"kcp","kcpSettings":{"mtu":1200,"tti":20,"uplinkCapacity":50,"downlinkCapacity":100},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`,
			client:   vmess + "network: kcp\nmkcp-opts: {mtu: 1200, tti: 20, uplink-capacity: 50, downlink-capacity: 100}\n",
		},
		{
			name:   "vless",
			stream: `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`,
			client: "network: kcp\n",
		},
		{
			name:   "vless-seed-tuned",
			stream: `"network":"kcp","kcpSettings":{"mtu":1200,"tti":20},"finalmask":{"udp":[{"type":"mkcp-legacy","settings":{"value":"secret"}}]}`,
			client: "network: kcp\nmkcp-opts: {seed: secret, mtu: 1200, tti: 20}\n",
		},
		{
			name:   "vless-tls",
			stream: `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]},` + trTLSServer,
			client: trTLSClient + "network: kcp\n",
		},
		{
			name:     "trojan-tls",
			protocol: "trojan",
			stream:   `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]},` + trTLSServer,
			client:   "type: trojan\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\nnetwork: kcp\n",
		},
	})
}

func TestTransportHysteria(t *testing.T) {
	h3 := `"security":"tls","tlsSettings":{"alpn":["h3"],"certificates":[{"certificateFile":"%CERT%","keyFile":"%KEY%"}]}`
	trRun(t, []trCase{
		{
			name:     "hysteria2-outbound",
			protocol: "hysteria",
			stream:   `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + h3,
			client:   "type: hysteria2\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\n",
		},
		{
			name:   "vless-over-hysteria",
			stream: `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + h3,
			client: trTLSClient + "network: hysteria\nhysteria-opts: {version: 2, auth: %UUID%}\nudp: true\n",
			check: func(t *testing.T, x *xray, proxy C.Proxy, tg targets) {
				trCheck(t, proxy, tg)
				checkUDP(t, proxy, tg) // inside the stream, the transport itself carries no UDP here
				// several streams share the one connection
				errs := make(chan error, 8)
				for i := 0; i < cap(errs); i++ {
					go func() { errs <- trRoundTrip(proxy, tg, 256<<10, 30*time.Second) }()
				}
				for i := 0; i < cap(errs); i++ {
					require.NoError(t, <-errs)
				}
			},
		},
		{
			name:     "trojan-over-hysteria",
			protocol: "trojan",
			stream:   `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + h3,
			client:   "type: trojan\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\nnetwork: hysteria\nhysteria-opts: {auth: %UUID%}\n",
		},
		{
			name:   "vless-over-hysteria-pinned",
			stream: `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + h3,
			client: "tls: true\nservername: example.org\nfingerprint: %PIN%\nnetwork: hysteria\nhysteria-opts: {auth: %UUID%}\n",
		},
		{
			name:   "vless-over-hysteria-wrong-auth",
			stream: `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + h3,
			client: trTLSClient + "network: hysteria\nhysteria-opts: {auth: not-the-auth}\n",
			gap:    "not a gap: the server refuses the auth",
			gapErr: "auth failed",
		},
	})
}

// trZone is a resolver of the proxy servers with a few records of its own:
// what a DNS zone of the server operator would hold.
type trZone struct {
	records []string
}

func (z *trZone) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	reply := new(dns.Msg)
	reply.SetReply(m)
	for _, record := range z.records {
		rr, err := dns.NewRR(record)
		if err != nil {
			return nil, err
		}
		if rr.Header().Name == m.Question[0].Name && rr.Header().Rrtype == m.Question[0].Qtype {
			reply.Answer = append(reply.Answer, rr)
		}
	}
	return reply, nil
}

func (z *trZone) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
func (z *trZone) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return z.LookupIP(ctx, host)
}
func (z *trZone) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, errors.New("no IPv6")
}
func (z *trZone) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, errors.New("no ECH")
}
func (z *trZone) Invalid() bool    { return true }
func (z *trZone) ClearCache()      {}
func (z *trZone) ResetConnection() {}

// The server is found through a SRV or a TXT record of its name, so its
// address and port can be moved by changing the record.
func TestTransportAddressPortStrategy(t *testing.T) {
	tg := startTargets(t)
	port := freePort(t)
	trStartXray(t, trInbound(t, "vless", trFill(t, trXHTTPServer(trTLSServer, ""), port, 0), port))

	old := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = &trZone{records: []string{
		fmt.Sprintf(`_xray._tcp.example.org. 60 IN SRV 0 0 %d entry.example.org.`, port),
		fmt.Sprintf(`moved.example.org. 60 IN TXT "127.0.0.1:%d"`, port),
	}}
	defer func() { resolver.ProxyServerHostResolver = old }()

	for server, strategy := range map[string]string{
		"_xray._tcp.example.org": "SrvPortAndAddress",
		"moved.example.org":      "txtportandaddress",
	} {
		proxy, err := adapter.ParseProxy(map[string]any{
			"name": "xray", "type": "vless", "uuid": userUUID,
			"server": server, "port": 1, // the port to dial comes from the record
			"tls": true, "servername": trServerName, "skip-cert-verify": true,
			"network": "xhttp", "xhttp-opts": map[string]any{"path": "/xh"},
			"sockopt": map[string]any{"address-port-strategy": strategy},
		})
		require.NoError(t, err)
		require.NoError(t, trRoundTrip(proxy, tg, 1<<20, 20*time.Second), strategy)
		_ = proxy.Close()
	}
}
