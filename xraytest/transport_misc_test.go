package xraytest

import "testing"

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
			gap:    "no kcp network for vless",
			stream: `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`,
			client: "network: kcp\n",
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
			client: trTLSClient + "network: hysteria\n",
			gap:    "no hysteria network for vless",
		},
	})
}
