package xraytest

import "testing"

// streamSettings of Xray-core apply to an inbound of any protocol. This is the
// matrix of the protocols other than VLESS against the transports and the
// security layers, for the cells the mihomo adapters have options for. The
// cells without any option are listed in the gap map, not here.
func TestTransportMatrix(t *testing.T) {
	const (
		ws          = `"network":"ws","wsSettings":{"path":"/ws"}`
		grpc        = `"network":"grpc","grpcSettings":{"serviceName":"gun"}`
		httpupgrade = `"network":"httpupgrade","httpupgradeSettings":{"path":"/up"}`
		raw         = `"network":"raw"`

		hysteria = `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},"security":"tls","tlsSettings":{"alpn":["h3"],"certificates":[{"certificateFile":"%CERT%","keyFile":"%KEY%"}]}`

		trojanPlain   = "type: trojan\npassword: %UUID%\ntls: false\n"
		trojan        = "type: trojan\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\n"
		trojanReality = "type: trojan\npassword: %UUID%\nsni: example.org\nclient-fingerprint: chrome\nreality-opts: {public-key: %PUB%, short-id: 0123456789abcdef, support-x25519mlkem768: true}\n"
		vmess         = "type: vmess\nuuid: %UUID%\nalterId: 0\ncipher: auto\n"
		ss            = "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n"
		ssPluginTLS   = "tls: true, host: example.org, skip-cert-verify: true, mux: false"
	)
	trRun(t, []trCase{
		// Trojan
		{name: "trojan-tls", protocol: "trojan", stream: raw + "," + trTLSServer, client: trojan},
		{name: "trojan-ws-tls", protocol: "trojan", stream: ws + "," + trTLSServer, client: trojan + "network: ws\nws-opts: {path: /ws}\n"},
		{name: "trojan-grpc-tls", protocol: "trojan", stream: grpc + "," + trTLSServer, client: trojan + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n"},
		{name: "trojan-httpupgrade-tls", protocol: "trojan", stream: httpupgrade + "," + trTLSServer, client: trojan + "network: ws\nws-opts: {path: /up, v2ray-http-upgrade: true}\n"},
		{name: "trojan-reality", protocol: "trojan", stream: raw + "," + trRealityServer, client: trojanReality},
		{name: "trojan-grpc-reality", protocol: "trojan", stream: grpc + "," + trRealityServer, client: trojanReality + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n"},
		{
			name: "trojan-no-security-default", protocol: "trojan", stream: raw, client: trojan,
			gap: "by design: the trojan adapter wraps the connection in TLS unless tls is false",
		},
		{name: "trojan-no-security", protocol: "trojan", stream: raw, client: trojanPlain},
		{name: "trojan-ws-no-security", protocol: "trojan", stream: ws, client: trojanPlain + "network: ws\nws-opts: {path: /ws}\n"},
		{name: "trojan-grpc-no-security", protocol: "trojan", stream: grpc, client: trojanPlain + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n"},
		{name: "trojan-xhttp-no-security", protocol: "trojan", stream: `"network":"xhttp","xhttpSettings":{"path":"/xh"}`, client: trojanPlain + "network: xhttp\nxhttp-opts: {path: /xh}\n"},
		{name: "trojan-kcp-no-security", protocol: "trojan", stream: `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`, client: trojanPlain + "network: kcp\n"},
		{name: "trojan-hysteria", protocol: "trojan", stream: hysteria, client: trojan + "network: hysteria\nhysteria-opts: {auth: %UUID%}\n"},

		// VMess
		{name: "vmess-raw", protocol: "vmess", stream: raw, client: vmess},
		{name: "vmess-tls", protocol: "vmess", stream: raw + "," + trTLSServer, client: vmess + trTLSClient},
		{name: "vmess-ws", protocol: "vmess", stream: ws, client: vmess + "network: ws\nws-opts: {path: /ws}\n"},
		{name: "vmess-ws-tls", protocol: "vmess", stream: ws + "," + trTLSServer, client: vmess + trTLSClient + "network: ws\nws-opts: {path: /ws}\n"},
		{name: "vmess-grpc-tls", protocol: "vmess", stream: grpc + "," + trTLSServer, client: vmess + trTLSClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n"},
		{name: "vmess-httpupgrade-tls", protocol: "vmess", stream: httpupgrade + "," + trTLSServer, client: vmess + trTLSClient + "network: ws\nws-opts: {path: /up, v2ray-http-upgrade: true}\n"},
		{name: "vmess-reality", protocol: "vmess", stream: raw + "," + trRealityServer, client: vmess + trRealityClient},
		{name: "vmess-hysteria", protocol: "vmess", stream: hysteria, client: vmess + trTLSClient + "network: hysteria\nhysteria-opts: {auth: %UUID%}\n"},
		{name: "vmess-grpc-reality", protocol: "vmess", stream: grpc + "," + trRealityServer, client: vmess + trRealityClient + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n"},

		// Shadowsocks: its transports are the modes of the v2ray-plugin option
		{name: "ss-raw", protocol: "shadowsocks", stream: raw, client: ss},
		{name: "ss-ws", protocol: "shadowsocks", stream: ws, client: ss + "plugin: v2ray-plugin\nplugin-opts: {mode: websocket, path: /ws, mux: false}\n"},
		{name: "ss-ws-tls", protocol: "shadowsocks", stream: ws + "," + trTLSServer, client: ss + "plugin: v2ray-plugin\nplugin-opts: {mode: websocket, path: /ws, " + ssPluginTLS + "}\n"},
		{name: "ss-httpupgrade-tls", protocol: "shadowsocks", stream: httpupgrade + "," + trTLSServer, client: ss + "plugin: v2ray-plugin\nplugin-opts: {mode: websocket, path: /up, v2ray-http-upgrade: true, " + ssPluginTLS + "}\n"},

		// SOCKS and HTTP
		{name: "socks-raw", protocol: "socks", stream: raw, client: "type: socks5\n"},
		{name: "socks-tls", protocol: "socks", stream: raw + "," + trTLSServer, client: "type: socks5\ntls: true\nskip-cert-verify: true\n"},
		{name: "http-raw", protocol: "http", stream: raw, client: "type: http\n"},
		{name: "http-tls", protocol: "http", stream: raw + "," + trTLSServer, client: "type: http\ntls: true\nsni: example.org\nskip-cert-verify: true\n"},
	})
}
