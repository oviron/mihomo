package xraytest

import (
	"strings"
	"testing"
)

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

// The protocols whose adapters have no transport options take them from
// stream-settings, the transport as a layer under any proxy protocol.
func TestTransportMatrixStreamSettings(t *testing.T) {
	const (
		ws          = `"network":"ws","wsSettings":{"path":"/ws"}`
		grpc        = `"network":"grpc","grpcSettings":{"serviceName":"gun"}`
		httpupgrade = `"network":"httpupgrade","httpupgradeSettings":{"path":"/up"}`
		xhttp       = `"network":"xhttp","xhttpSettings":{"path":"/xh"}`
		kcp         = `"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}`
		raw         = `"network":"raw"`

		tls     = "tls: true, servername: example.org, skip-cert-verify: true"
		reality = "tls: true, servername: example.org, client-fingerprint: chrome, reality-opts: {public-key: %PUB%, short-id: 0123456789abcdef, support-x25519mlkem768: true}"
	)
	type transport struct {
		name, stream, settings string
	}
	transports := []transport{
		{"tls", raw + "," + trTLSServer, tls},
		{"tls-utls", raw + "," + trTLSServer, tls + ", client-fingerprint: chrome"},
		{"reality", raw + "," + trRealityServer, reality},
		{"ws", ws, "network: ws, ws-opts: {path: /ws}"},
		{"ws-tls", ws + "," + trTLSServer, "network: ws, " + tls + ", ws-opts: {path: /ws}"},
		{"httpupgrade-tls", httpupgrade + "," + trTLSServer, "network: httpupgrade, " + tls + ", ws-opts: {path: /up}"},
		{"grpc", grpc, "network: grpc, grpc-opts: {grpc-service-name: gun}"},
		{"grpc-tls", grpc + "," + trTLSServer, "network: grpc, " + tls + ", grpc-opts: {grpc-service-name: gun}"},
		{"grpc-reality", grpc + "," + trRealityServer, "network: grpc, " + reality + ", grpc-opts: {grpc-service-name: gun}"},
		{"xhttp", xhttp, "network: xhttp, xhttp-opts: {path: /xh}"},
		{"xhttp-tls", xhttp + "," + trTLSServer, "network: xhttp, " + tls + ", xhttp-opts: {path: /xh, mode: packet-up, pipeline-posts: true, xmux: {}}"},
		{"xhttp-h3", xhttp + "," + strings.Replace(trTLSServer, "%TLS%", `,"alpn":["h3"]`, 1), "network: xhttp, alpn: [h3], " + tls + ", xhttp-opts: {path: /xh, mode: stream-up}"},
		{"xhttp-reality", xhttp + "," + trRealityServer, "network: xhttp, " + reality + ", xhttp-opts: {path: /xh}"},
		{"kcp", kcp, "network: kcp"},
		{"kcp-tls", kcp + "," + trTLSServer, "network: kcp, " + tls},
	}
	protocols := []struct{ name, inbound, client string }{
		{"ss", "shadowsocks", "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n"},
		{"socks", "socks", "type: socks5\n"},
		{"http", "http", "type: http\n"},
	}
	var cases []trCase
	for _, protocol := range protocols {
		for _, tr := range transports {
			c := trCase{
				name:     protocol.name + "-" + tr.name,
				protocol: protocol.inbound,
				stream:   tr.stream,
				client:   protocol.client + "stream-settings: {" + tr.settings + "}\n",
			}
			if protocol.name == "socks" && (strings.HasPrefix(tr.name, "kcp") || tr.name == "xhttp-h3") {
				// proxy/socks/server.go:112 takes the peer address for a TCP one
				c.gap = "not a client gap: the socks inbound of Xray-core 26.11.9 panics on a transport over UDP"
				c.serverLog = "interface conversion: net.Addr is *net.UDPAddr, not *net.TCPAddr"
			}
			cases = append(cases, c)
		}
	}
	cases = append(cases,
		trCase{
			name: "ss-reality-over-ws-is-refused", protocol: "shadowsocks", stream: raw,
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\nstream-settings: {network: ws, " + reality + "}\n",
			gap:    "not a gap: Xray-core has REALITY for raw, grpc and xhttp only", gapErr: "REALITY goes with",
		},
		trCase{
			name: "ss-unknown-network", protocol: "shadowsocks", stream: raw,
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\nstream-settings: {network: quic}\n",
			gap:    "not a gap: no such transport", gapErr: "unknown network",
		},
	)
	cases = append(cases, trCase{
		name: "trojan-tls-false-with-reality-is-refused", protocol: "trojan", stream: raw + "," + trRealityServer,
		client:   "type: trojan\npassword: %UUID%\ntls: false\nclient-fingerprint: chrome\nreality-opts: {public-key: %PUB%, short-id: 0123456789abcdef}\n",
		parseErr: "REALITY requires TLS",
	})
	trRun(t, cases)
}
