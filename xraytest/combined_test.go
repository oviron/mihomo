package xraytest

import (
	"testing"
)

// This file checks that the layers the three parts of the Xray parity work
// add go together: the protocols, the transports and TLS, finalmask and
// quic-params. Each part has its own files next to this one.

const (
	cbH3       = `"security":"tls","tlsSettings":{"alpn":["h3"],"certificates":[{"certificateFile":"%CERT%","keyFile":"%KEY%"}]}`
	cbHysteria = `"network":"hysteria","hysteriaSettings":{"version":2,"auth":"%UUID%"},` + cbH3
)

// TestCombinedQuicParams applies the quic-params of finalmask to the QUIC
// transports that carry another protocol: the hysteria transport and XHTTP
// over HTTP/3.
func TestCombinedQuicParams(t *testing.T) {
	// the server names a receive rate, so that brutal has something to agree on
	hysteriaBrutal := cbHysteria + `,"finalmask":{"quicParams":{"congestion":"brutal","brutalUp":"100mbps","brutalDown":"30mbps"}}`
	vlessHysteria := trTLSClient + "network: hysteria\nhysteria-opts: {auth: %UUID%}\nudp: true\n"
	xhttpH3 := trXHTTPServer(cbH3, "")
	vlessXHTTP := trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n"
	vmessXHTTP := "type: vmess\nuuid: %UUID%\nalterId: 0\ncipher: auto\n" + vlessXHTTP
	windows := "init-stream-receive-window: 1048576, max-stream-receive-window: 4194304, " +
		"init-connection-receive-window: 2097152, max-connection-receive-window: 8388608, " +
		"max-idle-timeout: 20, keep-alive-period: 5, disable-path-mtu-discovery: true"

	var cases []trCase
	for name, params := range map[string]string{
		"bbr":          "congestion: bbr, bbr-profile: aggressive",
		"reno":         "congestion: reno",
		"brutal":       "congestion: brutal, brutal-up: 50 mbps, brutal-down: 100 mbps",
		"force-brutal": "congestion: force-brutal, brutal-up: 20 mbps",
		"windows":      windows,
	} {
		finalmask := "finalmask: {quic-params: {" + params + "}}\n"
		cases = append(cases, trCase{
			name:   "vless-hysteria-" + name,
			stream: hysteriaBrutal,
			client: vlessHysteria + finalmask,
		})
		if name == "brutal" {
			// only Hysteria negotiates brutal; Xray panics on it over HTTP/3
			cases = append(cases, trCase{
				name:     "vless-xhttp-h3-brutal-rejected",
				stream:   xhttpH3,
				client:   vlessXHTTP + finalmask,
				parseErr: "brutal",
			})
			continue
		}
		cases = append(cases,
			trCase{name: "vless-xhttp-h3-" + name, stream: xhttpH3, client: vlessXHTTP + finalmask},
			trCase{name: "vmess-xhttp-h3-" + name, protocol: "vmess", stream: xhttpH3, client: vmessXHTTP + finalmask},
		)
	}
	// a UDP mask under the hysteria transport and under XHTTP over HTTP/3
	salamander := `,"finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfs-password"}}]}`
	mask := "finalmask: {udp: [{type: salamander, settings: {password: obfs-password}}], quic-params: {congestion: bbr}}\n"
	cases = append(cases,
		trCase{name: "vless-hysteria-salamander", stream: cbHysteria + salamander, client: "type: vless\nuuid: %UUID%\n" + vlessHysteria + mask},
		trCase{name: "vmess-xhttp-h3-salamander", protocol: "vmess", stream: xhttpH3 + salamander, client: vmessXHTTP + mask},
		trCase{
			name: "vmess-xhttp-h3-salamander-missing", protocol: "vmess", stream: xhttpH3 + salamander, client: vmessXHTTP,
			gap: "the mask is on the server only: this must not work",
		},
	)
	trRun(t, cases)
}
