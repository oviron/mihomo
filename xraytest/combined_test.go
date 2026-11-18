package xraytest

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

// TestCombinedXHTTPDownloadFinalmask: the download leg of XHTTP goes to a
// server of its own, so the masks of the proxy do not apply to it; it takes
// the finalmask of download-settings. Two taps in front of one inbound show
// which leg got its ClientHello cut in pieces by the fragment mask.
func TestCombinedXHTTPDownloadFinalmask(t *testing.T) {
	tg := startTargets(t)
	const fragment = "finalmask: {tcp: [{type: fragment, settings: {packets: tlshello, length: 20-40, delay: 1-2}}]}"
	for _, protocol := range []string{"vless", "vmess"} {
		for name, masks := range map[string]struct{ upload, download bool }{
			"upload-only":   {true, false},
			"download-only": {false, true},
			"both":          {true, true},
			"none":          {false, false},
		} {
			t.Run(protocol+"-"+name, func(t *testing.T) {
				port := freePort(t)
				trStartXray(t, trInbound(t, protocol, trFill(t, trXHTTPServer(trTLSServer, ""), port, 0), port))
				upload, download := fmStartTap(t, port), fmStartTap(t, port)

				client := "type: vless\nuuid: %UUID%\n"
				if protocol == "vmess" {
					client = "type: vmess\nuuid: %UUID%\nalterId: 0\ncipher: auto\n"
				}
				client += trTLSClient + "network: xhttp\nxhttp-opts:\n  path: /xh\n  mode: packet-up\n" +
					"  download-settings:\n    server: 127.0.0.1\n    port: " + strconv.Itoa(download.port) + "\n"
				if masks.download {
					client += "    " + fragment + "\n"
				}
				if masks.upload {
					client += fragment + "\n"
				}
				proxy, err := trParseProxy(trFill(t, client, port, 0), upload.port)
				require.NoError(t, err)
				defer proxy.Close()
				require.NoError(t, trRoundTrip(proxy, tg, 1<<20, 30*time.Second))

				// a ClientHello in one record, or in pieces of 20 to 39 bytes
				fragmented := func(tap *fmTap) bool {
					records := tap.handshakeRecords()
					require.NotEmpty(t, records, "the leg was not used")
					return len(records) >= 4
				}
				require.Equal(t, masks.upload, fragmented(upload), "upload leg")
				require.Equal(t, masks.download, fragmented(download), "download leg")
			})
		}
	}
}
