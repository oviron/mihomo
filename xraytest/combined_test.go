package xraytest

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

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

// The access log of Xray names the source of a Mux.Cool session with its
// network ("from tcp:127.0.0.1:1 accepted ..."), and the source of a
// connection the inbound took itself without.
var (
	cbDirect    = regexp.MustCompile(`from [0-9.]+:[0-9]+ accepted `)
	cbDirectUDP = regexp.MustCompile(`from [0-9.]+:[0-9]+ accepted udp:`)
)

// cbPastMux counts the connections and associations that reached the inbound
// outside Mux.Cool.
func cbPastMux(x *xray, re *regexp.Regexp) int {
	return len(re.FindAllStringIndex(x.log.String(), -1))
}

// cbMuxCheck pushes streams and packets through a proxy with mux and expects
// one Mux.Cool connection on the server to have carried them all.
func cbMuxCheck(t *testing.T, x *xray, proxy C.Proxy, tg targets) {
	t.Helper()
	checkTCP(t, proxy, tg)
	checkUDP(t, proxy, tg)
	// the server took both as sessions of Mux.Cool
	x.waitCount(t, "common/mux: received request for tcp:", 1)
	x.waitCount(t, "common/mux: received request for udp:", 1)
	checkTLS(t, proxy, tg)
	checkUDPFullCone(t, proxy, tg)
	parallel(t, 6, func(t *testing.T) {
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
	require.Equal(t, 1, carriers(x), "everything must share one Mux.Cool connection")
	require.Equal(t, 0, cbPastMux(x, cbDirect), "something went past Mux.Cool")
}

// cbMuxXHTTPCheck is cbMuxCheck for an inbound on XHTTP, which takes UDP in
// Mux.Cool only: TCP stays on the streams of XHTTP, UDP shares one Mux.Cool
// connection.
func cbMuxXHTTPCheck(t *testing.T, x *xray, proxy C.Proxy, tg targets) {
	t.Helper()
	checkTCP(t, proxy, tg)
	checkTLS(t, proxy, tg)
	x.waitFor(t, "two TCP connections outside Mux.Cool", func() bool { return cbPastMux(x, cbDirect) >= 2 })
	require.Equal(t, 0, carriers(x), "TCP must not go into Mux.Cool on XHTTP")
	checkUDP(t, proxy, tg)
	x.waitCount(t, "common/mux: received request for udp:", 1)
	checkUDPFullCone(t, proxy, tg)
	parallel(t, 6, func(t *testing.T) {
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
	// without mux every UDP association is a connection of its own: an XUDP
	// one to v1.mux.cool for VLESS, a UDP one for Trojan
	require.Equal(t, 1, carriers(x), "the UDP sessions must share one Mux.Cool connection")
	require.Equal(t, 0, cbPastMux(x, cbDirectUDP), "a UDP association went past Mux.Cool")
	require.Equal(t, 0, x.count("common/mux: received request for tcp:"), "a TCP stream went into Mux.Cool")
}

// TestCombinedLayers runs the stacks that take a piece from each part of the
// parity work.
func TestCombinedLayers(t *testing.T) {
	tg := startTargets(t)

	// XTLS Vision with the padding law of Xray (testseed) over a TLS handshake
	// that the fragment mask cuts in pieces.
	t.Run("vless-vision-testseed-fragment", func(t *testing.T) {
		const flow = "xtls-rprx-vision"
		port := freePort(t)
		x := startXray(t, inbound("vless", port, obj{
			"clients": []obj{{"id": userUUID, "flow": flow}}, "decryption": "none",
		}, tlsStream()))
		tap := fmStartTap(t, port)
		proxy := newProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"testseed":  []int{900, 500, 900, 256},
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{"packets": "tlshello", "length": "20-40", "delay": "1-2"})}},
		})
		for i := 0; i < 4; i++ {
			checkTLS(t, proxy, tg)
		}
		checkVisionDirect(t, x)
		// the outer ClientHello came in pieces
		records := tap.handshakeRecords()
		require.GreaterOrEqual(t, len(records), 4)
		// the inner ClientHello, longer than 900 bytes, got the padding of Xray
		hellos := func() (blocks []visionBlock) {
			for _, b := range visionClientBlocks(x) {
				if b.content >= 900 && b.content < 2000 {
					blocks = append(blocks, b)
				}
			}
			return
		}
		// Xray may drop log lines, two of the four are enough
		x.waitFor(t, "inner ClientHello blocks", func() bool { return len(hellos()) >= 2 })
		padded := 0
		for _, b := range hellos() {
			require.Less(t, b.padding, 256)
			if b.padding > 0 {
				padded++
			}
		}
		require.Greater(t, padded, 0, "%v", hellos())
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
	})

	// Mux.Cool in a WebSocket over TLS, whose ClientHello the fragment mask
	// cuts in pieces.
	t.Run("vless-ws-tls-fragment-mux", func(t *testing.T) {
		port := freePort(t)
		stream := tlsStream()
		stream["network"], stream["wsSettings"] = "ws", obj{"path": "/ws"}
		x := startXray(t, inbound("vless", port, obj{"clients": []obj{{"id": userUUID}}, "decryption": "none"}, stream))
		tap := fmStartTap(t, port)
		proxy := newProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"network": "ws", "ws-opts": obj{"path": "/ws"},
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{"packets": "tlshello", "length": "20-40", "delay": "1-2"})}},
			"mux":       obj{"enabled": true},
		})
		cbMuxCheck(t, x, proxy, tg)
		require.GreaterOrEqual(t, len(tap.handshakeRecords()), 4, "the ClientHello of the Mux.Cool connection came in pieces")
	})

	// Mux.Cool over the transports and the masks of the other parts.
	mux := "mux: {enabled: true}\nudp: true\n"
	trojan := "type: trojan\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\n"
	trRun(t, []trCase{
		{
			name:   "vless-xhttp-reality-mux",
			stream: trXHTTPServer(trRealityServer, ""),
			client: trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n" + mux,
			check:  cbMuxXHTTPCheck,
		},
		{
			name:     "trojan-xhttp-tls-mux",
			protocol: "trojan",
			stream:   trXHTTPServer(trTLSServer, ""),
			client:   trojan + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n" + mux,
			check:    cbMuxXHTTPCheck,
		},
		{
			name:     "ss-stream-settings-xhttp-tls-mux",
			protocol: "shadowsocks",
			stream:   trXHTTPServer(trTLSServer, ""),
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n" +
				"stream-settings: {network: xhttp, tls: true, servername: example.org, skip-cert-verify: true, xhttp-opts: {path: /xh}}\n" +
				"mux: {enabled: true}\n",
			check: func(t *testing.T, x *xray, proxy C.Proxy, tg targets) {
				checkTCP(t, proxy, tg)
				checkTLS(t, proxy, tg)
				x.waitFor(t, "two TCP connections outside Mux.Cool", func() bool { return cbPastMux(x, cbDirect) >= 2 })
				require.Equal(t, 0, carriers(x), "TCP must not go into Mux.Cool on XHTTP")
			},
		},
		{
			name:     "trojan-grpc-tls-mux",
			protocol: "trojan",
			stream:   `"network":"grpc","grpcSettings":{"serviceName":"gun"},` + trTLSServer,
			client:   trojan + "network: grpc\ngrpc-opts: {grpc-service-name: gun}\n" + mux,
			check:    cbMuxCheck,
		},
		{
			name:     "ss-stream-settings-httpupgrade-tls-mux",
			protocol: "shadowsocks",
			stream:   `"network":"httpupgrade","httpupgradeSettings":{"path":"/up"},` + trTLSServer,
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n" +
				"stream-settings: {network: httpupgrade, tls: true, servername: example.org, skip-cert-verify: true, ws-opts: {path: /up}}\n" + mux,
			check: cbMuxCheck,
		},
		{
			// Shadowsocks has no transport of its own: REALITY from stream-settings,
			// over a connection the sudoku mask has rewritten.
			name:     "ss-stream-settings-reality-sudoku",
			protocol: "shadowsocks",
			stream:   `"network":"raw",` + trRealityServer + `,"finalmask":{"tcp":[{"type":"sudoku","settings":{"password":"interop"}}]}`,
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n" +
				"stream-settings: {tls: true, servername: example.org, client-fingerprint: chrome, reality-opts: {public-key: %PUB%, short-id: 0123456789abcdef, support-x25519mlkem768: true}}\n" +
				"finalmask: {tcp: [{type: sudoku, settings: {password: interop}}]}\n",
		},
		{
			name:     "ss-stream-settings-reality-sudoku-wrong-password",
			protocol: "shadowsocks",
			stream:   `"network":"raw",` + trRealityServer + `,"finalmask":{"tcp":[{"type":"sudoku","settings":{"password":"interop"}}]}`,
			client: "type: ss\ncipher: aes-128-gcm\npassword: %UUID%\n" +
				"stream-settings: {tls: true, servername: example.org, client-fingerprint: chrome, reality-opts: {public-key: %PUB%, short-id: 0123456789abcdef, support-x25519mlkem768: true}}\n" +
				"finalmask: {tcp: [{type: sudoku, settings: {password: another}}]}\n",
			gap: "not a gap: the masks differ, this must not work",
		},
	})

	// Hysteria 2 under two UDP masks, with its QUIC connection tuned: the
	// packets are obfuscated by salamander and the ports hop meanwhile. What
	// quic-params does to the connection is not visible from outside; that it
	// is applied is checked next to the code (transport/finalmask).
	t.Run("hysteria2-salamander-udphop-quic-params", func(t *testing.T) {
		salamander := fmMask("salamander", obj{"password": "obfs-password"})
		port := freePort(t)
		in := fmHysteriaInbound(port, salamander)
		in["streamSettings"].(obj)["finalmask"].(obj)["quicParams"] = obj{"congestion": "brutal", "brutalUp": "100mbps", "brutalDown": "30mbps"}
		startXray(t, in)
		fan := fmStartFanIn(t, port, 4)
		proxy := fmProxy(t, obj{
			"type": "hysteria2", "port": fan.ports[0], "password": fmHysteriaAuth,
			"sni": "example.org", "skip-cert-verify": true,
			"finalmask": obj{
				"udp": []obj{salamander, fmMask("udphop", obj{
					"mode": "intervalLocal,intervalRemote", "interval": 5,
					"remoteIPs": []string{"127.0.0.1"}, "remotePorts": fmt.Sprintf("%d-%d,%s", fan.ports[0], fan.ports[0], fan.portList()),
				})},
				"quic-params": obj{"congestion": "brutal", "brutal-up": "50 mbps", "brutal-down": "100 mbps", "keep-alive-period": 5},
			},
		})
		fmEchoUntil(t, proxy, tg, func() bool { clients, ports := fan.seen(); return clients >= 2 && ports >= 2 })
		checkUDP(t, proxy, tg)
		checkUDPFullCone(t, proxy, tg)
	})

	// VLESS over bare mKCP, obfuscated by the mkcp-legacy mask and carried in
	// DNS queries by xdns.
	t.Run("vless-kcp-mkcp-legacy-xdns", func(t *testing.T) {
		tn := fmXDNSTunnel{names: []string{fmXDNSDomain}, edns0: 1232}
		legacy := fmMask("mkcp-legacy", nil)
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "kcp", "kcpSettings": obj{"mtu": tn.mtu()},
			"finalmask": obj{"udp": []obj{legacy, fmMask("xdns", obj{"domains": tn.domains(true)})}},
		}))
		tap := fmXDNSStartTap(t, port, tn.names...)
		proxy := fmProxy(t, obj{
			// port 9: the mask never sends to the server address
			"type": "vless", "port": 9, "uuid": userUUID, "udp": true,
			"network": "kcp", "mkcp-opts": obj{"raw": true, "mtu": tn.mtu()},
			"finalmask": obj{"udp": []obj{legacy, fmMask("xdns", obj{
				"domains": tn.domains(false), "resolvers": fmXDNSResolver(tap.addr),
			})}},
		})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		require.NotEmpty(t, tap.seen(), "the traffic must have gone as DNS queries")
	})
}
