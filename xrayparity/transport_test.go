//go:build xray_parity

package xrayparity

import (
	"strconv"
	"strings"
	"testing"
)

const (
	tlsServer     = `"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/cert.pem","keyFile":"/etc/xray/key.pem"}]%TLS%}`
	realityServer = `"security":"reality","realitySettings":{"show":true,"target":"host.docker.internal:%TARGET%","serverNames":["example.org"],"privateKey":"%PRIV%","shortIds":["0123456789abcdef"]%REALITY%}`

	tlsClient = `
tls: true
servername: example.org
skip-cert-verify: true
`
	realityClient = `
tls: true
servername: example.org
client-fingerprint: chrome
reality-opts:
  public-key: %PUB%
  short-id: 0123456789abcdef
  support-x25519mlkem768: true
`
)

// parityCase is one server/client pair. In both configs %NAME% placeholders are
// filled from the key material.
type parityCase struct {
	name     string
	protocol string // inbound protocol, vless by default
	stream   string // contents of streamSettings, without the braces
	client   string // mihomo proxy YAML, without name, server and port
	// serverLog, when set, must appear in the Xray log after the round trip.
	serverLog string
	// gap, when set, says why the pair is known not to work: the round trip
	// must fail, and the case fails once it starts to pass.
	gap string
}

func fill(t *testing.T, s string, target int) string {
	m := getMaterial(t)
	return strings.NewReplacer(
		"%TARGET%", strconv.Itoa(target),
		"%PRIV%", m.realityPrivate,
		"%PUB%", m.realityPublic,
		"%SEED%", m.mldsaSeed,
		"%VERIFY%", m.mldsaVerify,
		"%ECHKEYS%", m.echServerKeys,
		"%ECHLIST%", m.echConfigList,
		"%PIN%", m.certSHA256,
		"%UUID%", testUUID,
		"%TLS%", "", "%REALITY%", "",
	).Replace(s)
}

func serverConfig(protocol, stream string) string {
	var settings string
	switch protocol {
	case "", "vless":
		protocol = "vless"
		settings = `{"clients":[{"id":"%UUID%"}],"decryption":"none"}`
	case "vless-vision":
		protocol = "vless"
		settings = `{"clients":[{"id":"%UUID%","flow":"xtls-rprx-vision"}],"decryption":"none"}`
	case "vmess":
		settings = `{"clients":[{"id":"%UUID%"}]}`
	case "trojan":
		settings = `{"clients":[{"password":"%UUID%"}]}`
	case "hysteria":
		settings = `{"version":2,"clients":[{"auth":"%UUID%"}]}`
	}
	return `{"log":{"loglevel":"debug"},
"inbounds":[{"listen":"0.0.0.0","port":%PORT%,"protocol":"` + protocol + `","settings":` + settings + `,"streamSettings":{` + stream + `}}],
"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}`
}

func runCases(t *testing.T, cases []parityCase) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := 0
			if strings.Contains(c.stream, "%TARGET%") {
				target = realityTarget(t)
			}
			x := startXray(t, fill(t, serverConfig(c.protocol, c.stream), target), getMaterial(t).files())
			client := c.client
			if !strings.Contains(client, "type:") {
				client = "type: vless\nuuid: %UUID%\n" + client
			}
			if c.gap != "" {
				proxy, err := parseProxy(x, fill(t, client, target))
				if err == nil {
					defer proxy.Close()
					err = roundTrip(proxy, echoServer(t), 16)
				}
				if err == nil {
					t.Fatalf("works now, drop the gap mark: %s", c.gap)
				}
				t.Logf("known gap (%s): %v", c.gap, err)
				x.t = nil // the failure is expected, keep the Xray log out
				return
			}
			proxy := newProxy(t, x, fill(t, client, target))
			mustRoundTrip(t, proxy)
			if c.serverLog != "" && !strings.Contains(x.Logs(), c.serverLog) {
				t.Errorf("xray log has no %q", c.serverLog)
			}
		})
	}
}

func xhttpServer(security, settings string) string {
	s := `"network":"xhttp","xhttpSettings":{"path":"/xh"` + settings + `}`
	if security != "" {
		s += "," + security
	}
	return s
}

func TestXHTTP(t *testing.T) {
	h3 := strings.Replace(tlsServer, "%TLS%", `,"alpn":["h3"]`, 1)
	runCases(t, []parityCase{
		{
			name:   "tls-h2-auto",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "tls-h2-packet-up",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h2-stream-up",
			stream: xhttpServer(tlsServer, `,"mode":"stream-up"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "tls-h2-stream-one",
			stream: xhttpServer(tlsServer, `,"mode":"stream-one"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-one}\n",
		},
		{
			name:   "tls-h1-packet-up",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "alpn: [http/1.1]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h3-packet-up",
			stream: xhttpServer(h3, ""),
			client: tlsClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h3-stream-up",
			stream: xhttpServer(h3, ""),
			client: tlsClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "tls-h3-stream-one",
			stream: xhttpServer(h3, ""),
			client: tlsClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-one}\n",
		},
		{
			name:   "plain-auto",
			stream: xhttpServer("", ""),
			client: "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "reality-auto",
			stream: xhttpServer(realityServer, ""),
			client: realityClient + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "reality-stream-up",
			stream: xhttpServer(realityServer, ""),
			client: realityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "reality-packet-up",
			stream: xhttpServer(realityServer, ""),
			client: realityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name: "padding-cookie-tokenish-meta-header-query",
			stream: xhttpServer(tlsServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingMethod":"tokenish","xPaddingKey":"sid",
				"xPaddingBytes":"200-400","sessionIDPlacement":"header","sessionIDKey":"X-Req","seqPlacement":"query","seqKey":"n","uplinkHTTPMethod":"PUT","noGRPCHeader":true`),
			client: tlsClient + `network: xhttp
xhttp-opts:
  path: /xh
  mode: packet-up
  x-padding-obfs-mode: true
  x-padding-placement: cookie
  x-padding-method: tokenish
  x-padding-key: sid
  x-padding-bytes: 200-400
  session-placement: header
  session-key: X-Req
  seq-placement: query
  seq-key: n
  uplink-http-method: PUT
  no-grpc-header: true
`,
		},
		{
			name:   "padding-header-meta-cookie-stream-up",
			stream: xhttpServer(tlsServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Trace","sessionIDPlacement":"cookie","seqPlacement":"header"`),
			client: tlsClient + `network: xhttp
xhttp-opts:
  path: /xh
  mode: stream-up
  x-padding-obfs-mode: true
  x-padding-placement: header
  x-padding-header: X-Trace
  session-placement: cookie
  seq-placement: header
`,
		},
		{
			name:   "padding-query-meta-query-cookie",
			stream: xhttpServer(tlsServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"query","sessionIDPlacement":"query","seqPlacement":"cookie"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, x-padding-obfs-mode: true, x-padding-placement: query, x-padding-key: x_padding, session-placement: query, seq-placement: cookie}\n",
		},
		{
			name:   "padding-obfs-defaults",
			gap:    "x-padding-key, -header, -placement and -method have no Xray defaults",
			stream: xhttpServer(tlsServer, `,"xPaddingObfsMode":true`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, x-padding-obfs-mode: true}\n",
		},
		{
			name:   "uplink-data-header-default-key",
			gap:    "uplink-data-key has no Xray default",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"header","scMaxEachPostBytes":3000`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-header-explicit-key",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"header","uplinkDataKey":"X-Data","scMaxEachPostBytes":3000`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, uplink-data-key: X-Data, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-cookie-default-key-get",
			gap:    "uplink-data-key has no Xray default",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"cookie","uplinkHTTPMethod":"GET","scMaxEachPostBytes":3000`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: cookie, uplink-http-method: GET, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-cookie-explicit-key-get",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"cookie","uplinkDataKey":"x_data","uplinkHTTPMethod":"GET","scMaxEachPostBytes":3000`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: cookie, uplink-data-key: x_data, uplink-http-method: GET, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-header-custom-key-chunk",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"header","uplinkDataKey":"X-Blob","uplinkChunkSize":"500-900","scMaxEachPostBytes":3000`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, uplink-data-key: X-Blob, uplink-chunk-size: 500-900, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-auto-server",
			stream: xhttpServer(tlsServer, `,"mode":"packet-up","uplinkDataPlacement":"auto"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "session-table",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, session-table: Base62, session-length: 20-30}\n",
		},
		{
			name:   "small-posts",
			stream: xhttpServer(tlsServer, `,"scMaxEachPostBytes":4096,"scMaxBufferedPosts":100`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 2000-4096, sc-min-posts-interval-ms: 5-10}\n",
		},
		{
			name:   "path-with-query",
			gap:    "a query in path is escaped into the path",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: \"/xh?token=abc\", mode: packet-up}\n",
		},
		{
			name:   "host-and-headers",
			stream: xhttpServer(tlsServer, `,"host":"cdn.example.org"`),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, host: cdn.example.org, headers: {X-Custom: \"1\"}}\n",
		},
		{
			name:   "download-settings",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, download-settings: {server: 127.0.0.1, port: %PORT%, path: /xh}}\n",
		},
		{
			name:   "reuse-settings",
			stream: xhttpServer(tlsServer, ""),
			client: tlsClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, reuse-settings: {max-connections: \"2\", h-max-request-times: 50-100, h-max-reusable-secs: 1800-3000, h-keep-alive-period: 30}}\n",
		},
	})
}
