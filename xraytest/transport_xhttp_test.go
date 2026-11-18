package xraytest

import (
	"strings"
	"testing"
)

func trXHTTPServer(security, settings string) string {
	s := `"network":"xhttp","xhttpSettings":{"path":"/xh"` + settings + `}`
	if security != "" {
		s += "," + security
	}
	return s
}

func TestTransportXHTTP(t *testing.T) {
	h3 := strings.Replace(trTLSServer, "%TLS%", `,"alpn":["h3"]`, 1)
	trRun(t, []trCase{
		{
			name:   "tls-h2-auto",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "tls-h2-packet-up",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h2-stream-up",
			stream: trXHTTPServer(trTLSServer, `,"mode":"stream-up"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "tls-h2-stream-one",
			stream: trXHTTPServer(trTLSServer, `,"mode":"stream-one"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-one}\n",
		},
		{
			name:   "tls-h1-packet-up",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "alpn: [http/1.1]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h3-packet-up",
			stream: trXHTTPServer(h3, ""),
			client: trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "tls-h3-stream-up",
			stream: trXHTTPServer(h3, ""),
			client: trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "tls-h3-stream-one",
			stream: trXHTTPServer(h3, ""),
			client: trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-one}\n",
		},
		{
			name:   "plain-auto",
			stream: trXHTTPServer("", ""),
			client: "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "reality-auto",
			stream: trXHTTPServer(trRealityServer, ""),
			client: trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		{
			name:   "reality-stream-up",
			stream: trXHTTPServer(trRealityServer, ""),
			client: trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		{
			name:   "reality-packet-up",
			stream: trXHTTPServer(trRealityServer, ""),
			client: trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name: "padding-cookie-tokenish-meta-header-query",
			stream: trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingMethod":"tokenish","xPaddingKey":"sid",
				"xPaddingBytes":"200-400","sessionIDPlacement":"header","sessionIDKey":"X-Req","seqPlacement":"query","seqKey":"n","uplinkHTTPMethod":"PUT","noGRPCHeader":true`),
			client: trTLSClient + `network: xhttp
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
			stream: trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Trace","sessionIDPlacement":"cookie","seqPlacement":"header"`),
			client: trTLSClient + `network: xhttp
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
			stream: trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"query","sessionIDPlacement":"query","seqPlacement":"cookie"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, x-padding-obfs-mode: true, x-padding-placement: query, x-padding-key: x_padding, session-placement: query, seq-placement: cookie}\n",
		},
		{
			name:   "padding-obfs-defaults",
			stream: trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, x-padding-obfs-mode: true}\n",
		},
		{
			name:   "uplink-data-header-default-key",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"header","scMaxEachPostBytes":3000`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-header-explicit-key",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"header","uplinkDataKey":"X-Data","scMaxEachPostBytes":3000`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, uplink-data-key: X-Data, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-cookie-default-key-get",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"cookie","uplinkHTTPMethod":"GET","scMaxEachPostBytes":3000`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: cookie, uplink-http-method: GET, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-cookie-explicit-key-get",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"cookie","uplinkDataKey":"x_data","uplinkHTTPMethod":"GET","scMaxEachPostBytes":3000`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: cookie, uplink-data-key: x_data, uplink-http-method: GET, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-header-custom-key-chunk",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"header","uplinkDataKey":"X-Blob","uplinkChunkSize":"500-900","scMaxEachPostBytes":3000`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-data-placement: header, uplink-data-key: X-Blob, uplink-chunk-size: 500-900, sc-max-each-post-bytes: 3000, sc-min-posts-interval-ms: 1}\n",
		},
		{
			name:   "uplink-data-auto-server",
			stream: trXHTTPServer(trTLSServer, `,"mode":"packet-up","uplinkDataPlacement":"auto"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		{
			name:   "session-table",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, session-table: Base62, session-length: 20-30}\n",
		},
		{
			name:   "small-posts",
			stream: trXHTTPServer(trTLSServer, `,"scMaxEachPostBytes":4096,"scMaxBufferedPosts":100`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 2000-4096, sc-min-posts-interval-ms: 5-10}\n",
		},
		{
			name:   "path-with-query",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: \"/xh?token=abc\", mode: packet-up}\n",
		},
		{
			name:   "path-with-query-stream-up-meta-in-query",
			stream: trXHTTPServer(trTLSServer, `,"sessionIDPlacement":"query"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: \"/xh?token=abc\", mode: stream-up, session-placement: query}\n",
		},
		{
			name:   "lower-case-uplink-method",
			stream: trXHTTPServer(trTLSServer, `,"uplinkHTTPMethod":"put"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, uplink-http-method: put}\n",
		},
		{
			name:   "host-and-headers",
			stream: trXHTTPServer(trTLSServer, `,"host":"cdn.example.org"`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, host: cdn.example.org, headers: {X-Custom: \"1\"}}\n",
		},
		{
			name:   "download-settings",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, download-settings: {server: 127.0.0.1, port: %PORT%, path: /xh}}\n",
		},
		{
			name:   "pipeline-posts-h2",
			stream: trXHTTPServer(trTLSServer, `,"scMaxEachPostBytes":32768`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 32768, sc-min-posts-interval-ms: 1, pipeline-posts: true}\n",
		},
		{
			name:   "pipeline-posts-h3",
			stream: trXHTTPServer(strings.Replace(trTLSServer, "%TLS%", `,"alpn":["h3"]`, 1), `,"scMaxEachPostBytes":32768`),
			client: trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 32768, sc-min-posts-interval-ms: 1, pipeline-posts: true}\n",
		},
		{
			name:   "pipeline-posts-h1",
			stream: trXHTTPServer(trTLSServer, `,"scMaxEachPostBytes":32768`),
			client: trTLSClient + "alpn: [http/1.1]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 32768, sc-min-posts-interval-ms: 1, pipeline-posts: true}\n",
		},
		{
			name:   "pipeline-posts-reality-xmux",
			stream: trXHTTPServer(trRealityServer, `,"scMaxEachPostBytes":32768`),
			client: trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 32768, sc-min-posts-interval-ms: 1, pipeline-posts: true, xmux: {max-connections: \"2\", h-max-request-times: 20-30}}\n",
		},
		{
			name:   "pipeline-posts-default-sizes",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, pipeline-posts: true}\n",
		},
		{
			name:   "xmux-defaults",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, xmux: {}}\n",
		},
		{
			name:   "xmux-rotates-on-request-limit",
			stream: trXHTTPServer(trTLSServer, `,"scMaxEachPostBytes":65536`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, sc-max-each-post-bytes: 65536, sc-min-posts-interval-ms: 1, xmux: {max-connections: \"1\", h-max-request-times: \"5-8\"}}\n",
		},
		{
			name:   "xmux-stream-up-h3",
			stream: trXHTTPServer(strings.Replace(trTLSServer, "%TLS%", `,"alpn":["h3"]`, 1), ""),
			client: trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-up, xmux: {max-concurrency: 16-32, h-max-request-times: \"3\"}}\n",
		},
		{
			name:   "xmux-download-settings",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, download-settings: {server: 127.0.0.1, port: %PORT%, xmux: {max-connections: \"1\"}}}\n",
		},
		{
			name:   "reuse-settings",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, reuse-settings: {max-connections: \"2\", h-max-request-times: 50-100, h-max-reusable-secs: 1800-3000, h-keep-alive-period: 30}}\n",
		},
	})
}

// XHTTP is a transport for any protocol in Xray-core, not for VLESS alone.
func TestTransportXHTTPOtherProtocols(t *testing.T) {
	h3 := strings.Replace(trTLSServer, "%TLS%", `,"alpn":["h3"]`, 1)
	vmess := "type: vmess\nuuid: %UUID%\nalterId: 0\ncipher: auto\n"
	trojan := "type: trojan\npassword: %UUID%\nsni: example.org\nskip-cert-verify: true\n"
	trojanReality := "type: trojan\npassword: %UUID%\nsni: example.org\nclient-fingerprint: chrome\nreality-opts: {public-key: %PUB%, short-id: 0123456789abcdef, support-x25519mlkem768: true}\n"
	var cases []trCase
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		cases = append(cases,
			trCase{
				name:     "vmess-tls-" + mode,
				protocol: "vmess",
				stream:   trXHTTPServer(trTLSServer, ""),
				client:   vmess + trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: " + mode + "}\n",
			},
			trCase{
				name:     "trojan-tls-" + mode,
				protocol: "trojan",
				stream:   trXHTTPServer(trTLSServer, ""),
				client:   trojan + "network: xhttp\nxhttp-opts: {path: /xh, mode: " + mode + "}\n",
			},
		)
	}
	cases = append(cases,
		trCase{
			name:     "vmess-plain",
			protocol: "vmess",
			stream:   trXHTTPServer("", ""),
			client:   vmess + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		trCase{
			name:     "vmess-reality",
			protocol: "vmess",
			stream:   trXHTTPServer(trRealityServer, ""),
			client:   vmess + trRealityClient + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		trCase{
			name:     "vmess-h3",
			protocol: "vmess",
			stream:   trXHTTPServer(h3, ""),
			client:   vmess + trTLSClient + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up}\n",
		},
		trCase{
			name:     "trojan-reality",
			protocol: "trojan",
			stream:   trXHTTPServer(trRealityServer, ""),
			client:   trojanReality + "network: xhttp\nxhttp-opts: {path: /xh}\n",
		},
		trCase{
			name:     "trojan-h3",
			protocol: "trojan",
			stream:   trXHTTPServer(h3, ""),
			client:   trojan + "alpn: [h3]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: stream-up}\n",
		},
		trCase{
			name:     "trojan-obfs-xmux-pipeline-download",
			protocol: "trojan",
			stream:   trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true,"xPaddingPlacement":"cookie","sessionIDPlacement":"query","host":"cdn.example.org"`),
			client: trojan + `network: xhttp
xhttp-opts:
  path: /xh
  host: cdn.example.org
  mode: packet-up
  x-padding-obfs-mode: true
  x-padding-placement: cookie
  session-placement: query
  pipeline-posts: true
  xmux: {}
  download-settings:
    server: 127.0.0.1
    port: %PORT%
    xmux: {max-connections: "1"}
`,
		},
		trCase{
			name:     "vmess-reuse-settings-h1",
			protocol: "vmess",
			stream:   trXHTTPServer(trTLSServer, ""),
			client:   vmess + trTLSClient + "alpn: [http/1.1]\nnetwork: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, reuse-settings: {max-connections: \"2\"}}\n",
		},
	)
	trRun(t, cases)
}
