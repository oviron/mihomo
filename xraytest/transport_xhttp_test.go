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
			gap:    "x-padding-key, -header, -placement and -method have no Xray defaults",
			stream: trXHTTPServer(trTLSServer, `,"xPaddingObfsMode":true`),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, x-padding-obfs-mode: true}\n",
		},
		{
			name:   "uplink-data-header-default-key",
			gap:    "uplink-data-key has no Xray default",
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
			gap:    "uplink-data-key has no Xray default",
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
			gap:    "a query in path is escaped into the path",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: \"/xh?token=abc\", mode: packet-up}\n",
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
			name:   "reuse-settings",
			stream: trXHTTPServer(trTLSServer, ""),
			client: trTLSClient + "network: xhttp\nxhttp-opts: {path: /xh, mode: packet-up, reuse-settings: {max-connections: \"2\", h-max-request-times: 50-100, h-max-reusable-secs: 1800-3000, h-keep-alive-period: 30}}\n",
		},
	})
}
