package xraytest

import (
	"strings"
	"testing"
)

func trRawServer(security string) string {
	return `"network":"raw",` + security
}

func TestTransportREALITY(t *testing.T) {
	withOpt := func(opt string) string { return strings.Replace(trRealityServer, "%REALITY%", opt, 1) }
	fingerprint := func(name string) string {
		return strings.Replace(trRealityClient, "client-fingerprint: chrome", "client-fingerprint: "+name, 1)
	}
	cases := []trCase{
		{
			name:      "mlkem768",
			stream:    trRawServer(trRealityServer),
			client:    trRealityClient,
			serverLog: "is using X25519MLKEM768 for TLS' communication: true",
		},
		{
			name:   "x25519-only-hello",
			stream: trRawServer(trRealityServer),
			client: strings.Replace(trRealityClient, "  support-x25519mlkem768: true\n", "", 1),
			gap:    "Xray 26.x drops a hello without X25519MLKEM768, mihomo strips it by default",
		},
		{
			name:      "mldsa65-server",
			stream:    trRawServer(withOpt(`,"mldsa65Seed":"%SEED%"`)),
			client:    trRealityClient,
			serverLog: "is using ML-DSA-65 for cert's extra signature: true",
		},
		{
			name:   "min-client-ver",
			stream: trRawServer(withOpt(`,"minClientVer":"26.3.27","maxClientVer":"26.11.9"`)),
			client: trRealityClient + "  client-version: 26.11.9\n",
		},
		{
			name:   "min-client-ver-default-version",
			stream: trRawServer(withOpt(`,"minClientVer":"26.3.27"`)),
			client: trRealityClient,
			gap:    "by design: the reported version stays 1.8.2 unless client-version is set",
		},
		{
			name:   "max-client-ver",
			stream: trRawServer(withOpt(`,"maxClientVer":"25.12.31"`)),
			client: trRealityClient + "  client-version: 26.11.9\n",
			gap:    "not a gap: the server refuses a newer client",
		},
		{
			name:   "client-version-zero",
			stream: trRawServer(withOpt(`,"maxClientVer":"0.0.0"`)),
			client: trRealityClient + "  client-version: 0.0.0\n",
		},
		{
			name:   "max-time-diff",
			stream: trRawServer(withOpt(`,"maxTimeDiff":60000`)),
			client: trRealityClient,
		},
		{
			name:   "vision",
			stream: trRawServer(trRealityServer),
			client: trRealityClient + "flow: xtls-rprx-vision\n",
		},
	}
	for _, name := range []string{"chrome155", "firefox", "safari", "random"} {
		cases = append(cases, trCase{
			name:   "fingerprint-" + name,
			stream: trRawServer(trRealityServer),
			client: fingerprint(name),
		})
	}
	for _, name := range []string{"ios", "edge", "android", "360", "qq"} {
		cases = append(cases, trCase{
			name:   "fingerprint-" + name,
			stream: trRawServer(trRealityServer),
			client: fingerprint(name),
			gap:    "this ClientHello has no X25519MLKEM768 key share",
		})
	}
	// the vision case needs the flow on the server user
	for i := range cases {
		if cases[i].name == "vision" {
			cases[i].protocol = "vless-vision"
		}
	}
	trRun(t, cases)
}

func TestTransportTLS(t *testing.T) {
	withOpt := func(opt string) string { return strings.Replace(trTLSServer, "%TLS%", opt, 1) }
	pqOnly := withOpt(`,"curvePreferences":["X25519MLKEM768"]`)
	ech := withOpt(`,"echServerKeys":"%ECHKEYS%"`)
	otherECH := trField(t, trXrayTool(t, "tls", "ech", "--serverName", trServerName), "ECH config list")
	trRun(t, []trCase{
		{
			name:   "go-tls",
			stream: trRawServer(trTLSServer),
			client: trTLSClient,
		},
		{
			name:   "utls-chrome",
			stream: trRawServer(trTLSServer),
			client: trTLSClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "pq-only-server-go-tls",
			stream: trRawServer(pqOnly),
			client: trTLSClient,
		},
		{
			name:   "pq-only-server-utls-chrome",
			stream: trRawServer(pqOnly),
			client: trTLSClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "secp256r1mlkem768-only-server-go-tls",
			stream: trRawServer(withOpt(`,"curvePreferences":["SecP256r1MLKEM768"]`)),
			client: trTLSClient,
		},
		{
			name:   "secp384r1mlkem1024-only-server-go-tls",
			stream: trRawServer(withOpt(`,"curvePreferences":["SecP384r1MLKEM1024"]`)),
			client: trTLSClient,
		},
		{
			name:   "p384-only-server-utls-chrome",
			stream: trRawServer(withOpt(`,"curvePreferences":["CurveP384"]`)),
			client: trTLSClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "tls12-only-server",
			stream: trRawServer(withOpt(`,"maxVersion":"1.2"`)),
			client: trTLSClient,
		},
		{
			name:   "tls13-only-server",
			stream: trRawServer(withOpt(`,"minVersion":"1.3"`)),
			client: trTLSClient,
		},
		{
			name:   "pinned-certificate",
			stream: trRawServer(trTLSServer),
			client: "tls: true\nservername: example.org\nfingerprint: %PIN%\n",
		},
		{
			name:   "ech-go-tls",
			stream: trRawServer(ech),
			client: trTLSClient + "ech-opts: {enable: true, config: %ECHLIST%}\n",
		},
		{
			name:   "ech-utls-chrome",
			stream: trRawServer(ech),
			client: trTLSClient + "client-fingerprint: chrome\nech-opts: {enable: true, config: %ECHLIST%}\n",
		},
		{
			name:   "ech-foreign-config-is-refused",
			stream: trRawServer(ech),
			client: trTLSClient + "ech-opts: {enable: true, config: " + otherECH + "}\n",
			gap:    "not a gap: proves the client really sends ECH",
		},
		{
			name:   "session-resumption-server",
			stream: trRawServer(withOpt(`,"enableSessionResumption":true`)),
			client: trTLSClient,
		},
	})
}
