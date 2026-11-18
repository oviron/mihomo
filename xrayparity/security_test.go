//go:build xray_parity

package xrayparity

import (
	"strings"
	"testing"
)

func rawServer(security string) string {
	return `"network":"raw",` + security
}

func TestREALITY(t *testing.T) {
	withOpt := func(opt string) string { return strings.Replace(realityServer, "%REALITY%", opt, 1) }
	fingerprint := func(name string) string {
		return strings.Replace(realityClient, "client-fingerprint: chrome", "client-fingerprint: "+name, 1)
	}
	cases := []parityCase{
		{
			name:      "mlkem768",
			stream:    rawServer(realityServer),
			client:    realityClient,
			serverLog: "is using X25519MLKEM768 for TLS' communication: true",
		},
		{
			name:   "x25519-only-hello",
			stream: rawServer(realityServer),
			client: strings.Replace(realityClient, "  support-x25519mlkem768: true\n", "", 1),
			gap:    "Xray 26.x drops a hello without X25519MLKEM768, mihomo strips it by default",
		},
		{
			name:      "mldsa65-server",
			stream:    rawServer(withOpt(`,"mldsa65Seed":"%SEED%"`)),
			client:    realityClient,
			serverLog: "is using ML-DSA-65 for cert's extra signature: true",
		},
		{
			name:   "min-client-ver",
			stream: rawServer(withOpt(`,"minClientVer":"26.3.27"`)),
			client: realityClient,
			gap:    "mihomo reports client version 1.8.2",
		},
		{
			name:   "max-time-diff",
			stream: rawServer(withOpt(`,"maxTimeDiff":60000`)),
			client: realityClient,
		},
		{
			name:   "vision",
			stream: rawServer(realityServer),
			client: realityClient + "flow: xtls-rprx-vision\n",
		},
	}
	for _, name := range []string{"chrome155", "firefox", "safari"} {
		cases = append(cases, parityCase{
			name:   "fingerprint-" + name,
			stream: rawServer(realityServer),
			client: fingerprint(name),
		})
	}
	for _, name := range []string{"ios", "edge", "android", "360", "qq"} {
		cases = append(cases, parityCase{
			name:   "fingerprint-" + name,
			stream: rawServer(realityServer),
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
	runCases(t, cases)
}

func TestTLS(t *testing.T) {
	withOpt := func(opt string) string { return strings.Replace(tlsServer, "%TLS%", opt, 1) }
	pqOnly := withOpt(`,"curvePreferences":["X25519MLKEM768"]`)
	ech := withOpt(`,"echServerKeys":"%ECHKEYS%"`)
	otherECH := field(t, xrayTool(t, "tls", "ech", "--serverName", serverName), "ECH config list")
	runCases(t, []parityCase{
		{
			name:   "go-tls",
			stream: rawServer(tlsServer),
			client: tlsClient,
		},
		{
			name:   "utls-chrome",
			stream: rawServer(tlsServer),
			client: tlsClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "pq-only-server-go-tls",
			stream: rawServer(pqOnly),
			client: tlsClient,
		},
		{
			name:   "pq-only-server-utls-chrome",
			stream: rawServer(pqOnly),
			client: tlsClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "secp256r1mlkem768-only-server-go-tls",
			stream: rawServer(withOpt(`,"curvePreferences":["SecP256r1MLKEM768"]`)),
			client: tlsClient,
		},
		{
			name:   "secp384r1mlkem1024-only-server-go-tls",
			stream: rawServer(withOpt(`,"curvePreferences":["SecP384r1MLKEM1024"]`)),
			client: tlsClient,
		},
		{
			name:   "p384-only-server-utls-chrome",
			stream: rawServer(withOpt(`,"curvePreferences":["CurveP384"]`)),
			client: tlsClient + "client-fingerprint: chrome\n",
		},
		{
			name:   "tls12-only-server",
			stream: rawServer(withOpt(`,"maxVersion":"1.2"`)),
			client: tlsClient,
		},
		{
			name:   "tls13-only-server",
			stream: rawServer(withOpt(`,"minVersion":"1.3"`)),
			client: tlsClient,
		},
		{
			name:   "pinned-certificate",
			stream: rawServer(tlsServer),
			client: "tls: true\nservername: example.org\nfingerprint: %PIN%\n",
		},
		{
			name:   "ech-go-tls",
			stream: rawServer(ech),
			client: tlsClient + "ech-opts: {enable: true, config: %ECHLIST%}\n",
		},
		{
			name:   "ech-utls-chrome",
			stream: rawServer(ech),
			client: tlsClient + "client-fingerprint: chrome\nech-opts: {enable: true, config: %ECHLIST%}\n",
		},
		{
			name:   "ech-foreign-config-is-refused",
			stream: rawServer(ech),
			client: tlsClient + "ech-opts: {enable: true, config: " + otherECH + "}\n",
			gap:    "not a gap: proves the client really sends ECH",
		},
		{
			name:   "session-resumption-server",
			stream: rawServer(withOpt(`,"enableSessionResumption":true`)),
			client: tlsClient,
		},
	})
}
