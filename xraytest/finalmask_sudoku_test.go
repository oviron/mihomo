package xraytest

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// The sudoku mask: both sides must derive the same tables from the password
// and the table settings. The client sends puzzles and reads the packed
// stream over TCP, and sends and reads puzzles over UDP.

// fmSudokuKCPMTU is the mKCP packet size the checks use on both sides. The
// mask turns a datagram of n bytes into as many as 9n+1 (4n without padding).
// With the 6 bytes mkcp-legacy adds, (150+6)*9+1 = 1405 bytes: a datagram
// that crosses a 1500 byte link in one piece. The mKCP default of 1350 would
// make datagrams of 12 KiB.
const fmSudokuKCPMTU = 150

// fmSudokuTables are custom tables from the tests of Xray-core.
var fmSudokuTables = []string{"xpxvvpvv", "vxpvxvvp", "pxvvxvvp", "vpxvxvpv", "xvpvvxpv", "vvxpxpvv"}

// fmSudokuVless starts a VLESS inbound behind the mask and returns the
// outbound for it. server are the settings in Xray's JSON, client the ones of
// mihomo.
func fmSudokuVless(t *testing.T, server, client obj, security, flow string) C.Proxy {
	t.Helper()
	port := freePort(t)
	stream := obj{"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("sudoku", server)}}}
	proxy := obj{
		"type": "vless", "port": port, "uuid": userUUID, "udp": true,
		"finalmask": obj{"tcp": []obj{fmMask("sudoku", client)}},
	}
	if security == "tls" {
		stream["security"] = "tls"
		stream["tlsSettings"] = tlsSettings()
		proxy["tls"] = true
		proxy["skip-cert-verify"] = true
		proxy["servername"] = "example.org"
	}
	if flow != "" {
		proxy["flow"] = flow
	}
	startXray(t, fmInbound("vless", port, fmVlessSettings(flow), stream))
	return fmProxy(t, proxy)
}

// fmSudokuKCP is VMess over mKCP with the mask on its datagrams, under the
// mkcp-legacy mask on both sides.
func fmSudokuKCP(t *testing.T, server, client obj, mtu int) C.Proxy {
	t.Helper()
	port := freePort(t)
	legacy := fmMask("mkcp-legacy", nil)
	startXray(t, fmInbound("vmess", port, obj{"clients": []obj{{"id": userUUID}}}, obj{
		"network": "kcp", "kcpSettings": obj{"mtu": mtu},
		"finalmask": obj{"udp": []obj{legacy, fmMask("sudoku", server)}},
	}))
	return fmKCP(t, port, obj{"raw": true, "mtu": mtu}, legacy, fmMask("sudoku", client))
}

// fmSudokuHysteria is Hysteria 2 with the mask on the QUIC packets.
func fmSudokuHysteria(t *testing.T, server, client obj) C.Proxy {
	t.Helper()
	port := freePort(t)
	startXray(t, fmInbound("hysteria", port, obj{"version": 2, "clients": []obj{{"auth": "hysteria-auth"}}}, obj{
		"network": "hysteria", "security": "tls",
		"tlsSettings":      obj{"alpn": []string{"h3"}, "certificates": tlsSettings()["certificates"]},
		"hysteriaSettings": obj{"version": 2},
		"finalmask":        obj{"udp": []obj{fmMask("sudoku", server)}},
	}))
	return fmProxy(t, obj{
		"type": "hysteria2", "port": port, "password": "hysteria-auth",
		"sni": "example.org", "skip-cert-verify": true,
		"finalmask": obj{"udp": []obj{fmMask("sudoku", client)}},
	})
}

func TestFinalmaskSudokuTCP(t *testing.T) {
	tg := startTargets(t)

	for _, tc := range []struct {
		name   string
		server obj // Xray's names
		client obj // nil: the same map
	}{
		{name: "entropy", server: obj{"password": "interop"}},
		{name: "entropy-named", server: obj{"password": "interop", "ascii": "prefer_entropy"}, client: obj{"password": "interop", "ascii": "entropy"}},
		{name: "ascii", server: obj{"password": "interop", "ascii": "prefer_ascii"}},
		{
			name:   "custom-table",
			server: obj{"password": "interop", "customTable": fmSudokuTables[0]},
			client: obj{"password": "interop", "custom-table": fmSudokuTables[0]},
		},
		// With several tables both sides move to the next one after every
		// byte the client sends and every 6-bit group the server sends.
		{
			name:   "two-tables-padding-20-60",
			server: obj{"password": "interop", "customTables": fmSudokuTables[:2], "paddingMin": 20, "paddingMax": 60},
			client: obj{"password": "interop", "custom-tables": fmSudokuTables[:2], "padding-min": 20, "padding-max": 60},
		},
		{
			name:   "three-tables-padding-100",
			server: obj{"password": "interop", "customTables": fmSudokuTables[2:5], "paddingMin": 100, "paddingMax": 100},
		},
		{
			name:   "six-tables",
			server: obj{"password": "interop", "customTables": fmSudokuTables},
		},
		{
			name:   "tables-with-entropy-entry",
			server: obj{"password": "interop", "customTables": []string{fmSudokuTables[5], "", fmSudokuTables[0]}},
		},
		{name: "padding-0", server: obj{"password": "interop", "paddingMin": 0, "paddingMax": 0}},
		{name: "padding-20-60", server: obj{"password": "interop", "paddingMin": 20, "paddingMax": 60}},
		{name: "padding-100", server: obj{"password": "interop", "paddingMin": 100, "paddingMax": 100}},
		{name: "ascii-padding-100", server: obj{"password": "interop", "ascii": "ascii", "paddingMin": 100, "paddingMax": 100}},
		{name: "empty-password", server: obj{}},
		// the names Xray read before it took the camelCase ones
		{
			name:   "legacy-names",
			server: obj{"password": "interop", "customTables": fmSudokuTables[1:3], "paddingMin": 20, "paddingMax": 60},
			client: obj{"password": "interop", "custom_tables": fmSudokuTables[1:3], "padding_min": 20, "padding_max": 60},
		},
		{
			name:   "legacy-names-on-both-sides",
			server: obj{"password": "interop", "custom_table": fmSudokuTables[3], "padding_min": 30, "padding_max": 30},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.client
			if client == nil {
				client = tc.server
			}
			proxy := fmSudokuVless(t, tc.server, client, "", "")
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}

	// The mask stays under TLS and under XTLS Vision, which writes to the
	// connection below TLS once it sees the inner handshake end.
	settings := obj{"password": "interop", "customTables": fmSudokuTables[:2], "paddingMin": 20, "paddingMax": 60}
	t.Run("tls", func(t *testing.T) {
		proxy := fmSudokuVless(t, settings, settings, "tls", "")
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
	t.Run("tls-vision", func(t *testing.T) {
		proxy := fmSudokuVless(t, settings, settings, "tls", "xtls-rprx-vision")
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
	t.Run("vision-entropy", func(t *testing.T) {
		proxy := fmSudokuVless(t, obj{"password": "interop"}, obj{"password": "interop"}, "tls", "xtls-rprx-vision")
		checkTLS(t, proxy, tg)
	})

	// What the client puts on the wire has the shape the settings ask for.
	for name, tc := range map[string]struct {
		settings obj
		shape    func(b byte) bool
	}{
		"entropy":      {obj{"password": "interop"}, func(b byte) bool { return b&0x90 == 0 }},
		"ascii-padded": {obj{"ascii": "prefer_ascii", "paddingMin": 100, "paddingMax": 100}, func(b byte) bool { return b == '\n' || (b >= 0x20 && b < 0x7f) }},
		"custom-table": {obj{"customTable": "xpxvvpvv"}, func(b byte) bool { return b&0xa0 == 0xa0 }},
	} {
		t.Run("wire-bytes-"+name, func(t *testing.T) {
			port := freePort(t)
			finalmask := obj{"tcp": []obj{fmMask("sudoku", tc.settings)}}
			startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{"network": "raw", "finalmask": finalmask}))
			tap := fmStartTap(t, port)
			checkTCP(t, fmProxy(t, obj{"type": "vless", "port": tap.port, "uuid": userUUID, "finalmask": finalmask}), tg)
			tap.mu.Lock()
			defer tap.mu.Unlock()
			require.NotEmpty(t, tap.reads)
			for _, read := range tap.reads {
				for _, b := range read {
					if !tc.shape(b) {
						t.Fatalf("byte %#x on the wire", b)
					}
				}
			}
		})
	}

	for name, client := range map[string]obj{
		"wrong-password":     {"password": "other", "customTables": fmSudokuTables[:2]},
		"no-password":        {"customTables": fmSudokuTables[:2]},
		"tables-swapped":     {"password": "interop", "customTables": []string{fmSudokuTables[1], fmSudokuTables[0]}},
		"one-table-of-two":   {"password": "interop", "customTables": fmSudokuTables[:1]},
		"other-table":        {"password": "interop", "customTables": []string{fmSudokuTables[0], fmSudokuTables[2]}},
		"ascii-for-entropy":  {"password": "interop", "ascii": "prefer_ascii"},
		"entropy-for-tables": {"password": "interop"},
	} {
		t.Run("fails-"+name, func(t *testing.T) {
			server := obj{"password": "interop", "customTables": fmSudokuTables[:2]}
			fmCheckFails(t, fmSudokuVless(t, server, client, "", ""), tg)
		})
	}
	t.Run("fails-without-the-mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "finalmask": obj{"tcp": []obj{fmMask("sudoku", obj{"password": "interop"})}},
		}))
		fmCheckFails(t, fmProxy(t, obj{"type": "vless", "port": port, "uuid": userUUID}), tg)
	})
}

func TestFinalmaskSudokuKCP(t *testing.T) {
	tg := startTargets(t)

	for name, settings := range map[string]obj{
		"entropy":                  {"password": "interop"},
		"ascii-padding-20-60":      {"password": "interop", "ascii": "prefer_ascii", "paddingMin": 20, "paddingMax": 60},
		"custom-table":             {"password": "interop", "customTable": fmSudokuTables[4]},
		"two-tables-padding-100":   {"password": "interop", "customTables": fmSudokuTables[:2], "paddingMin": 100, "paddingMax": 100},
		"three-tables-padding-0-9": {"customTables": fmSudokuTables[3:6], "paddingMax": 9},
	} {
		t.Run(name, func(t *testing.T) {
			proxy := fmSudokuKCP(t, settings, settings, fmSudokuKCPMTU)
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}

	// (3000+6)*9+1 = 27055 bytes: a masked datagram may be as large as UDP
	// carries, loopback takes it in one piece.
	t.Run("large-datagrams", func(t *testing.T) {
		settings := obj{"password": "interop", "customTables": fmSudokuTables[:2], "paddingMin": 100, "paddingMax": 100}
		proxy := fmSudokuKCP(t, settings, settings, 3000)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	server := obj{"password": "interop", "customTables": fmSudokuTables[:2]}
	t.Run("fails-wrong-password", func(t *testing.T) {
		fmCheckFails(t, fmSudokuKCP(t, server, obj{"password": "other", "customTables": fmSudokuTables[:2]}, fmSudokuKCPMTU), tg)
	})
	t.Run("fails-tables-swapped", func(t *testing.T) {
		client := obj{"password": "interop", "customTables": []string{fmSudokuTables[1], fmSudokuTables[0]}}
		fmCheckFails(t, fmSudokuKCP(t, server, client, fmSudokuKCPMTU), tg)
	})
}

// A QUIC packet of 1200 to 1452 bytes becomes a datagram of up to 13 KiB.
// That needs a path that carries such datagrams, as loopback does.
func TestFinalmaskSudokuHysteria2(t *testing.T) {
	tg := startTargets(t)

	for name, settings := range map[string]obj{
		"entropy":                 {"password": "interop"},
		"ascii-padding-20-60":     {"password": "interop", "ascii": "prefer_ascii", "paddingMin": 20, "paddingMax": 60},
		"two-tables-padding-100":  {"password": "interop", "customTables": fmSudokuTables[:2], "paddingMin": 100, "paddingMax": 100},
		"three-tables-no-padding": {"customTables": fmSudokuTables[1:4]},
	} {
		t.Run(name, func(t *testing.T) {
			proxy := fmSudokuHysteria(t, settings, settings)
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}

	t.Run("fails-wrong-password", func(t *testing.T) {
		fmCheckFails(t, fmSudokuHysteria(t, obj{"password": "interop"}, obj{"password": "other"}), tg)
	})
	t.Run("fails-other-tables", func(t *testing.T) {
		server := obj{"password": "interop", "customTables": fmSudokuTables[:2]}
		client := obj{"password": "interop", "customTables": fmSudokuTables[1:3]}
		fmCheckFails(t, fmSudokuHysteria(t, server, client), tg)
	})
}
