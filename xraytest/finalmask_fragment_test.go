package xraytest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFinalmaskFragment(t *testing.T) {
	tg := startTargets(t)

	// Without the mask the ClientHello is one TLS record.
	t.Run("no-mask", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "security": "tls", "tlsSettings": tlsSettings(),
		}))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
		})
		checkTCP(t, proxy, tg)
		records := tap.handshakeRecords()
		require.Len(t, records, 1)
		require.Greater(t, records[0], 100)
	})

	t.Run("tlshello", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "security": "tls", "tlsSettings": tlsSettings(),
		}))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{
				"packets": "tlshello", "length": "20-40", "delay": "1-3", "max-split": "4-8",
			})}},
		})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		// the ClientHello reached the server as 4 to 7 records, all but the last of 20..39 bytes
		records := tap.handshakeRecords()
		require.GreaterOrEqual(t, len(records), 4)
		require.LessOrEqual(t, len(records), 7)
		for _, size := range records[:len(records)-1] {
			require.GreaterOrEqual(t, size, 20)
			require.Less(t, size, 40)
		}
	})

	// With TCP Fast Open the connection would only be made by the first
	// write; the masks get a connected one.
	t.Run("tfo", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "security": "tls", "tlsSettings": tlsSettings(),
		}))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "tfo": true,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{"packets": "tlshello", "length": "20-40", "delay": "1-3"})}},
		})
		checkTCP(t, proxy, tg)
		require.GreaterOrEqual(t, len(tap.handshakeRecords()), 4)
	})

	// The names Xray uses in JSON are accepted as they are.
	t.Run("tlshello-merged-xray-names", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), obj{
			"network": "raw", "security": "tls", "tlsSettings": tlsSettings(),
		}))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{
				"packets": "tlshello", "lengths": []any{"10-20", 50, "100-200"}, "maxSplit": 6,
			})}},
		})
		checkTCP(t, proxy, tg)
	})

	t.Run("writes", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), nil))
		tap := fmStartTap(t, port)
		proxy := fmProxy(t, obj{
			"type": "vless", "port": tap.port, "uuid": userUUID, "udp": true,
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{
				"packets": "1-1", "length": "3-9", "delay": "2-4",
			})}},
		})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
		// the first write, the VLESS request, arrived in pieces of 3..8 bytes
		sizes := tap.readSizes()
		require.GreaterOrEqual(t, len(sizes), 4)
		for _, size := range sizes[:3] {
			require.Less(t, size, 9)
		}
	})

	t.Run("several-writes", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), nil))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true,
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{
				"packets": "1-3", "length": "3-9", "delays": []any{"1-2", 0},
			})}},
		})
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("every-write", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmInbound("vless", port, fmVlessSettings(""), nil))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID,
			"finalmask": obj{"tcp": []obj{fmMask("fragment", obj{"length": "4000-9000"})}},
		})
		checkTCP(t, proxy, tg)
	})

	// The server fragments what it writes too; the client needs nothing for that.
	t.Run("vision-both-sides", func(t *testing.T) {
		const flow = "xtls-rprx-vision"
		port := freePort(t)
		fragment := fmMask("fragment", obj{"packets": "tlshello", "length": "30-60", "delay": "1-2"})
		startXray(t, fmInbound("vless", port, fmVlessSettings(flow), obj{
			"network": "raw", "security": "tls", "tlsSettings": tlsSettings(),
			"finalmask": obj{"tcp": []obj{fragment}},
		}))
		proxy := fmProxy(t, obj{
			"type": "vless", "port": port, "uuid": userUUID, "udp": true, "flow": flow,
			"tls": true, "skip-cert-verify": true, "servername": "example.org",
			"finalmask": obj{"tcp": []obj{fragment}},
		})
		checkTCP(t, proxy, tg)
		checkTLS(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
}
