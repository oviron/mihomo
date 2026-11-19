package xraytest

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// fmKCPInbound is a VMess inbound over mKCP with the given UDP masks. Since
// 26.x Xray's mKCP has no obfuscation of its own, it is all in finalmask.
func fmKCPInbound(port int, udpMasks ...obj) obj {
	stream := obj{"network": "kcp", "kcpSettings": obj{}}
	if len(udpMasks) > 0 {
		stream["finalmask"] = obj{"udp": udpMasks}
	}
	return fmInbound("vmess", port, obj{"clients": []obj{{"id": userUUID}}}, stream)
}

func fmKCPMapping(port int, mkcpOpts obj, udpMasks ...obj) obj {
	mapping := obj{
		"type": "vmess", "port": port, "uuid": userUUID, "alterId": 0, "cipher": "auto",
		"network": "kcp", "udp": true,
	}
	if mkcpOpts != nil {
		mapping["mkcp-opts"] = mkcpOpts
	}
	if len(udpMasks) > 0 {
		mapping["finalmask"] = obj{"udp": udpMasks}
	}
	return mapping
}

func fmKCP(t *testing.T, port int, mkcpOpts obj, udpMasks ...obj) C.Proxy {
	t.Helper()
	return fmProxy(t, fmKCPMapping(port, mkcpOpts, udpMasks...))
}

func TestFinalmaskMKCP(t *testing.T) {
	tg := startTargets(t)
	raw := obj{"raw": true}
	legacy := func(settings obj) obj { return fmMask("mkcp-legacy", settings) }

	// Bare mKCP, what Xray speaks when it has no mask.
	t.Run("raw", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmKCPInbound(port))
		proxy := fmKCP(t, port, raw)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// Without raw mihomo adds its built-in obfuscation, which Xray takes for garbage.
	t.Run("builtin-against-bare", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmKCPInbound(port))
		fmCheckFails(t, fmKCP(t, port, nil), tg)
	})

	for _, tc := range []struct {
		name  string
		masks []obj
	}{
		{"original", []obj{legacy(nil)}},
		{"seed", []obj{legacy(obj{"value": "kcp-seed"})}},
		{"seed-wechat", []obj{legacy(obj{"value": "kcp-seed"}), legacy(obj{"header": "wechat"})}},
		{"original-dtls", []obj{legacy(obj{}), legacy(obj{"header": "dtls"})}},
		{"original-dns", []obj{legacy(nil), legacy(obj{"header": "dns", "value": "www.example.org"})}},
		{"dns-default-domain", []obj{legacy(obj{"header": "DNS"})}},
		{"header-only-utp", []obj{legacy(obj{"header": "utp"})}},
		{"header-only-srtp", []obj{legacy(obj{"header": "srtp"})}},
		{"header-only-wireguard", []obj{legacy(obj{"header": "wireguard"})}},
		{"header-under-seed", []obj{legacy(obj{"header": "dtls"}), legacy(obj{"value": "kcp-seed"})}},
		{"with-salamander", []obj{legacy(nil), fmMask("salamander", obj{"password": "obfs-password"})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			startXray(t, fmKCPInbound(port, tc.masks...))
			proxy := fmKCP(t, port, raw, tc.masks...)
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}

	// The obfuscation built into mihomo's mKCP is the same thing as the masks.
	for _, tc := range []struct {
		name     string
		masks    []obj
		mkcpOpts obj
	}{
		{"builtin-original", []obj{legacy(nil)}, nil},
		{"builtin-seed", []obj{legacy(obj{"value": "kcp-seed"})}, obj{"seed": "kcp-seed"}},
		{"builtin-seed-wechat", []obj{legacy(obj{"value": "kcp-seed"}), legacy(obj{"header": "wechat"})}, obj{"seed": "kcp-seed", "header": "wechat-video"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			startXray(t, fmKCPInbound(port, tc.masks...))
			proxy := fmKCP(t, port, tc.mkcpOpts)
			checkTCP(t, proxy, tg)
		})
	}

	t.Run("wrong-seed", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmKCPInbound(port, legacy(obj{"value": "kcp-seed"})))
		fmCheckFails(t, fmKCP(t, port, raw, legacy(obj{"value": "another-seed"})), tg)
	})

	// The client sends noise ahead of mKCP, the server drops it.
	t.Run("noise", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmKCPInbound(port, legacy(obj{"value": "kcp-seed"})))
		noise := fmMask("noise", obj{"noise": []obj{{"rand": "100-200"}, {"rand": "20-30", "delay": "2-5"}}})
		proxy := fmKCP(t, port, raw, legacy(obj{"value": "kcp-seed"}), noise)
		checkTCP(t, proxy, tg)
	})
}

func TestFinalmaskMKCPOptions(t *testing.T) {
	for name, mapping := range map[string]obj{
		"mask without raw": fmKCPMapping(443, nil, fmMask("mkcp-legacy", nil)),
		"raw with seed":    fmKCPMapping(443, obj{"raw": true, "seed": "kcp-seed"}),
		"raw with header":  fmKCPMapping(443, obj{"raw": true, "header": "dtls"}),
		"bad header":       fmKCPMapping(443, obj{"raw": true}, fmMask("mkcp-legacy", obj{"header": "quic"})),
	} {
		t.Run(name, func(t *testing.T) {
			mapping["name"] = "xray"
			mapping["server"] = "127.0.0.1"
			_, err := adapter.ParseProxy(mapping)
			require.Error(t, err)
		})
	}
}
