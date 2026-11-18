package xraytest

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

func adapterParse(mapping obj) (C.Proxy, error) {
	return adapter.ParseProxy(mapping)
}

// quic-params is local tuning of the client's QUIC connection; the checks are
// that every setting is accepted and the connection works with it.
func TestFinalmaskQuicParams(t *testing.T) {
	tg := startTargets(t)
	for name, params := range map[string]obj{
		"bbr":          {"congestion": "bbr", "bbr-profile": "aggressive"},
		"reno":         {"congestion": "reno"},
		"brutal":       {"congestion": "brutal", "brutal-up": "50 mbps", "brutal-down": "100mbps"},
		"force-brutal": {"congestion": "force-brutal", "brutalUp": "20m"},
		"windows": {
			"initStreamReceiveWindow": 1 << 20, "maxStreamReceiveWindow": 1 << 22,
			"initConnectionReceiveWindow": 1 << 21, "maxConnectionReceiveWindow": 1 << 23,
			"maxIdleTimeout": 20, "keepAlivePeriod": 5, "disablePathMTUDiscovery": true,
			// accepted for Xray configs, with no effect here
			"debug": true, "disableGSO": true, "disableChromeParrot": true, "brutalDisableLossCompensation": true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			inbound := fmHysteriaInbound(port)
			// the server names its own receive rate, the client sends no faster
			inbound["streamSettings"].(obj)["finalmask"] = obj{"quicParams": obj{"congestion": "brutal", "brutalUp": "100mbps", "brutalDown": "30mbps"}}
			startXray(t, inbound)
			proxy := fmHysteria(t, port, obj{"finalmask": obj{"quic-params": params}})
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}
}
