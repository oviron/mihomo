package xraytest

import "testing"

func TestFinalmaskNoise(t *testing.T) {
	tg := startTargets(t)
	noise := fmMask("noise", obj{"noise": []obj{
		{"rand": "40-80", "delay": "1-3"},
		{"type": "exp", "packet": "<b 0xc000000001> <r 20-40> <t> <c> <n>"},
		{"type": "hex", "packet": "0001020304050607"},
	}})

	// Only the client sends noise, the server drops it as broken QUIC.
	t.Run("client", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port))
		proxy := fmHysteria(t, port, nil, noise)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	t.Run("both-sides", func(t *testing.T) {
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, noise))
		proxy := fmHysteria(t, port, nil, noise)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})

	// Noise first in the list goes through salamander, noise last goes raw.
	salamander := fmMask("salamander", obj{"password": "obfs-password"})
	for name, masks := range map[string][]obj{
		"masked-noise": {noise, salamander},
		"raw-noise":    {salamander, noise},
	} {
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			startXray(t, fmHysteriaInbound(port, salamander))
			proxy := fmHysteria(t, port, nil, masks...)
			checkTCP(t, proxy, tg)
			checkUDP(t, proxy, tg)
		})
	}
}
