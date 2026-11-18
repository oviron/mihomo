package xraytest

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

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

	// The noise comes from a Lua script.
	t.Run("script", func(t *testing.T) {
		home := C.Path.HomeDir()
		dir := t.TempDir()
		C.SetHomeDir(dir)
		defer C.SetHomeDir(home)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "quic-like.lua"), []byte(`
local noise = require("xray.finalmask.noise")

-- something that looks like the start of a QUIC long header packet
function HandleNoise(plan, address)
	plan:Add(string.char(0xc3, 0x00, 0x00, 0x00, 0x01, 0x08) .. noise.Random(8) .. noise.Random(noise.RandomBetween(100, 200)), 3)
	plan:AddRandom(64)
end
`), 0o600))
		script := fmMask("noise", obj{"script": "quic-like.lua"})
		port := freePort(t)
		startXray(t, fmHysteriaInbound(port, salamander))
		proxy := fmHysteria(t, port, nil, script, salamander)
		checkTCP(t, proxy, tg)
		checkUDP(t, proxy, tg)
	})
}
