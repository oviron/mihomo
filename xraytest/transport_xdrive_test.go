package xraytest

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// trVlessEnc returns a decryption/encryption pair of VLESS Encryption, which
// the xdrive transport requires.
func trVlessEnc(t *testing.T) (decryption, encryption string) {
	t.Helper()
	out := trXrayTool(t, "vlessenc")
	dec := regexp.MustCompile(`"decryption": "([^"]+)"`).FindStringSubmatch(out)
	enc := regexp.MustCompile(`"encryption": "([^"]+)"`).FindStringSubmatch(out)
	require.NotNil(t, dec, out)
	require.NotNil(t, enc, out)
	return dec[1], enc[1]
}

// trXDriveServer starts an Xray inbound on the xdrive transport with the given
// xdriveSettings.
func trXDriveServer(t *testing.T, settings obj) (encryption string) {
	t.Helper()
	decryption, encryption := trVlessEnc(t)
	startXray(t, obj{
		"listen": "127.0.0.1", "port": freePort(t), "protocol": "vless",
		"settings":       obj{"clients": []obj{{"id": userUUID}}, "decryption": decryption},
		"streamSettings": obj{"network": "xdrive", "xdriveSettings": settings},
	})
	return encryption
}

func trXDriveProxy(t *testing.T, encryption string, opts obj) C.Proxy {
	t.Helper()
	proxy, err := adapter.ParseProxy(map[string]any{
		"name": "xray", "type": "vless", "uuid": userUUID, "encryption": encryption,
		"server": "storage.invalid", "port": 443, // not dialed
		"network": "xdrive", "xdrive-opts": map[string]any(opts),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// trXDriveCheck pushes streams through the storage: one after another and
// several at once, each a session of its own.
func trXDriveCheck(t *testing.T, proxy C.Proxy, tg targets) {
	t.Helper()
	require.NoError(t, trRoundTrip(proxy, tg, 16, 30*time.Second))
	require.NoError(t, trRoundTrip(proxy, tg, 3<<20, 60*time.Second))
	errs := make(chan error, 4)
	for i := 0; i < cap(errs); i++ {
		go func() { errs <- trRoundTrip(proxy, tg, 256<<10, 60*time.Second) }()
	}
	for i := 0; i < cap(errs); i++ {
		require.NoError(t, <-errs)
	}
}

// The local service: client and server share a directory. The client runs
// plain VLESS streams, one session each, without Mux.Cool.
func TestTransportXDriveLocal(t *testing.T) {
	tg := startTargets(t)
	folder := t.TempDir()
	encryption := trXDriveServer(t, obj{"service": "local", "remoteFolder": folder})
	proxy := trXDriveProxy(t, encryption, obj{"service": "local", "remote-folder": folder})
	trXDriveCheck(t, proxy, tg)

	// both sides delete what they have read: nothing piles up
	time.Sleep(time.Second)
	entries, err := os.ReadDir(folder + "/sessions")
	require.NoError(t, err)
	require.Empty(t, entries, "announcements left behind")
}

func TestTransportXDriveNeedsEncryption(t *testing.T) {
	_, err := adapter.ParseProxy(map[string]any{
		"name": "xray", "type": "vless", "uuid": userUUID, "server": "storage.invalid", "port": 443,
		"network": "xdrive", "xdrive-opts": map[string]any{"service": "local", "remote-folder": t.TempDir()},
	})
	require.ErrorContains(t, err, "encryption")
}
