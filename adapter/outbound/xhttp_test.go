package outbound

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/stretchr/testify/require"
)

func decodeVlessOption(t *testing.T, mapping map[string]any) VlessOption {
	t.Helper()
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	var option VlessOption
	require.NoError(t, decoder.Decode(mapping, &option))
	return option
}

func TestXHTTPXmuxOption(t *testing.T) {
	option := decodeVlessOption(t, map[string]any{
		"name": "x", "server": "example.org", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"network": "xhttp",
		"xhttp-opts": map[string]any{
			"xmux": map[string]any{"max-connections": "2", "h-max-request-times": "600-900", "h-keep-alive-period": 30},
		},
	})
	require.NotNil(t, option.XHTTPOpts.Xmux)
	cfg, keepAlive := option.XHTTPOpts.Xmux.build()
	require.Equal(t, &xhttp.ReuseConfig{MaxConnections: "2", HMaxRequestTimes: "600-900", XraySemantics: true, HKeepAlivePeriod: 30}, cfg)
	require.Equal(t, 30*time.Second, keepAlive)

	_, err := NewVless(option)
	require.NoError(t, err)
}

func TestXHTTPDownloadOptions(t *testing.T) {
	option := decodeVlessOption(t, map[string]any{
		"name": "x", "server": "example.org", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"network": "xhttp",
		"xhttp-opts": map[string]any{
			"x-padding-obfs-mode": true,
			"x-padding-key":       "up",
			"session-placement":   "header",
			"download-settings": map[string]any{
				"path":              "/down",
				"x-padding-key":     "down",
				"x-padding-bytes":   "10-20",
				"session-placement": "query",
				"session-key":       "s",
				"seq-placement":     "path",
				"xmux":              map[string]any{},
			},
		},
	})
	ds := option.XHTTPOpts.DownloadSettings
	require.NotNil(t, ds)
	require.NotNil(t, ds.Xmux)

	cfg := xhttp.Config{XPaddingObfsMode: true, XPaddingKey: "up", XPaddingHeader: "H", SessionPlacement: "header", SeqPlacement: "header"}
	ds.XHTTPDownloadXHTTPOptions.apply(&cfg)
	require.Equal(t, xhttp.Config{
		XPaddingObfsMode: true, XPaddingKey: "down", XPaddingHeader: "H", XPaddingBytes: "10-20",
		SessionPlacement: "query", SessionKey: "s", SeqPlacement: "path",
	}, cfg)
	require.Equal(t, "/", cfg.NormalizedPath()) // the download path ends in "/" again

	_, err := NewVless(option)
	require.NoError(t, err)
}
