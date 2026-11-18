package outbound

import (
	"time"

	"github.com/metacubex/mihomo/transport/xhttp"
)

// build turns an `xmux` block into pool settings with the meaning Xray-core
// gives them, see transport/xhttp/xmux.go.
func (o *XHTTPReuseSettings) build() (*xhttp.ReuseConfig, time.Duration) {
	return &xhttp.ReuseConfig{
		MaxConcurrency:   o.MaxConcurrency,
		MaxConnections:   o.MaxConnections,
		CMaxReuseTimes:   o.CMaxReuseTimes,
		HMaxRequestTimes: o.HMaxRequestTimes,
		HMaxReusableSecs: o.HMaxReusableSecs,
		XraySemantics:    true,
	}, time.Duration(o.HKeepAlivePeriod) * time.Second
}

// XHTTPDownloadXHTTPOptions are the xhttp options the download leg may set
// apart from the upload leg, as downloadSettings.xhttpSettings does in
// Xray-core. The download leg is one GET, so these are the options a GET
// carries: the padding and where the session id goes.
type XHTTPDownloadXHTTPOptions struct {
	XPaddingBytes     *string `proxy:"x-padding-bytes,omitempty"`
	XPaddingObfsMode  *bool   `proxy:"x-padding-obfs-mode,omitempty"`
	XPaddingKey       *string `proxy:"x-padding-key,omitempty"`
	XPaddingHeader    *string `proxy:"x-padding-header,omitempty"`
	XPaddingPlacement *string `proxy:"x-padding-placement,omitempty"`
	XPaddingMethod    *string `proxy:"x-padding-method,omitempty"`
	SessionPlacement  *string `proxy:"session-placement,omitempty"`
	SessionKey        *string `proxy:"session-key,omitempty"`
}

// apply overrides what cfg inherited from the upload leg.
func (o *XHTTPDownloadXHTTPOptions) apply(cfg *xhttp.Config) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&cfg.XPaddingBytes, o.XPaddingBytes)
	if o.XPaddingObfsMode != nil {
		cfg.XPaddingObfsMode = *o.XPaddingObfsMode
	}
	set(&cfg.XPaddingKey, o.XPaddingKey)
	set(&cfg.XPaddingHeader, o.XPaddingHeader)
	set(&cfg.XPaddingPlacement, o.XPaddingPlacement)
	set(&cfg.XPaddingMethod, o.XPaddingMethod)
	set(&cfg.SessionPlacement, o.SessionPlacement)
	set(&cfg.SessionKey, o.SessionKey)
}
