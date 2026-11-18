package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/samber/lo"
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
		HKeepAlivePeriod: o.HKeepAlivePeriod,
	}, time.Duration(o.HKeepAlivePeriod) * time.Second
}

// XHTTPDownloadXHTTPOptions are the xhttp options the download leg may set
// apart from the upload leg, as downloadSettings.xhttpSettings does in
// Xray-core. The download leg is one GET, so these are the options a GET
// carries: the padding and where the session id goes. The place of the
// sequence number is here because it decides whether the path ends in "/".
type XHTTPDownloadXHTTPOptions struct {
	XPaddingBytes     *string `proxy:"x-padding-bytes,omitempty"`
	XPaddingObfsMode  *bool   `proxy:"x-padding-obfs-mode,omitempty"`
	XPaddingKey       *string `proxy:"x-padding-key,omitempty"`
	XPaddingHeader    *string `proxy:"x-padding-header,omitempty"`
	XPaddingPlacement *string `proxy:"x-padding-placement,omitempty"`
	XPaddingMethod    *string `proxy:"x-padding-method,omitempty"`
	SessionPlacement  *string `proxy:"session-placement,omitempty"`
	SessionKey        *string `proxy:"session-key,omitempty"`
	SeqPlacement      *string `proxy:"seq-placement,omitempty"`
	SeqKey            *string `proxy:"seq-key,omitempty"`
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
	set(&cfg.SeqPlacement, o.SeqPlacement)
	set(&cfg.SeqKey, o.SeqKey)
}

// xhttpTransport describes the proxy an XHTTP client is built for. It serves
// the adapters that carry their protocol over XHTTP the way Xray-core lets any
// protocol do; VLESS builds its client in vless.go.
type xhttpTransport struct {
	// DialOptions are the dial options of the proxy, for the QUIC connections
	// of HTTP/3, which do not go through Dialer.
	DialOptions []dialer.Option
	Dialer      C.Dialer
	Server      string
	Port        int
	TLS         bool
	ALPN        []string
	// TLSConfig holds the TLS options of the proxy; Host is the server name
	// and may be empty, NextProtos is filled per connection.
	TLSConfig vmess.TLSConfig
	Options   *XHTTPOptions
}

// xhttpLeg is one of the two connections of an XHTTP stream: where it goes
// and how it is secured.
type xhttpLeg struct {
	dialOptions []dialer.Option
	dialer      C.Dialer
	server      string
	addr        string
	tls         bool
	alpn        []string
	tlsConfig   vmess.TLSConfig
	keepAlive   time.Duration
}

func (l *xhttpLeg) serverName() string {
	if l.tlsConfig.Host != "" {
		return l.tlsConfig.Host
	}
	return l.server
}

// requestHost is the Host of the requests: host > servername > server.
func (l *xhttpLeg) requestHost(host string) string {
	if host != "" {
		return host
	}
	host = l.serverName()
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		host = "[" + host + "]"
	}
	return host
}

func (l *xhttpLeg) transport() http.RoundTripper {
	return xhttp.NewTransport(
		func(ctx context.Context) (net.Conn, error) {
			return l.dialer.DialContext(ctx, "tcp", l.addr)
		},
		func(ctx context.Context, raw net.Conn, isH2 bool) (net.Conn, error) {
			if !l.tls {
				return raw, nil
			}
			tlsConfig := l.tlsConfig
			tlsConfig.Host = l.serverName()
			tlsConfig.NextProtos = l.alpn
			if isH2 {
				tlsConfig.NextProtos = []string{"h2"}
			}
			return vmess.StreamTLSConn(ctx, raw, &tlsConfig)
		},
		func(ctx context.Context, cfg *quic.Config) (*quic.Conn, error) {
			if !l.tls {
				return nil, errors.New("xhttp HTTP/3 requires TLS")
			}
			if c := l.tlsConfig; c.Reality != nil || c.ShadowTLS != nil || c.Restls != nil || c.JLS != nil || c.TLSMirror != nil {
				return nil, errors.New("xhttp HTTP/3 takes plain TLS only")
			}
			tlsConfig := l.tlsConfig
			tlsConfig.Host = l.serverName()
			tlsConfig.NextProtos = []string{"h3"}
			stdConfig, err := tlsConfig.ToStdConfig()
			if err != nil {
				return nil, err
			}
			if err = tlsConfig.ECH.ClientHandle(ctx, stdConfig); err != nil {
				return nil, err
			}
			quicParams := finalmask.QuicParamsOf(l.dialer) // nil without finalmask.quic-params
			_, quicConn, err := common.DialQuic(ctx, l.addr, l.dialOptions, l.dialer, stdConfig, quicParams.HTTP3Config(cfg), common.DialQuicOption{Early: true})
			if err != nil {
				return nil, err
			}
			quicParams.ApplyCongestion(quicConn, 0)
			return quicConn, nil
		},
		l.alpn,
		l.keepAlive,
	)
}

func newXHTTPClient(t xhttpTransport) (*xhttp.Client, error) {
	opts := t.Options
	upload := &xhttpLeg{
		dialOptions: t.DialOptions,
		dialer:      t.Dialer,
		server:      t.Server,
		addr:        net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		tls:         t.TLS,
		alpn:        t.ALPN,
		tlsConfig:   t.TLSConfig,
	}

	var reuseCfg *xhttp.ReuseConfig
	if opts.ReuseSettings != nil {
		reuseCfg, upload.keepAlive = opts.ReuseSettings.build()
		reuseCfg.XraySemantics = false
	}
	if opts.Xmux != nil {
		reuseCfg, upload.keepAlive = opts.Xmux.build()
	}

	cfg := &xhttp.Config{
		Host:                 upload.requestHost(opts.Host),
		Path:                 opts.Path,
		Mode:                 opts.Mode,
		Headers:              opts.Headers,
		NoGRPCHeader:         opts.NoGRPCHeader,
		XPaddingBytes:        opts.XPaddingBytes,
		XPaddingObfsMode:     opts.XPaddingObfsMode,
		XPaddingKey:          opts.XPaddingKey,
		XPaddingHeader:       opts.XPaddingHeader,
		XPaddingPlacement:    opts.XPaddingPlacement,
		XPaddingMethod:       opts.XPaddingMethod,
		UplinkHTTPMethod:     opts.UplinkHTTPMethod,
		SessionPlacement:     opts.SessionPlacement,
		SessionKey:           opts.SessionKey,
		SessionTable:         opts.SessionTable,
		SessionLength:        opts.SessionLength,
		SeqPlacement:         opts.SeqPlacement,
		SeqKey:               opts.SeqKey,
		UplinkDataPlacement:  opts.UplinkDataPlacement,
		UplinkDataKey:        opts.UplinkDataKey,
		UplinkChunkSize:      opts.UplinkChunkSize,
		ScMaxEachPostBytes:   opts.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: opts.ScMinPostsIntervalMs,
		PipelinePosts:        opts.PipelinePosts,
		ReuseConfig:          reuseCfg,
	}

	var makeDownloadTransport xhttp.TransportMaker
	if ds := opts.DownloadSettings; ds != nil {
		if cfg.Mode == "stream-one" {
			return nil, errors.New(`xhttp mode "stream-one" cannot be used with download-settings`)
		}
		if ds.ShadowTLSOpts != nil || ds.RestlsOpts != nil || ds.JLSOpts != nil {
			return nil, errors.New("xhttp download-settings: shadow-tls-opts, restls-opts and jls-opts are for vless only")
		}
		download := *upload
		download.server = lo.FromPtrOr(ds.Server, t.Server)
		download.addr = net.JoinHostPort(download.server, strconv.Itoa(lo.FromPtrOr(ds.Port, t.Port)))
		download.tls = lo.FromPtrOr(ds.TLS, t.TLS)
		download.alpn = lo.FromPtrOr(ds.ALPN, t.ALPN)
		download.tlsConfig.Host = lo.FromPtrOr(ds.ServerName, t.TLSConfig.Host)
		download.tlsConfig.SkipCertVerify = lo.FromPtrOr(ds.SkipCertVerify, t.TLSConfig.SkipCertVerify)
		download.tlsConfig.NameCertVerify = lo.FromPtrOr(ds.NameCertVerify, t.TLSConfig.NameCertVerify)
		download.tlsConfig.FingerPrint = lo.FromPtrOr(ds.Fingerprint, t.TLSConfig.FingerPrint)
		download.tlsConfig.Certificate = lo.FromPtrOr(ds.Certificate, t.TLSConfig.Certificate)
		download.tlsConfig.PrivateKey = lo.FromPtrOr(ds.PrivateKey, t.TLSConfig.PrivateKey)
		download.tlsConfig.ClientFingerprint = lo.FromPtrOr(ds.ClientFingerprint, t.TLSConfig.ClientFingerprint)
		var err error
		if ds.ECHOpts != nil {
			if download.tlsConfig.ECH, err = ds.ECHOpts.Parse(); err != nil {
				return nil, err
			}
		}
		if ds.RealityOpts != nil {
			if download.tlsConfig.Reality, err = ds.RealityOpts.Parse(); err != nil {
				return nil, err
			}
		}
		if download.tlsConfig.Reality != nil && !download.tls {
			return nil, errors.New("xhttp download-settings: REALITY requires TLS")
		}

		downloadCfg := *cfg
		downloadCfg.Host = download.requestHost(lo.FromPtrOr(ds.Host, opts.Host))
		downloadCfg.Path = lo.FromPtrOr(ds.Path, opts.Path)
		downloadCfg.Headers = lo.FromPtrOr(ds.Headers, opts.Headers)
		if ds.ReuseSettings != nil {
			downloadCfg.ReuseConfig, download.keepAlive = ds.ReuseSettings.build()
			downloadCfg.ReuseConfig.XraySemantics = false
		}
		if ds.Xmux != nil {
			downloadCfg.ReuseConfig, download.keepAlive = ds.Xmux.build()
		}
		ds.XHTTPDownloadXHTTPOptions.apply(&downloadCfg)
		cfg.DownloadConfig = &downloadCfg
		makeDownloadTransport = download.transport
	}

	return xhttp.NewClient(cfg, upload.transport, makeDownloadTransport, t.TLSConfig.Reality != nil)
}
