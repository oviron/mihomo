package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xdrive"

	"github.com/metacubex/http"
)

// XDriveOptions is `xdrive-opts`, the client part of xdriveSettings of
// Xray-core, for `network: xdrive`: the stream goes through objects in a
// storage, see transport/xdrive. `server` and `port` of the proxy are not
// dialed; the storage is reached at the address of its URL, through the dialer
// of the proxy and with its TLS options. `template` is the template object of
// Xray-core as it is, keys included.
type XDriveOptions struct {
	Service           string           `proxy:"service,omitempty"` // s3, template or local
	RemoteFolder      string           `proxy:"remote-folder,omitempty"`
	Secrets           []string         `proxy:"secrets,omitempty"`
	SegmentBytes      uint32           `proxy:"segment-bytes,omitempty"`
	FlushIntervalMs   uint32           `proxy:"flush-interval-ms,omitempty"`
	PollIntervalMs    uint32           `proxy:"poll-interval-ms,omitempty"`
	MaxPollIntervalMs uint32           `proxy:"max-poll-interval-ms,omitempty"`
	Concurrency       uint32           `proxy:"concurrency,omitempty"`
	EagerWindowMs     uint32           `proxy:"eager-window-ms,omitempty"`
	HoleTimeoutMs     uint32           `proxy:"hole-timeout-ms,omitempty"`
	S3                *XDriveS3Options `proxy:"s3,omitempty"`
	Template          map[string]any   `proxy:"template,omitempty"`
}

type XDriveS3Options struct {
	Endpoint  string `proxy:"endpoint,omitempty"`
	Region    string `proxy:"region,omitempty"`
	Bucket    string `proxy:"bucket,omitempty"`
	PathStyle *bool  `proxy:"path-style,omitempty"` // true when unset
}

// newXDriveClient builds the client for a VLESS proxy. Xray-core takes only
// VLESS with its encryption and without a flow over this transport: nothing
// else protects what is stored.
func newXDriveClient(option *VlessOption, httpClient xdrive.HTTPDoer) (*xdrive.Client, error) {
	if option.Flow != "" {
		return nil, errors.New(`the xdrive transport doesn't support VLESS "flow"`)
	}
	if option.Encryption == "" || option.Encryption == "none" {
		return nil, errors.New(`the xdrive transport needs VLESS "encryption"`)
	}
	opts := option.XDriveOpts
	cfg := xdrive.Config{
		Service:           opts.Service,
		RemoteFolder:      opts.RemoteFolder,
		Secrets:           opts.Secrets,
		SegmentBytes:      opts.SegmentBytes,
		FlushIntervalMs:   opts.FlushIntervalMs,
		PollIntervalMs:    opts.PollIntervalMs,
		MaxPollIntervalMs: opts.MaxPollIntervalMs,
		Concurrency:       opts.Concurrency,
		EagerWindowMs:     opts.EagerWindowMs,
		HoleTimeoutMs:     opts.HoleTimeoutMs,
		HTTPClient:        httpClient,
	}
	if opts.Template != nil {
		template, err := json.Marshal(opts.Template)
		if err != nil {
			return nil, err
		}
		cfg.Template = string(template)
	}
	if opts.S3 != nil {
		cfg.S3 = &xdrive.S3Config{
			Endpoint:  opts.S3.Endpoint,
			Region:    opts.S3.Region,
			Bucket:    opts.S3.Bucket,
			PathStyle: opts.S3.PathStyle == nil || *opts.S3.PathStyle,
		}
	}
	return xdrive.NewClient(cfg)
}

// xdriveHTTPClient is how the s3 and template services reach the storage: over
// the dialer of the proxy, with its client fingerprint and certificate
// options. servername, when set, replaces the host of the URL in the TLS
// handshake. Redirects are not followed: a signed request is for one host.
func xdriveHTTPClient(dialer C.Dialer, option *VlessOption, ech *ech.Config) *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: dial,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dial(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				host, _, _ := net.SplitHostPort(addr)
				if option.ServerName != "" {
					host = option.ServerName
				}
				tlsConn, err := vmess.StreamTLSConn(ctx, conn, &vmess.TLSConfig{
					Host:              host,
					SkipCertVerify:    option.SkipCertVerify,
					NameCertVerify:    option.NameCertVerify,
					FingerPrint:       option.Fingerprint,
					Certificate:       option.Certificate,
					PrivateKey:        option.PrivateKey,
					ClientFingerprint: option.ClientFingerprint,
					NextProtos:        []string{"http/1.1"},
					ECH:               ech,
				})
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}
