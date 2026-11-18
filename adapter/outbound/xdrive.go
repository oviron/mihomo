package outbound

import (
	"errors"

	"github.com/metacubex/mihomo/transport/xdrive"
)

// XDriveOptions is `xdrive-opts`, the client part of xdriveSettings of
// Xray-core, for `network: xdrive`: the stream goes through objects in a
// storage, see transport/xdrive. `server` and `port` of the proxy are not
// dialed.
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
