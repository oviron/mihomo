package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
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
	// alpn is what to offer; a client fingerprint offers its own list
	dialTLS := func(alpn []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
			defer cancel()
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
				NextProtos:        alpn,
				ECH:               ech,
			})
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	}

	// HTTP/2 the way the other transports force it, see xhttp.NewTransport
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &xdriveTransport{
		probe: dialTLS([]string{"h2", "http/1.1"}),
		h1: &http.Transport{
			DialContext:           dial,
			DialTLSContext:        dialTLS([]string{"http/1.1"}),
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		h2: &http.Transport{
			DialTLSContext:        dialTLS([]string{"h2"}),
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			Protocols:             protocols,
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// xdriveTransport speaks to each HTTPS host the protocol its TLS handshake
// settles on: storage services differ, and with a client fingerprint the ALPN
// list is that of the browser, so the choice is the server's. The first
// request to a host makes one handshake to find out.
type xdriveTransport struct {
	probe  func(ctx context.Context, network, addr string) (net.Conn, error)
	h1, h2 *http.Transport
	useH2  sync.Map // host:port -> bool
}

func (t *xdriveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.h1.RoundTrip(req)
	}
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	h2, known := t.useH2.Load(addr)
	if !known {
		conn, err := t.probe(req.Context(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		h2 = tlsC.GetTLSConnectionState(conn).NegotiatedProtocol == "h2"
		_ = conn.Close()
		t.useH2.Store(addr, h2)
	}
	if h2.(bool) {
		return t.h2.RoundTrip(req)
	}
	return t.h1.RoundTrip(req)
}

func (t *xdriveTransport) CloseIdleConnections() {
	t.h1.CloseIdleConnections()
	t.h2.CloseIdleConnections()
}
