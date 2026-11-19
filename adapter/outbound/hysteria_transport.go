package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/finalmask"
	"github.com/metacubex/mihomo/transport/hystream"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/quic-go"
)

// HyStreamOptions is `hysteria-opts`, the client part of
// hysteriaSettings of Xray-core, for `network: hysteria`: the proxy protocol
// runs in the streams of a Hysteria 2 connection, see transport/hystream.
type HyStreamOptions struct {
	Version int    `proxy:"version,omitempty"` // 2, the only one there is
	Auth    string `proxy:"auth,omitempty"`
}

// hysteriaTransport describes the proxy a hysteria transport client is built for.
type hysteriaTransport struct {
	Base   *Base
	Basic  *BasicOption
	Dialer C.Dialer
	Server string
	Port   int
	TLS    bool
	ALPN   []string
	// TLSConfig holds the TLS options of the proxy; Host is the server name
	// and may be empty.
	TLSConfig vmess.TLSConfig
	Options   *HyStreamOptions
}

func newHysteriaTransport(t hysteriaTransport) (*hystream.Client, error) {
	if v := t.Options.Version; v != 0 && v != 2 {
		return nil, fmt.Errorf("hysteria transport: unsupported version %d", v)
	}
	if !t.TLS {
		return nil, errors.New("hysteria transport requires TLS")
	}
	if c := t.TLSConfig; c.Reality != nil || c.ShadowTLS != nil || c.Restls != nil || c.JLS != nil || c.TLSMirror != nil {
		return nil, errors.New("hysteria transport takes plain TLS only")
	}
	addr := net.JoinHostPort(t.Server, strconv.Itoa(t.Port))
	quicParams := finalmask.QuicParamsOf(t.Dialer) // nil without finalmask.quic-params
	return hystream.NewClient(hystream.Config{
		Auth:       t.Options.Auth,
		ReceiveBPS: quicParams.HysteriaReceiveBPS(),
		Dial: func(ctx context.Context, cfg *quic.Config) (net.PacketConn, *quic.Conn, error) {
			if quicParams != nil {
				cfg = cfg.Clone() // the config belongs to the transport
				quicParams.ApplyTo(cfg)
			}
			tlsConfig := t.TLSConfig
			if tlsConfig.Host == "" {
				tlsConfig.Host = t.Server
			}
			tlsConfig.NextProtos = t.ALPN
			if len(tlsConfig.NextProtos) == 0 {
				tlsConfig.NextProtos = []string{"h3"}
			}
			stdConfig, err := tlsConfig.ToStdConfig()
			if err != nil {
				return nil, nil, err
			}
			if err = tlsConfig.ECH.ClientHandle(ctx, stdConfig); err != nil {
				return nil, nil, err
			}
			return common.DialQuic(ctx, addr, t.Basic.quicDialOptions(t.Base), t.Dialer, stdConfig, cfg, common.DialQuicOption{})
		},
		OnConnected: quicParams.ApplyHysteriaStream,
	})
}
