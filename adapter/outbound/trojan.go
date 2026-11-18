package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/hystream"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type Trojan struct {
	*Base
	option      *TrojanOption
	hexPassword [trojan.KeyLength]byte

	// for gun mux
	gunClient *gun.Client
	// for xhttp
	xhttpClient *xhttp.Client
	// for the hysteria transport
	hysteriaClient *hystream.Client

	echConfig       *ech.Config
	shadowTLSConfig *shadowtls.Config
	restlsConfig    *restls.Config
	jlsConfig       *jls.Config
	realityConfig   *tlsC.RealityConfig

	ssCipher core.Cipher
}

type TrojanOption struct {
	BasicOption
	Name              string           `proxy:"name"`
	Server            string           `proxy:"server"`
	Port              int              `proxy:"port"`
	Password          string           `proxy:"password"`
	TLS               *bool            `proxy:"tls,omitempty"` // false is trojan without TLS, which Xray-core serves too; TLS when unset
	ALPN              []string         `proxy:"alpn,omitempty"`
	SNI               string           `proxy:"sni,omitempty"`
	SkipCertVerify    bool             `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify    string           `proxy:"name-cert-verify,omitempty"`
	Fingerprint       string           `proxy:"fingerprint,omitempty"`
	Certificate       string           `proxy:"certificate,omitempty"`
	PrivateKey        string           `proxy:"private-key,omitempty"`
	UDP               bool             `proxy:"udp,omitempty"`
	Network           string           `proxy:"network,omitempty"`
	ECHOpts           ECHOptions       `proxy:"ech-opts,omitempty"`
	ShadowTLSOpts     ShadowTLSOptions `proxy:"shadow-tls-opts,omitempty"`
	RestlsOpts        RestlsOptions    `proxy:"restls-opts,omitempty"`
	JLSOpts           JLSOptions       `proxy:"jls-opts,omitempty"`
	RealityOpts       RealityOptions   `proxy:"reality-opts,omitempty"`
	GrpcOpts          GrpcOptions      `proxy:"grpc-opts,omitempty"`
	WSOpts            WSOptions        `proxy:"ws-opts,omitempty"`
	XHTTPOpts         XHTTPOptions     `proxy:"xhttp-opts,omitempty"`
	MKCPOpts          MKCPOptions      `proxy:"mkcp-opts,omitempty"`
	HysteriaOpts      HyStreamOptions  `proxy:"hysteria-opts,omitempty"`
	SSOpts            TrojanSSOption   `proxy:"ss-opts,omitempty"`
	ClientFingerprint string           `proxy:"client-fingerprint,omitempty"`
}

// TrojanSSOption from https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/shadowsocks/config.go#L5
type TrojanSSOption struct {
	Enabled  bool   `proxy:"enabled,omitempty"`
	Method   string `proxy:"method,omitempty"`
	Password string `proxy:"password,omitempty"`
}

func (t *Trojan) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	switch t.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(t.addr)

		wsOpts := &vmess.WebsocketConfig{
			Host:                     host,
			Port:                     port,
			Path:                     t.option.WSOpts.Path,
			MaxEarlyData:             t.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName:      t.option.WSOpts.EarlyDataHeaderName,
			V2rayHttpUpgrade:         t.option.WSOpts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: t.option.WSOpts.V2rayHttpUpgradeFastOpen,
			ClientFingerprint:        t.option.ClientFingerprint,
			ECHConfig:                t.echConfig,
			Headers:                  http.Header{},
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			for key, value := range t.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		alpn := trojan.DefaultWebsocketALPN
		if t.option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			alpn = t.option.ALPN
		}

		if t.shadowTLSConfig != nil || t.restlsConfig != nil || t.jlsConfig != nil {
			c, err = vmess.StreamTLSConn(ctx, c, &vmess.TLSConfig{
				Host:              t.option.SNI,
				SkipCertVerify:    t.option.SkipCertVerify,
				NameCertVerify:    t.option.NameCertVerify,
				FingerPrint:       t.option.Fingerprint,
				Certificate:       t.option.Certificate,
				PrivateKey:        t.option.PrivateKey,
				ClientFingerprint: t.option.ClientFingerprint,
				NextProtos:        []string{"http/1.1"},
				ShadowTLS:         t.shadowTLSConfig,
				Restls:            t.restlsConfig,
				JLS:               t.jlsConfig,
			})
			if err != nil {
				return nil, err
			}
		} else if !t.noTLS() {
			wsOpts.TLS = true
			wsOpts.TLSConfig, err = ca.GetTLSConfig(ca.Option{
				TLSConfig: &tls.Config{
					NextProtos:         alpn,
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: t.option.SkipCertVerify,
					ServerName:         t.option.SNI,
				},
				Fingerprint:    t.option.Fingerprint,
				NameCertVerify: t.option.NameCertVerify,
				Certificate:    t.option.Certificate,
				PrivateKey:     t.option.PrivateKey,
			})
			if err != nil {
				return nil, err
			}
		}

		c, err = vmess.StreamWebsocketConn(ctx, c, wsOpts)
	case "grpc":
		break // already handle in dialContext
	case "xhttp":
		break // already handle in dialContext
	case "hysteria":
		break // already handle in dialContext
	default:
		if t.noTLS() {
			break
		}
		// default tcp network
		// handle TLS
		alpn := trojan.DefaultALPN
		if t.option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			alpn = t.option.ALPN
		}
		c, err = vmess.StreamTLSConn(ctx, c, &vmess.TLSConfig{
			Host:              t.option.SNI,
			SkipCertVerify:    t.option.SkipCertVerify,
			NameCertVerify:    t.option.NameCertVerify,
			FingerPrint:       t.option.Fingerprint,
			Certificate:       t.option.Certificate,
			PrivateKey:        t.option.PrivateKey,
			ClientFingerprint: t.option.ClientFingerprint,
			NextProtos:        alpn,
			ECH:               t.echConfig,
			ShadowTLS:         t.shadowTLSConfig,
			Restls:            t.restlsConfig,
			JLS:               t.jlsConfig,
			Reality:           t.realityConfig,
		})
	}
	if err != nil {
		return nil, err
	}

	return t.streamConnContext(ctx, c, metadata)
}

func (t *Trojan) noTLS() bool {
	return t.option.TLS != nil && !*t.option.TLS
}

func (t *Trojan) streamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if t.ssCipher != nil {
		c = t.ssCipher.StreamConn(c)
	}

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	command := trojan.CommandTCP
	if metadata.NetWork == C.UDP {
		command = trojan.CommandUDP
	}
	err = trojan.WriteHeader(c, t.hexPassword, command, serializesSocksAddr(metadata))
	return c, err
}

func (t *Trojan) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	command := trojan.CommandTCP
	if metadata.NetWork == C.UDP {
		command = trojan.CommandUDP
	}
	err = trojan.WriteHeader(c, t.hexPassword, command, serializesSocksAddr(metadata))
	return err
}

func (t *Trojan) dialContext(ctx context.Context) (c net.Conn, err error) {
	switch t.option.Network {
	case "grpc": // gun transport
		return t.gunClient.Dial()
	case "xhttp":
		return t.xhttpClient.Dial(ctx)
	case "mkcp", "kcp":
		return dialMKCP(ctx, t.dialer, t.addr, t.option.MKCPOpts)
	case "hysteria":
		return t.hysteriaClient.Dial(ctx)
	default:
	}
	return t.dialer.DialContext(ctx, "tcp", t.addr)
}

// DialContext implements C.ProxyAdapter
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	return NewConn(c, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Trojan) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err := t.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	pc := trojan.NewPacketConn(c)
	return NewPacketConn(pc, t), err
}

// SupportUOT implements C.ProxyAdapter
func (t *Trojan) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *Trojan) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *Trojan) Close() error {
	var errs []error
	if t.gunClient != nil {
		if err := t.gunClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.hysteriaClient != nil {
		_ = t.hysteriaClient.Close()
	}
	if t.xhttpClient != nil {
		if err := t.xhttpClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func NewTrojan(option TrojanOption) (*Trojan, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	sni := option.SNI // as configured: the transports with legs of their own fill it in per leg
	if option.SNI == "" {
		option.SNI = option.Server
	}

	t := &Trojan{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Trojan,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:      &option,
		hexPassword: trojan.Key(option.Password),
	}
	t.dialer = option.NewDialer(t.DialOptions())

	var err error
	t.echConfig, err = option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	t.shadowTLSConfig, err = option.ShadowTLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	t.restlsConfig, err = option.RestlsOpts.Parse(option.SNI, option.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	t.jlsConfig, err = option.JLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	t.realityConfig, err = option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	securityModes := make([]string, 0, 4)
	if t.shadowTLSConfig != nil {
		securityModes = append(securityModes, "ShadowTLS")
	}
	if t.restlsConfig != nil {
		securityModes = append(securityModes, "Restls")
	}
	if t.jlsConfig != nil {
		securityModes = append(securityModes, "JLS")
	}
	if t.realityConfig != nil {
		securityModes = append(securityModes, "REALITY")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	if t.noTLS() && len(securityModes) == 1 { // never the password in the clear by an oversight
		return nil, fmt.Errorf("%s requires TLS", securityModes[0])
	}

	if option.SSOpts.Enabled {
		if option.SSOpts.Password == "" {
			return nil, errors.New("empty password")
		}
		if option.SSOpts.Method == "" {
			option.SSOpts.Method = "AES-128-GCM"
		}
		ciph, err := core.PickCipher(option.SSOpts.Method, nil, option.SSOpts.Password)
		if err != nil {
			return nil, err
		}
		t.ssCipher = ciph
	}

	if option.Network == "grpc" {
		dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := t.dialer.DialContext(ctx, "tcp", t.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", t.addr, err.Error())
			}
			return c, nil
		}

		tlsConfig := &vmess.TLSConfig{
			Host:              option.SNI,
			SkipCertVerify:    option.SkipCertVerify,
			NameCertVerify:    option.NameCertVerify,
			FingerPrint:       option.Fingerprint,
			Certificate:       option.Certificate,
			PrivateKey:        option.PrivateKey,
			ClientFingerprint: option.ClientFingerprint,
			NextProtos:        []string{"h2"},
			ECH:               t.echConfig,
			ShadowTLS:         t.shadowTLSConfig,
			Restls:            t.restlsConfig,
			JLS:               t.jlsConfig,
			Reality:           t.realityConfig,
		}

		if t.noTLS() {
			tlsConfig = nil
		}

		gunConfig := &gun.Config{
			ServiceName:  option.GrpcOpts.GrpcServiceName,
			UserAgent:    option.GrpcOpts.GrpcUserAgent,
			Host:         option.SNI,
			PingInterval: option.GrpcOpts.PingInterval,
			Authority:    option.GrpcOpts.Authority,
		}

		t.gunClient = gun.NewClient(
			func() *gun.Transport {
				return gun.NewTransport(dialFn, tlsConfig, gunConfig)
			},
			option.GrpcOpts.MaxConnections,
			option.GrpcOpts.MinStreams,
			option.GrpcOpts.MaxStreams,
		)
	}
	if option.Network == "xhttp" {
		t.xhttpClient, err = newXHTTPClient(xhttpTransport{
			DialOptions: t.option.BasicOption.quicDialOptions(t.Base), Dialer: t.dialer, Server: option.Server, Port: option.Port,
			TLS: !t.noTLS(), ALPN: option.ALPN, Options: &t.option.XHTTPOpts,
			TLSConfig: vmess.TLSConfig{
				Host:              sni,
				SkipCertVerify:    option.SkipCertVerify,
				NameCertVerify:    option.NameCertVerify,
				FingerPrint:       option.Fingerprint,
				Certificate:       option.Certificate,
				PrivateKey:        option.PrivateKey,
				ClientFingerprint: option.ClientFingerprint,
				ECH:               t.echConfig,
				ShadowTLS:         t.shadowTLSConfig,
				Restls:            t.restlsConfig,
				JLS:               t.jlsConfig,
				Reality:           t.realityConfig,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	if option.Network == "hysteria" {
		t.hysteriaClient, err = newHysteriaTransport(hysteriaTransport{
			Base: t.Base, Basic: &t.option.BasicOption, Dialer: t.dialer, Server: option.Server, Port: option.Port,
			TLS: !t.noTLS(), ALPN: option.ALPN, Options: &t.option.HysteriaOpts,
			TLSConfig: vmess.TLSConfig{
				Host:           sni,
				SkipCertVerify: option.SkipCertVerify,
				NameCertVerify: option.NameCertVerify,
				FingerPrint:    option.Fingerprint,
				Certificate:    option.Certificate,
				PrivateKey:     option.PrivateKey,
				ECH:            t.echConfig,
				ShadowTLS:      t.shadowTLSConfig,
				Restls:         t.restlsConfig,
				JLS:            t.jlsConfig,
				Reality:        t.realityConfig,
			},
		})
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}
