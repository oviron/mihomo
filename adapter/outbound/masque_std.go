package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/masque"
	"github.com/metacubex/mihomo/transport/vmess"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// The standard mode of the MASQUE outbound: a CONNECT-IP tunnel (RFC 9484) to
// a server that authenticates with HTTP Basic and assigns the tunnel
// addresses itself, which is what an Xray-core MASQUE inbound does. It is
// used when neither "private-key" nor "public-key" of WARP is set.

// masqueStandard is the state of the standard mode.
type masqueStandard struct {
	header http.Header
	mtu    uint32
	stack  *masqueStack
	dialH2 func(ctx context.Context) (net.Conn, error) // nil for HTTP/3

	// for HTTP/3: the ECH config list is looked up for every connection
	ech       *ech.Config
	tlsConfig *tls.Config
}

// masqueConnectTimeout bounds the setup of a tunnel when the caller does not.
const masqueConnectTimeout = 15 * time.Second

// masquePathReplacer turns the RFC 9484 URI template into the unscoped
// request Xray-core sends for it.
var masquePathReplacer = strings.NewReplacer(
	"{target}", "*", "{ipproto}", "*",
	"{?target,ipproto}", "?target=*&ipproto=*", "{?ipproto,target}", "?ipproto=*&target=*",
	"{&target,ipproto}", "&target=*&ipproto=*", "{&ipproto,target}", "&ipproto=*&target=*",
)

func (w *Masque) initStandard(option MasqueOption) error {
	switch option.Network {
	case "", "h3", "h2":
	default:
		return fmt.Errorf("masque: network %s needs a WARP private-key", option.Network)
	}
	if option.Ip != "" || option.Ipv6 != "" {
		return errors.New("masque: without a WARP private-key the server assigns the addresses, remove ip and ipv6")
	}

	sni := option.SNI
	if sni == "" {
		sni = option.Server
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: option.SkipCertVerify,
			NextProtos:         []string{"h3"},
		},
		Fingerprint: option.Fingerprint,
	})
	if err != nil {
		return err
	}
	w.tlsConfig = tlsConfig
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return err
	}

	w.uri = option.URI
	if w.uri == "" {
		host := option.Host
		if host == "" {
			host = sni
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
				host = "[" + host + "]"
			}
			if option.Port != 443 {
				host = net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(option.Port))
			}
		}
		path := option.Path
		if path == "" {
			path = masque.DefaultPath
		}
		w.uri = "https://" + host + masquePathReplacer.Replace(path)
	}

	header := http.Header{}
	for k, v := range option.Headers {
		header.Set(k, v)
	}
	if option.User != "" || option.Pass != "" {
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(option.User+":"+option.Pass)))
	}
	if header.Get("User-Agent") == "" {
		convert.SetUserAgent(header)
	}

	var dialH2 func(ctx context.Context) (net.Conn, error)
	if option.Network == "h2" {
		// HTTP/2 over TCP and TLS, for where UDP does not get through.
		dialH2 = func(ctx context.Context) (net.Conn, error) {
			c, err := w.dialer.DialContext(ctx, "tcp", w.addr)
			if err != nil {
				return nil, err
			}
			tlsConn, err := vmess.StreamTLSConn(ctx, c, &vmess.TLSConfig{
				Host:              sni,
				SkipCertVerify:    option.SkipCertVerify,
				FingerPrint:       option.Fingerprint,
				ClientFingerprint: option.ClientFingerprint,
				NextProtos:        []string{"h2"},
				ECH:               echConfig,
			})
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			// a fingerprint without ALPN, or a server without HTTP/2
			if p := tlsC.GetTLSConnectionState(tlsConn).NegotiatedProtocol; p != "h2" {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("masque: the server negotiated %q instead of h2", p)
			}
			return tlsConn, nil
		}
	}

	w.quicConfig = &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1350, // room for the 1280 byte packets every IP tunnel has to carry
		KeepAlivePeriod:   30 * time.Second,
	}

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1280
	}
	w.standard = &masqueStandard{header: header, mtu: uint32(mtu), stack: &masqueStack{}, dialH2: dialH2, ech: echConfig, tlsConfig: tlsConfig}
	w.tunDevice = w.standard.stack
	w.option = option

	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return err
		}
		for i := range nss {
			nss[i].ProxyAdapter = w
		}
		w.resolver = dns.NewResolver(dns.Config{Main: nss})
	}
	return nil
}

// startStandard connects the tunnel and builds the IP stack on the addresses
// the server assigned. Every connection gets addresses of its own, so the
// stack lives as long as the connection.
func (w *Masque) startStandard(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, masqueConnectTimeout)
	defer cancel()

	var closer io.Closer
	var ipConn *connectip.Conn
	var quicConn *quic.Conn
	var pc net.PacketConn
	var err error
	if w.standard.dialH2 != nil {
		var conn net.Conn
		if conn, err = w.standard.dialH2(ctx); err != nil {
			return err
		}
		closer, ipConn, err = masque.ConnectTunnelStandardH2(ctx, conn, w.uri, w.standard.header)
		if err != nil {
			_ = conn.Close()
			return err
		}
	} else {
		if w.standard.ech != nil {
			// dialQuic takes the config from the outbound; the run lock is held
			tlsConfig := w.standard.tlsConfig.Clone()
			if err = w.standard.ech.ClientHandle(ctx, tlsConfig); err != nil {
				return err
			}
			w.tlsConfig = tlsConfig
		}
		pc, quicConn, err = w.dialQuic(ctx)
		if err != nil {
			return err
		}
		closer, ipConn, err = masque.ConnectTunnelStandard(ctx, quicConn, w.uri, w.standard.header)
		if err != nil {
			_ = pc.Close()
			return err
		}
	}
	closeTunnel := func() {
		_ = ipConn.Close()
		_ = closer.Close()
		if quicConn != nil {
			_ = quicConn.CloseWithError(0, "") // tells the server, which then frees the addresses
			_ = pc.Close()
		}
	}

	assigned, err := ipConn.LocalPrefixes(ctx)
	if err != nil {
		closeTunnel()
		return fmt.Errorf("masque: no address assigned: %w", err)
	}
	var local []netip.Prefix
	var has4, has6 bool
	for _, prefix := range assigned {
		addr := prefix.Addr().Unmap()
		if prefix.Bits() != prefix.Addr().BitLen() { // a network: take its first host
			addr = prefix.Masked().Addr().Next()
		}
		if addr.Is4() && !has4 {
			has4 = true
		} else if addr.Is6() && !has6 {
			has6 = true
		} else {
			continue
		}
		local = append(local, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(local) == 0 {
		closeTunnel()
		return errors.New("masque: no address assigned")
	}

	stack, err := newIPStack(w.option.IPStack, local, w.standard.mtu)
	if err == nil {
		err = stack.Start()
	}
	if err != nil {
		closeTunnel()
		return fmt.Errorf("create device: %w", err)
	}
	if w.runCtx.Err() != nil { // closed meanwhile
		closeTunnel()
		_ = stack.Close()
		return w.runCtx.Err()
	}
	w.standard.stack.set(stack)
	log.Infoln("[Masque](%s) tunnel addresses %v", w.name, local)
	w.running.Store(true)

	runCtx, runCancel := context.WithCancel(w.runCtx)
	contextutils.AfterFunc(runCtx, func() {
		w.running.Store(false)
		closeTunnel()
		w.standard.stack.drop(stack)
	})

	// The server may assign other addresses later. The stack is bound to the
	// ones it has, so the tunnel is set up anew.
	go func() {
		for {
			again, err := ipConn.LocalPrefixes(runCtx)
			if err != nil {
				return
			}
			if !samePrefixes(again, assigned) {
				log.Warnln("[Masque](%s) tunnel addresses changed, reconnecting", w.name)
				runCancel()
				return
			}
		}
	}()

	go func() {
		defer runCancel()
		buf := pool.Get(pool.UDPBufferSize)
		defer pool.Put(buf)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for runCtx.Err() == nil {
			if _, err := stack.Read(bufs, sizes, 0); err != nil {
				return
			}
			icmp, err := ipConn.WritePacket(buf[:sizes[0]])
			if err != nil {
				if runCtx.Err() == nil {
					log.Warnln("[Masque](%s) tunnel closed while writing: %v", w.name, err)
				}
				return
			}
			if len(icmp) > 0 {
				_, _ = stack.Write([][]byte{icmp}, 0)
			}
		}
	}()

	go func() {
		defer runCancel()
		for runCtx.Err() == nil {
			buf, err := ipConn.ReadPacket()
			if err != nil {
				if runCtx.Err() == nil {
					log.Warnln("[Masque](%s) tunnel closed while reading: %v", w.name, err)
				}
				return
			}
			if _, err := stack.Write([][]byte{buf}, 0); err != nil {
				return
			}
		}
	}()
	return nil
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// masqueStack is the IP stack of the current tunnel connection. The stack is
// replaced on every connection, and is absent before the first one.
type masqueStack struct {
	mu      sync.RWMutex
	current ipStack
}

var errMasqueNoTunnel = errors.New("masque: tunnel is not connected")

func (s *masqueStack) set(stack ipStack) {
	s.mu.Lock()
	old := s.current
	s.current = stack
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// drop closes stack and forgets it if it is still the current one.
func (s *masqueStack) drop(stack ipStack) {
	s.mu.Lock()
	if s.current == stack {
		s.current = nil
	}
	s.mu.Unlock()
	_ = stack.Close()
}

func (s *masqueStack) get() (ipStack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, errMasqueNoTunnel
	}
	return s.current, nil
}

func (s *masqueStack) Start() error { return nil }

func (s *masqueStack) Close() error {
	s.set(nil)
	return nil
}

func (s *masqueStack) DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.DialTCP(ctx, network, source, destination)
}

func (s *masqueStack) DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.DialUDP(ctx, network, source, destination)
}

func (s *masqueStack) DialIP(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.DialIP(ctx, network, source, destination)
}

func (s *masqueStack) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.ListenTCP(ctx, network, local)
}

func (s *masqueStack) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.ListenUDP(ctx, network, local)
}

func (s *masqueStack) ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error) {
	stack, err := s.get()
	if err != nil {
		return nil, err
	}
	return stack.ListenIP(ctx, network, local)
}

func (s *masqueStack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	stack, err := s.get()
	if err != nil {
		return 0, err
	}
	return stack.Read(buffers, sizes, offset)
}

func (s *masqueStack) Write(buffers [][]byte, offset int) (int, error) {
	stack, err := s.get()
	if err != nil {
		return 0, err
	}
	return stack.Write(buffers, offset)
}

func (s *masqueStack) MTU() (int, error) {
	stack, err := s.get()
	if err != nil {
		return 0, err
	}
	return stack.MTU()
}

func (s *masqueStack) Name() (string, error) {
	stack, err := s.get()
	if err != nil {
		return "", err
	}
	return stack.Name()
}

func (s *masqueStack) BatchSize() int {
	stack, err := s.get()
	if err != nil {
		return 1
	}
	return stack.BatchSize()
}

var _ ipStack = (*masqueStack)(nil)
