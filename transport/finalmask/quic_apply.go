package finalmask

import (
	"context"
	"fmt"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing-quic/hysteria2"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/tls"
)

// QuicParamsOf returns the quic-params of a dialer made by NewDialer, nil when
// it has none. The methods of a nil *QuicParams do nothing.
func QuicParamsOf(dialer C.Dialer) *QuicParams {
	if config := ConfigOf(dialer); config != nil {
		return config.Quic
	}
	return nil
}

// ApplyCongestion sets the congestion control of a plain QUIC connection, as
// Xray-core does for XHTTP over HTTP/3: BBR unless reno is asked for,
// force-brutal sends at brutal-up. cwnd is the initial window in packets for
// BBR, 0 for the default.
func (p *QuicParams) ApplyCongestion(conn *quic.Conn, cwnd int) {
	if p == nil {
		return
	}
	switch p.Congestion {
	case CongestionReno:
		common.SetCongestionController(conn, "new_reno", cwnd, "")
	case CongestionForceBrutal:
		conn.SetCongestionControl(hyCC.NewBrutalSender(p.BrutalUp, false, log.SingLogger))
	default: // brutal, which only Hysteria negotiates, is rejected by CheckHTTP3
		common.SetCongestionController(conn, "bbr", cwnd, p.BBRProfile)
	}
}

// ApplyHysteria2 carries the parameters into the options of a Hysteria 2
// client. Hysteria negotiates the rate: the client tells the server what it
// can receive (brutal-down) and sends at the lower of its brutal-up and what
// the server can receive.
//
//	""/brutal     Brutal at the negotiated rate when brutal-up is set, BBR otherwise
//	bbr           BBR
//	reno          New Reno
//	force-brutal  Brutal at brutal-up whatever the server says
//
// One difference from Xray-core remains: when the server names no rate of its
// own, the client here sends at brutal-up where Xray-core falls back to BBR.
func (p *QuicParams) ApplyHysteria2(options *hysteria2.ClientOptions, cwnd int) {
	if p == nil {
		return
	}
	if p.BrutalDownSet {
		options.ReceiveBPS = p.BrutalDown
	}
	bbr := options.SetBBRCongestion
	if p.BBRProfile != "" {
		bbr = func(conn *quic.Conn) {
			common.SetCongestionController(conn, "bbr", cwnd, p.BBRProfile)
		}
	}
	switch p.Congestion {
	case CongestionDefault, CongestionBrutal:
		if p.BrutalUpSet {
			options.SendBPS = p.BrutalUp
		}
		options.SetBBRCongestion = bbr
	case CongestionBBR:
		options.SendBPS = 0
		options.SetBBRCongestion = bbr
	case CongestionReno:
		options.SendBPS = 0
		options.SetBBRCongestion = func(conn *quic.Conn) {
			common.SetCongestionController(conn, "new_reno", cwnd, "")
		}
	case CongestionForceBrutal:
		up := p.BrutalUp
		options.SendBPS = 0
		options.SetBBRCongestion = func(conn *quic.Conn) {
			conn.SetCongestionControl(hyCC.NewBrutalSender(up, false, log.SingLogger))
		}
	}
	if p.DisablePathMTUDiscovery {
		// The client sets this field of the config itself, by the OS, so it
		// has to be set again where the connection is dialed.
		dial := options.QuicDialer
		options.QuicDialer = qtls.QuicDialerFunc(func(ctx context.Context, addr string, dialer qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
			cfg = cfg.Clone() // the client's config is shared by its dials
			cfg.DisablePathMTUDiscovery = true
			return dial.DialContext(ctx, addr, dialer, tlsCfg, cfg, early)
		})
	}
}

// CheckHysteria2 rejects the Hysteria 2 options that can't be used with the
// UDP masks of the dialer: its own port hopping next to a mask that picks the
// server address, and realm, whose STUN and hole punching packets share the
// socket with QUIC and would be masked too.
func CheckHysteria2(dialer C.Dialer, ports, realm bool) error {
	config := ConfigOf(dialer)
	if !config.HasUDP() {
		return nil
	}
	if realm {
		return fmt.Errorf("finalmask: udp masks can't be used with realm-opts")
	}
	if ports && config.carrier != nil {
		return fmt.Errorf("finalmask: the last udp mask picks the server address itself and can't be used with ports")
	}
	return nil
}
