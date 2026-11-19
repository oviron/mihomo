package finalmask

import (
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
)

// HysteriaReceiveBPS is the rate the client of the hysteria transport tells
// the server it may send at: brutal-down, zero when it is not set.
func (p *QuicParams) HysteriaReceiveBPS() uint64 {
	if p == nil || !p.BrutalDownSet {
		return 0
	}
	return p.BrutalDown
}

// ApplyHysteriaStream sets the congestion control of a connection of the
// hysteria transport once the server has accepted the auth and told the rate
// it can receive at, as Xray-core does:
//
//	""/brutal     Brutal at the lower of brutal-up and the server's rate when
//	              both are known, BBR otherwise
//	bbr           BBR
//	reno          New Reno
//	force-brutal  Brutal at brutal-up whatever the server says
//
// A nil receiver gives BBR, which is what the transport uses on its own.
func (p *QuicParams) ApplyHysteriaStream(conn *quic.Conn, serverReceiveBPS uint64) {
	if p == nil {
		common.SetCongestionController(conn, "bbr", 0, "")
		return
	}
	switch p.Congestion {
	case CongestionReno:
		common.SetCongestionController(conn, "new_reno", 0, "")
	case CongestionForceBrutal:
		conn.SetCongestionControl(hyCC.NewBrutalSender(p.BrutalUp, false, log.SingLogger))
	case CongestionDefault, CongestionBrutal:
		if p.BrutalUpSet && p.BrutalUp > 0 && serverReceiveBPS > 0 {
			rate := p.BrutalUp
			if serverReceiveBPS < rate {
				rate = serverReceiveBPS
			}
			conn.SetCongestionControl(hyCC.NewBrutalSender(rate, false, log.SingLogger))
			return
		}
		common.SetCongestionController(conn, "bbr", 0, p.BBRProfile)
	default:
		common.SetCongestionController(conn, "bbr", 0, p.BBRProfile)
	}
}
