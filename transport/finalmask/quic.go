package finalmask

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/quic-go"
)

// Congestion controls of quic-params.
const (
	CongestionDefault     = ""
	CongestionReno        = "reno"
	CongestionBBR         = "bbr"
	CongestionBrutal      = "brutal"
	CongestionForceBrutal = "force-brutal"
)

// QuicParams is the quic-params section, the quicParams of Xray-core. All of
// it is local tuning of the client's QUIC connection.
//
// Not carried over from Xray-core: debug, disableGSO, disableStatelessReset,
// brutalDisableLossCompensation and disableChromeParrot. They are accepted
// and ignored.
type QuicParams struct {
	Congestion string
	BBRProfile string
	// BrutalUp and BrutalDown are bytes per second.
	BrutalUp   uint64
	BrutalDown uint64

	InitStreamReceiveWindow     uint64
	MaxStreamReceiveWindow      uint64
	InitConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow  uint64
	MaxIdleTimeout              time.Duration
	KeepAlivePeriod             time.Duration
	DisablePathMTUDiscovery     bool
	MaxIncomingStreams          int64
}

type rawQuicParams struct {
	Congestion                  string `mask:"congestion,omitempty"`
	BBRProfile                  string `mask:"bbr-profile,omitempty"`
	BrutalUp                    string `mask:"brutal-up,omitempty"`
	BrutalDown                  string `mask:"brutal-down,omitempty"`
	InitStreamReceiveWindow     int64  `mask:"init-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow      int64  `mask:"max-stream-receive-window,omitempty"`
	InitConnectionReceiveWindow int64  `mask:"init-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow  int64  `mask:"max-connection-receive-window,omitempty"`
	MaxIdleTimeout              int64  `mask:"max-idle-timeout,omitempty"`
	KeepAlivePeriod             int64  `mask:"keep-alive-period,omitempty"`
	DisablePathMTUDiscovery     bool   `mask:"disable-path-mtu-discovery,omitempty"`
	MaxIncomingStreams          int64  `mask:"max-incoming-streams,omitempty"`
}

func parseQuicParams(raw map[string]any) (*QuicParams, error) {
	var r rawQuicParams
	if err := mask.Decode(raw, &r); err != nil {
		return nil, err
	}
	profile := strings.ToLower(r.BBRProfile)
	switch profile {
	case "", "conservative", "standard", "aggressive":
	default:
		return nil, fmt.Errorf("unknown bbr-profile %q", r.BBRProfile)
	}
	up, err := parseBandwidth(r.BrutalUp)
	if err != nil {
		return nil, fmt.Errorf("brutal-up: %w", err)
	}
	down, err := parseBandwidth(r.BrutalDown)
	if err != nil {
		return nil, fmt.Errorf("brutal-down: %w", err)
	}
	if up > 0 && up < 65536 {
		return nil, fmt.Errorf("brutal-up must be at least 65536 bytes per second")
	}
	if down > 0 && down < 65536 {
		return nil, fmt.Errorf("brutal-down must be at least 65536 bytes per second")
	}
	congestion := strings.ToLower(r.Congestion)
	switch congestion {
	case CongestionDefault, CongestionBrutal, CongestionReno, CongestionBBR:
	case CongestionForceBrutal:
		if up == 0 {
			return nil, fmt.Errorf("force-brutal requires brutal-up")
		}
	default:
		return nil, fmt.Errorf("unknown congestion %q, valid values: reno, bbr, brutal, force-brutal", r.Congestion)
	}
	for name, window := range map[string]int64{
		"init-stream-receive-window":     r.InitStreamReceiveWindow,
		"max-stream-receive-window":      r.MaxStreamReceiveWindow,
		"init-connection-receive-window": r.InitConnectionReceiveWindow,
		"max-connection-receive-window":  r.MaxConnectionReceiveWindow,
	} {
		if window < 0 || (window > 0 && window < 16384) {
			return nil, fmt.Errorf("%s must be at least 16384", name)
		}
	}
	if r.MaxIdleTimeout != 0 && (r.MaxIdleTimeout < 4 || r.MaxIdleTimeout > 120) {
		return nil, fmt.Errorf("max-idle-timeout must be between 4 and 120")
	}
	if r.KeepAlivePeriod != 0 && (r.KeepAlivePeriod < 2 || r.KeepAlivePeriod > 60) {
		return nil, fmt.Errorf("keep-alive-period must be between 2 and 60")
	}
	if r.MaxIncomingStreams != 0 && r.MaxIncomingStreams < 8 {
		return nil, fmt.Errorf("max-incoming-streams must be at least 8")
	}
	return &QuicParams{
		Congestion:                  congestion,
		BBRProfile:                  profile,
		BrutalUp:                    up,
		BrutalDown:                  down,
		InitStreamReceiveWindow:     uint64(r.InitStreamReceiveWindow),
		MaxStreamReceiveWindow:      uint64(r.MaxStreamReceiveWindow),
		InitConnectionReceiveWindow: uint64(r.InitConnectionReceiveWindow),
		MaxConnectionReceiveWindow:  uint64(r.MaxConnectionReceiveWindow),
		MaxIdleTimeout:              time.Duration(r.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:             time.Duration(r.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:     r.DisablePathMTUDiscovery,
		MaxIncomingStreams:          r.MaxIncomingStreams,
	}, nil
}

// parseBandwidth reads a rate the way Xray-core does: a number with an
// optional unit (b, k, m, g, t with an optional b or bps), in bits per second
// with binary multiples, returned as bytes per second.
func parseBandwidth(value string) (uint64, error) {
	s := strings.TrimSpace(strings.ToLower(value))
	if s == "" {
		return 0, nil
	}
	idx := len(s)
	for i, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			idx = i
			break
		}
	}
	number, err := strconv.ParseFloat(s[:idx], 64)
	if err != nil {
		return 0, err
	}
	multiplier := uint64(1)
	switch strings.TrimSpace(s[idx:]) {
	case "", "b", "bps":
	case "k", "kb", "kbps":
		multiplier = 1 << 10
	case "m", "mb", "mbps":
		multiplier = 1 << 20
	case "g", "gb", "gbps":
		multiplier = 1 << 30
	case "t", "tb", "tbps":
		multiplier = 1 << 40
	default:
		return 0, fmt.Errorf("unsupported unit %q", strings.TrimSpace(s[idx:]))
	}
	return uint64(number*float64(multiplier)) / 8, nil
}

// ApplyTo copies the parameters that are set into a QUIC config. A nil
// receiver does nothing.
func (p *QuicParams) ApplyTo(config *quic.Config) {
	if p == nil || config == nil {
		return
	}
	if p.InitStreamReceiveWindow > 0 {
		config.InitialStreamReceiveWindow = p.InitStreamReceiveWindow
	}
	if p.MaxStreamReceiveWindow > 0 {
		config.MaxStreamReceiveWindow = p.MaxStreamReceiveWindow
	}
	if p.InitConnectionReceiveWindow > 0 {
		config.InitialConnectionReceiveWindow = p.InitConnectionReceiveWindow
	}
	if p.MaxConnectionReceiveWindow > 0 {
		config.MaxConnectionReceiveWindow = p.MaxConnectionReceiveWindow
	}
	if p.MaxIdleTimeout > 0 {
		config.MaxIdleTimeout = p.MaxIdleTimeout
	}
	if p.KeepAlivePeriod > 0 {
		config.KeepAlivePeriod = p.KeepAlivePeriod
	}
	if p.DisablePathMTUDiscovery {
		config.DisablePathMTUDiscovery = true
	}
	if p.MaxIncomingStreams != 0 {
		config.MaxIncomingStreams = p.MaxIncomingStreams
	}
}
