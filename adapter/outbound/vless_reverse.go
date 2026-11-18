package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/contextutils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/muxcool"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/vless"
)

// VlessReverseOption is the "reverse" option of a vless proxy, named after
// the "reverse" object of an Xray-core VLESS outbound.
type VlessReverseOption struct {
	// Tag is the inbound name the connections from the server get: rules
	// match them with IN-NAME.
	Tag string `proxy:"tag"`
}

const (
	// Xray-core checks its reverse connections this often, and opens another
	// one when a connection carries more than this many sessions.
	vlessReverseInterval    = 2 * time.Second
	vlessReverseMaxSessions = 16

	// The server sends a heartbeat every ten seconds. A connection without
	// one for this long is dead, whatever its transport says.
	vlessReverseSilence = 60 * time.Second

	// vlessReverseMaxWorkers bounds the connections kept at once, draining
	// ones included: the server decides how long those live.
	vlessReverseMaxWorkers = 8

	// vlessReverseControl is the destination of the session the server keeps
	// for its heartbeats.
	vlessReverseControl = "reverse"
)

// vlessReverse is the bridge of a reverse proxy over VLESS: it keeps
// connections to the server open and serves what the server sends through
// them, the way Xray-core does for an outbound with "reverse" (the server is
// the portal). The connections it gets are handled like those of a listener.
type vlessReverse struct {
	proxy  *Vless
	tag    string
	tunnel C.Tunnel
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	workers []*vlessReverseWorker
}

func newVlessReverse(proxy *Vless, option VlessReverseOption, tunnel C.Tunnel) (*vlessReverse, error) {
	if option.Tag == "" {
		return nil, errors.New("vless reverse: tag can't be empty")
	}
	if proxy.option.ProviderName != "" {
		// It lets a server reach into this network; a subscription must not turn it on.
		return nil, errors.New("vless reverse: not allowed for a proxy of a provider")
	}
	if tunnel == nil {
		return nil, errors.New("vless reverse: no tunnel to hand the connections to")
	}
	r := &vlessReverse{proxy: proxy, tag: option.Tag, tunnel: tunnel}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	go r.monitor()
	return r, nil
}

func (r *vlessReverse) close() {
	r.cancel()
	r.mu.Lock()
	workers := r.workers
	r.workers = nil
	r.mu.Unlock()
	for _, w := range workers {
		_ = w.carrier.Close()
	}
}

// monitor keeps enough connections to the server. Like Xray-core it waits a
// moment first, so that a configuration that is still being loaded and gets
// rejected does not connect.
func (r *vlessReverse) monitor() {
	ticker := time.NewTicker(vlessReverseInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		r.check()
	}
}

func (r *vlessReverse) check() {
	r.mu.Lock()
	alive := r.workers[:0]
	active, sessions := 0, 0
	for _, w := range r.workers {
		if w.carrier.Closed() {
			continue
		}
		if time.Since(time.Unix(0, w.heard.Load())) > vlessReverseSilence {
			_ = w.carrier.Close()
			continue
		}
		alive = append(alive, w)
		if !w.draining.Load() { // a draining connection serves its sessions to the end
			active++
			sessions += w.carrier.Sessions()
		}
	}
	for i := len(alive); i < len(r.workers); i++ {
		r.workers[i] = nil
	}
	r.workers = alive
	enough := active > 0 && sessions/active <= vlessReverseMaxSessions
	full := len(alive) >= vlessReverseMaxWorkers
	r.mu.Unlock()
	if enough || full {
		return
	}

	w, err := r.connect()
	if err != nil {
		if r.ctx.Err() == nil {
			log.Warnln("[Vless](%s) reverse: %v", r.proxy.Name(), err)
		}
		return
	}
	r.mu.Lock()
	if r.ctx.Err() != nil {
		r.mu.Unlock()
		_ = w.carrier.Close()
		return
	}
	r.workers = append(r.workers, w)
	r.mu.Unlock()
}

// connect opens a connection with the reverse command and starts Mux.Cool on
// it in the accepting role.
func (r *vlessReverse) connect() (*vlessReverseWorker, error) {
	ctx, cancel := context.WithTimeout(r.ctx, C.DefaultTCPTimeout)
	defer cancel()
	// C.INNER tells this dial from a connection of a user to the same name.
	conn, err := r.proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Type: C.INNER, Host: vless.ReverseDestination})
	if err != nil {
		return nil, err
	}
	// The request goes out with the first write, and the server speaks first.
	stop := contextutils.AfterFunc(ctx, func() { _ = conn.Close() })
	_, err = conn.Write(nil)
	if !stop() && err == nil {
		err = context.Cause(ctx)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	w := &vlessReverseWorker{reverse: r, started: make(chan struct{})}
	w.heard.Store(time.Now().UnixNano())
	w.carrier = muxcool.NewServerCarrier(conn, w, true)
	close(w.started)
	return w, nil
}

// vlessReverseWorker is one connection to the server.
type vlessReverseWorker struct {
	reverse  *vlessReverse
	carrier  *muxcool.Carrier
	started  chan struct{} // closed once carrier is set; sessions may arrive before
	draining atomic.Bool   // the server will open no more sessions here
	heard    atomic.Int64  // when the server was last heard, in unix nanoseconds
}

// vlessReverseSource numbers the sessions of all bridges.
var vlessReverseSource atomic.Uint32

// source makes up the source address of a session. The server names the real
// one, but nothing here may trust it: an address of this network would match
// rules meant for local devices and processes. 192.0.2.0/24 is reserved for
// documentation and belongs to nobody; the port keeps the sessions apart.
func (w *vlessReverseWorker) source() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: int(vlessReverseSource.Add(1)%65535) + 1}
}

func (w *vlessReverseWorker) additions(source net.Addr) []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(w.reverse.tag),
		inbound.WithSrcAddr(source),
		inbound.WithInAddr(source),
	}
}

// NewStream implements muxcool.Handler
func (w *vlessReverseWorker) NewStream(conn net.Conn, meta muxcool.Metadata) {
	<-w.started
	target := socks5.ParseAddr(meta.Target.Addr.String())
	if target == nil {
		_ = conn.Close()
		return
	}
	w.reverse.tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.VLESS, w.additions(w.source())...))
}

// NewPacket implements muxcool.Handler
func (w *vlessReverseWorker) NewPacket(conn net.PacketConn, meta muxcool.Metadata) {
	<-w.started
	defer conn.Close()
	if meta.Target.Addr.Fqdn == vlessReverseControl {
		w.control(conn)
		return
	}

	source := w.source()
	additions := w.additions(source)
	buf := make([]byte, muxcool.MaxPayload)
	for {
		n, to, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		target := socks5.ParseAddr(to.String())
		if target == nil {
			continue
		}
		packet := &vlessReversePacket{conn: conn, data: append([]byte(nil), buf[:n]...), source: source}
		w.reverse.tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.VLESS, additions...))
	}
}

// control reads the heartbeats of the server: protobuf messages with the
// state of the connection, active or draining.
func (w *vlessReverseWorker) control(conn net.PacketConn) {
	buf := make([]byte, muxcool.MaxPayload)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		draining, ok := parseVlessReverseControl(buf[:n])
		if !ok { // not something to go on with, as in Xray-core
			_ = w.carrier.Close()
			return
		}
		w.heard.Store(time.Now().UnixNano())
		w.draining.Store(draining)
	}
}

// parseVlessReverseControl reads the "state" field of Xray-core's
// app/reverse Control message: 0 is active, 1 is draining.
func parseVlessReverseControl(b []byte) (draining bool, ok bool) {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return false, false
		}
		b = b[n:]
		switch tag & 7 {
		case 0: // varint
			value, n := binary.Uvarint(b)
			if n <= 0 {
				return false, false
			}
			b = b[n:]
			if tag>>3 == 1 {
				draining = value == 1
			}
		case 2: // bytes
			length, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < length {
				return false, false
			}
			b = b[n+int(length):]
		default:
			return false, false
		}
	}
	return draining, true
}

// vlessReversePacket is a UDP packet the server sent for a target behind the
// bridge.
type vlessReversePacket struct {
	conn   net.PacketConn
	data   []byte
	source net.Addr
}

func (p *vlessReversePacket) Data() []byte { return p.data }

func (p *vlessReversePacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return p.conn.WriteTo(b, addr)
}

func (p *vlessReversePacket) Drop() { p.data = nil }

func (p *vlessReversePacket) LocalAddr() net.Addr { return p.source }

var _ C.UDPPacket = (*vlessReversePacket)(nil)
