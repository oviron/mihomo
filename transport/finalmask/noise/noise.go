// Package noise is the "noise" UDP mask of Xray-core's finalmask: before the
// first packet to an address, and again after the flow was idle, it sends
// junk datagrams. The receiver is expected to drop them, so the server needs
// no matching setting.
package noise

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

func init() {
	mask.RegisterUDP("noise", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// Reset is the idle time in seconds after which the noise is sent again,
	// 0 sends it once per address.
	Reset mask.Range `mask:"reset,omitempty"`
	Noise []Item     `mask:"noise,omitempty"`
	// Script is the path of a Lua script that builds the noise.
	Script string `mask:"script,omitempty"`
}

// Item is one junk datagram.
type Item struct {
	// Rand is the size of a random datagram, RandRange the range of its bytes.
	Rand      mask.Range  `mask:"rand,omitempty"`
	RandRange *mask.Range `mask:"rand-range,omitempty"`
	// Type tells how to read Packet: "array" (default), "str", "hex", "base64"
	// or "exp", an expression of <b 0x..>, <r N>, <rc N>, <rd N>, <t>, <c>, <n>.
	Type   string `mask:"type,omitempty"`
	Packet any    `mask:"packet,omitempty"`
	// Delay is the pause in milliseconds after the datagram.
	Delay mask.Range `mask:"delay,omitempty"`
}

type segmentKind int

const (
	segmentBytes segmentKind = iota
	segmentRandom
	segmentRandomASCII
	segmentRandomDigit
	segmentTimestamp
	segmentCounter
	segmentNonce
)

type segment struct {
	kind    segmentKind
	bytes   []byte
	minSize int64
	maxSize int64
}

type item struct {
	segments  []segment
	rand      mask.Range
	randRange mask.Range
	packet    []byte
	delay     mask.Range
}

// Mask is a parsed noise mask.
type Mask struct {
	reset  mask.Range
	items  []item
	script scriptSource
}

// scriptSource builds the noise with a script. It is nil unless the package
// is built with the script engine.
type scriptSource interface {
	packets(addr string) ([]scriptPacket, error)
}

type scriptPacket struct {
	packet []byte
	delay  time.Duration
}

// loadScript is set by the script engine, if there is one.
var loadScript func(path string) (scriptSource, error)

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{reset: options.Reset}
	if options.Reset.From < 0 {
		return nil, fmt.Errorf("negative reset %s", options.Reset)
	}
	if options.Script != "" {
		if len(options.Noise) > 0 {
			return nil, fmt.Errorf(`"script" and "noise" can't be used together`)
		}
		if loadScript == nil {
			return nil, fmt.Errorf(`"script" is not supported by this build`)
		}
		script, err := loadScript(options.Script)
		if err != nil {
			return nil, fmt.Errorf("failed to load the noise script: %w", err)
		}
		m.script = script
		return m, nil
	}
	for i, o := range options.Noise {
		it, err := parseItem(o)
		if err != nil {
			return nil, fmt.Errorf("noise[%d]: %w", i, err)
		}
		m.items = append(m.items, it)
	}
	return m, nil
}

func parseItem(o Item) (item, error) {
	it := item{rand: o.Rand, delay: o.Delay}
	if o.Packet != nil && o.Rand.To > 0 {
		return it, fmt.Errorf(`"packet" and "rand" can't be used together`)
	}
	if o.Rand.From < 0 || o.Rand.To > maxNoiseSize {
		return it, fmt.Errorf("invalid rand %s, want a size of 0 to %d bytes", o.Rand, maxNoiseSize)
	}
	if o.Delay.From < 0 {
		return it, fmt.Errorf("negative delay %s", o.Delay)
	}
	if strings.ToLower(o.Type) == "exp" {
		exp, ok := o.Packet.(string)
		if !ok {
			return it, fmt.Errorf(`"packet" of type exp must be a string`)
		}
		segments, err := parseExp(exp)
		if err != nil {
			return it, err
		}
		it.segments = segments
		return it, nil
	}
	it.randRange = mask.Range{From: 0, To: 255}
	if o.RandRange != nil {
		it.randRange = *o.RandRange
	}
	if it.randRange.From < 0 || it.randRange.To > 255 {
		return it, fmt.Errorf("invalid rand-range")
	}
	packet, err := mask.ParseBytes(o.Packet, o.Type)
	if err != nil {
		return it, err
	}
	it.packet = packet
	return it, nil
}

var expPattern = regexp.MustCompile(`<\s*([a-z]+)(?:\s+([^>]*?))?\s*>`)

func parseExp(exp string) ([]segment, error) {
	var segments []segment
	last := 0
	for _, m := range expPattern.FindAllStringSubmatchIndex(exp, -1) {
		if strings.TrimSpace(exp[last:m[0]]) != "" {
			return nil, fmt.Errorf("invalid noise exp near %q", exp[last:m[0]])
		}
		last = m[1]
		key := exp[m[2]:m[3]]
		arg := ""
		if m[4] >= 0 {
			arg = exp[m[4]:m[5]]
		}
		seg, err := parseSegment(key, arg)
		if err != nil {
			return nil, err
		}
		segments = append(segments, seg)
	}
	if strings.TrimSpace(exp[last:]) != "" {
		return nil, fmt.Errorf("invalid noise exp near %q", exp[last:])
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("empty noise exp %q", exp)
	}
	return segments, nil
}

func parseSegment(key, arg string) (segment, error) {
	sized := func(kind segmentKind) (segment, error) {
		if arg == "" {
			return segment{}, fmt.Errorf("<%s> in noise exp needs a size", key)
		}
		lo, hi, err := mask.ParseRange(arg)
		if err != nil {
			return segment{}, err
		}
		if lo < 0 || hi < lo || hi > 65535 {
			return segment{}, fmt.Errorf("invalid size in noise exp: %s", arg)
		}
		return segment{kind: kind, minSize: int64(lo), maxSize: int64(hi)}, nil
	}
	plain := func(kind segmentKind) (segment, error) {
		if arg != "" {
			return segment{}, fmt.Errorf("<%s> in noise exp takes no argument", key)
		}
		return segment{kind: kind}, nil
	}
	switch key {
	case "b":
		hexStr := strings.Join(strings.Fields(arg), "")
		hexStr = strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
		if hexStr == "" {
			return segment{}, fmt.Errorf("empty bytes in noise exp")
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			return segment{}, fmt.Errorf("invalid hex in noise exp %q: %w", arg, err)
		}
		return segment{kind: segmentBytes, bytes: raw}, nil
	case "r":
		return sized(segmentRandom)
	case "rc":
		return sized(segmentRandomASCII)
	case "rd":
		return sized(segmentRandomDigit)
	case "t":
		return plain(segmentTimestamp)
	case "c":
		return plain(segmentCounter)
	case "n":
		return plain(segmentNonce)
	default:
		return segment{}, fmt.Errorf("unknown <%s> in noise exp", key)
	}
}

func (m *Mask) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	return &Conn{PacketConn: conn, mask: m, next: make(map[string]time.Time)}, nil
}

// Conn sends the noise ahead of the packets written to it.
type Conn struct {
	net.PacketConn
	mask    *Mask
	mu      sync.Mutex
	next    map[string]time.Time // when the flow to an address counts as idle
	counter atomic.Uint32
}

// maxNoiseSize is the largest datagram that can be sent.
const maxNoiseSize = 65507

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := ""
	if addr != nil {
		key = addr.String()
	}
	idle := c.next[key]
	if idle.IsZero() || (c.mask.reset.To > 0 && time.Now().After(idle)) {
		c.sendNoise(addr, key)
	}
	c.next[key] = time.Now().Add(time.Duration(c.mask.reset.Rand()) * time.Second)

	return c.PacketConn.WriteTo(p, addr)
}

func (c *Conn) sendNoise(addr net.Addr, key string) {
	if c.mask.script != nil {
		packets, err := c.mask.script.packets(key)
		if err != nil {
			return
		}
		for _, packet := range packets {
			_, _ = c.PacketConn.WriteTo(packet.packet, addr)
			time.Sleep(packet.delay)
		}
		return
	}
	for i := range c.mask.items {
		it := &c.mask.items[i]
		_, _ = c.PacketConn.WriteTo(c.build(it), addr)
		time.Sleep(time.Duration(it.delay.Rand()) * time.Millisecond)
	}
}

func (c *Conn) build(it *item) []byte {
	if len(it.segments) == 0 {
		if it.rand.To > 0 {
			buf := make([]byte, it.rand.Rand())
			mask.RandBytesBetween(buf, byte(it.randRange.From), byte(it.randRange.To))
			return buf
		}
		return it.packet
	}
	var out []byte
	for i := range it.segments {
		out = append(out, c.buildSegment(&it.segments[i])...)
	}
	return out
}

func (c *Conn) buildSegment(seg *segment) []byte {
	switch seg.kind {
	case segmentBytes:
		return seg.bytes
	case segmentTimestamp:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
		return b
	case segmentCounter:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, c.counter.Add(1))
		return b
	case segmentNonce:
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		return b
	}
	size := mask.RandBetween(seg.minSize, seg.maxSize+1)
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	switch seg.kind {
	case segmentRandomASCII:
		for i := range buf {
			buf[i] = asciiLetters[int(buf[i])%len(asciiLetters)]
		}
	case segmentRandomDigit:
		for i := range buf {
			buf[i] = '0' + buf[i]%10
		}
	}
	return buf
}
