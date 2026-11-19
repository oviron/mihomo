// Package salamander is the "salamander" UDP mask of Xray-core's finalmask,
// the obfuscation of Hysteria 2: every datagram is XORed with a key derived
// from the password and a random salt. With a packet size it becomes Gecko,
// which also splits and pads the long header QUIC packets.
package salamander

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/metacubex/sing-quic/hysteria2"
	"golang.org/x/crypto/blake2b"
)

const (
	minPasswordLen = 4
	saltLen        = 8
	keyLen         = blake2b.Size256

	geckoMaxPacketSize = 2048
)

func init() {
	mask.RegisterUDP("salamander", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	Password string `mask:"password,omitempty"`
	// PacketSize is the range of the datagram sizes Gecko pads to. Zero keeps
	// plain Salamander.
	PacketSize mask.Range `mask:"packet-size,omitempty"`
}

// Mask is a parsed salamander mask.
type Mask struct {
	password   []byte
	gecko      bool
	packetSize mask.Range
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	if len(options.Password) < minPasswordLen {
		return nil, fmt.Errorf("password must be at least %d bytes", minPasswordLen)
	}
	m := &Mask{password: []byte(options.Password), packetSize: options.PacketSize}
	if options.PacketSize.To > 0 {
		if options.PacketSize.From <= 0 || options.PacketSize.To > geckoMaxPacketSize {
			return nil, fmt.Errorf("gecko: invalid min/max packet size")
		}
		m.gecko = true
	}
	return m, nil
}

func (m *Mask) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	if m.gecko {
		// The Gecko of sing-quic reads into the buffer it is given, which a
		// padded fragment may not fit.
		// It also hands datagrams no longer than the salt up as they are,
		// where Xray-core drops them.
		inner := hysteria2.NewGeckoConn(&minSizeConn{PacketConn: conn}, m.password, int(m.packetSize.From), int(m.packetSize.To))
		return &largeReadConn{PacketConn: inner}, nil
	}
	return &Conn{PacketConn: conn, password: m.password}, nil
}

// Conn obfuscates the datagrams of the wrapped connection: [8-byte salt][payload XOR key].
type Conn struct {
	net.PacketConn
	password []byte
}

func (c *Conn) key(salt []byte) [keyLen]byte {
	input := make([]byte, 0, len(c.password)+saltLen)
	input = append(input, c.password...)
	input = append(input, salt...)
	return blake2b.Sum256(input)
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= saltLen { // nothing after the salt
			continue
		}
		key := c.key(buf[:saltLen])
		payload := buf[saltLen:n]
		if len(payload) > len(p) {
			payload = payload[:len(p)]
		}
		for i, b := range payload {
			p[i] = b ^ key[i%keyLen]
		}
		return len(payload), addr, nil
	}
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p)+saltLen > mask.BufferSize {
		return 0, fmt.Errorf("salamander: packet of %d bytes is too large", len(p))
	}
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	out := buf[:saltLen+len(p)]
	if _, err := rand.Read(out[:saltLen]); err != nil {
		return 0, err
	}
	key := c.key(out[:saltLen])
	for i, b := range p {
		out[saltLen+i] = b ^ key[i%keyLen]
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// largeReadConn reads through a buffer of mask.BufferSize bytes.
type largeReadConn struct {
	net.PacketConn
}

func (c *largeReadConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) >= mask.BufferSize {
		return c.PacketConn.ReadFrom(p)
	}
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	n, addr, err := c.PacketConn.ReadFrom(buf)
	return copy(p, buf[:n]), addr, err
}

// minSizeConn drops the datagrams that have nothing after the salt.
type minSizeConn struct {
	net.PacketConn
}

func (c *minSizeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || n > saltLen {
			return n, addr, err
		}
	}
}
