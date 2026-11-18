// Package mkcplegacy is the "mkcp-legacy" UDP mask of Xray-core's finalmask:
// the packet obfuscation and the fake packet headers mKCP had built in before
// Xray-core moved them out of the transport.
//
//	{}                               the original obfuscation (FNV-1a checksum and XOR)
//	{value: seed}                    AES-128-GCM with a key made from the seed
//	{header: dns, value: domain}     a DNS query header
//	{header: dtls|srtp|utp|wechat|wireguard}
//
// An entry is one of them; seed plus header takes two entries, the header last.
package mkcplegacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

func init() {
	mask.RegisterUDP("mkcp-legacy", func(settings map[string]any) (mask.UDPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	Header string `mask:"header,omitempty"`
	Value  string `mask:"value,omitempty"`
}

// codec masks and unmasks one datagram.
type codec interface {
	// seal appends the masked payload to dst.
	seal(dst, payload []byte) ([]byte, error)
	// open returns the payload of a masked datagram, which it may overwrite.
	open(packet []byte) ([]byte, error)
}

// Mask is a parsed mkcp-legacy mask.
type Mask struct {
	newCodec func() (codec, error)
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{}
	switch strings.ToLower(options.Header) {
	case "":
		if options.Value == "" {
			m.newCodec = func() (codec, error) { return original{}, nil }
		} else {
			key := sha256.Sum256([]byte(options.Value))
			m.newCodec = func() (codec, error) { return newAESGCM(key[:16]) }
		}
	case "dns":
		domain := options.Value
		if domain == "" {
			domain = "www.baidu.com"
		}
		header, err := dnsHeader(domain)
		if err != nil {
			return nil, err
		}
		m.newCodec = func() (codec, error) { return &headerCodec{header: &dns{header: header}}, nil }
	case "dtls":
		m.newCodec = func() (codec, error) { return &headerCodec{header: &dtls{}}, nil }
	case "srtp":
		m.newCodec = func() (codec, error) { return &headerCodec{header: &srtp{}}, nil }
	case "utp":
		m.newCodec = func() (codec, error) { return &headerCodec{header: &utp{}}, nil }
	case "wechat":
		m.newCodec = func() (codec, error) { return &headerCodec{header: &wechat{}}, nil }
	case "wireguard":
		m.newCodec = func() (codec, error) { return &headerCodec{header: wireguard{}}, nil }
	default:
		return nil, fmt.Errorf("invalid header %q", options.Header)
	}
	if _, err := m.newCodec(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Mask) WrapPacketConn(conn net.PacketConn, _ netip.AddrPort) (net.PacketConn, error) {
	c, err := m.newCodec()
	if err != nil {
		return nil, err
	}
	return &Conn{PacketConn: conn, codec: c}, nil
}

// Conn masks the datagrams of the wrapped connection.
type Conn struct {
	net.PacketConn
	writeMu sync.Mutex // the headers count packets
	codec   codec
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		payload, err := c.codec.open(buf[:n])
		if err != nil {
			continue // not ours, as Xray-core drops it
		}
		return copy(p, payload), addr, nil
	}
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := mask.GetBuffer()
	defer mask.PutBuffer(buf)
	if len(p)+maxOverhead > len(buf) {
		return 0, fmt.Errorf("mkcp-legacy: packet of %d bytes is too large", len(p))
	}
	c.writeMu.Lock()
	out, err := c.codec.seal(buf[:0], p)
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// maxOverhead bounds what a codec adds: the DNS header with the longest name.
const maxOverhead = 12 + 0x100 + 4

var errInvalid = errors.New("invalid packet")

// original is the obfuscation of mKCP without a seed:
// [FNV-1a 32 of the rest][length][payload], XORed forward in 4 byte steps.
type original struct{}

func (original) seal(dst, payload []byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start+4:], uint16(len(payload)))
	dst = append(dst, payload...)
	out := dst[start:]

	hash := fnv.New32a()
	_, _ = hash.Write(out[4:])
	binary.BigEndian.PutUint32(out, hash.Sum32())

	for i := 4; i < len(out); i++ {
		out[i] ^= out[i-4]
	}
	return dst, nil
}

func (original) open(packet []byte) ([]byte, error) {
	if len(packet) < 6 {
		return nil, errInvalid
	}
	for i := len(packet) - 1; i >= 4; i-- {
		packet[i] ^= packet[i-4]
	}
	hash := fnv.New32a()
	_, _ = hash.Write(packet[4:])
	if binary.BigEndian.Uint32(packet[:4]) != hash.Sum32() {
		return nil, errInvalid
	}
	if len(packet)-6 != int(binary.BigEndian.Uint16(packet[4:6])) {
		return nil, errInvalid
	}
	return packet[6:], nil
}

// aesGCM is the obfuscation of mKCP with a seed: [nonce][ciphertext and tag].
type aesGCM struct {
	aead cipher.AEAD
}

func newAESGCM(key []byte) (codec, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM{aead: aead}, nil
}

func (c aesGCM) seal(dst, payload []byte) ([]byte, error) {
	nonceStart := len(dst)
	dst = append(dst, make([]byte, c.aead.NonceSize())...)
	nonce := dst[nonceStart:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(dst, nonce, payload, nil), nil
}

func (c aesGCM) open(packet []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(packet) < nonceSize+c.aead.Overhead() {
		return nil, errInvalid
	}
	return c.aead.Open(packet[nonceSize:nonceSize], packet[:nonceSize], packet[nonceSize:], nil)
}

// header is a fake packet header. The receiver cuts it off without looking.
type header interface {
	size() int
	serialize(b []byte)
}

type headerCodec struct {
	header header
}

func (c *headerCodec) seal(dst, payload []byte) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, c.header.size())...)
	c.header.serialize(dst[start:])
	return append(dst, payload...), nil
}

func (c *headerCodec) open(packet []byte) ([]byte, error) {
	if len(packet) < c.header.size() {
		return nil, errInvalid
	}
	return packet[c.header.size():], nil
}

type dns struct {
	header []byte
}

func (h *dns) size() int { return len(h.header) }

func (h *dns) serialize(b []byte) {
	copy(b, h.header)
	_, _ = rand.Read(b[:2]) // transaction ID
}

// dnsHeader is a standard query of type A for the domain.
func dnsHeader(domain string) ([]byte, error) {
	header := []byte{
		0, 0, // transaction ID
		1, 0, // flags: standard query
		0, 1, // questions
		0, 0, 0, 0, 0, 0, // answer, authority and additional records
	}
	name, err := packDomainName(domain + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	header = append(header, name...)
	header = append(header, 0, 1, 0, 1) // type A, class IN
	return header, nil
}

// packDomainName encodes a dotted name the way Xray-core does, so that both
// ends get a header of the same length for any value: every dot ends a
// label (a trailing dot in the setting makes one more, empty, label), a
// backslash escapes the character after it, a zero byte ends the name.
func packDomainName(name string) ([]byte, error) {
	msg := make([]byte, 0x100)
	s := []byte(name)
	ls := len(s)
	off, begin := 0, 0
	for i := 0; i < ls; i++ {
		switch s[i] {
		case '\\':
			copy(s[i:ls-1], s[i+1:ls])
			ls--
		case '.':
			labelLen := i - begin
			if labelLen >= 1<<6 {
				return nil, errors.New("a label is longer than 63 bytes")
			}
			if off+1+labelLen > len(msg) {
				return nil, errors.New("the name is too long")
			}
			msg[off] = byte(labelLen)
			copy(msg[off+1:], s[begin:i])
			off += 1 + labelLen
			begin = i + 1
		}
	}
	if off+1 > len(msg) {
		return nil, errors.New("the name is too long")
	}
	msg[off] = 0
	return msg[:off+1], nil
}

type dtls struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func (*dtls) size() int { return 13 }

func (h *dtls) serialize(b []byte) {
	b[0] = 23
	b[1] = 254
	b[2] = 253
	binary.BigEndian.PutUint16(b[3:], h.epoch)
	b[5] = 0
	b[6] = 0
	binary.BigEndian.PutUint32(b[7:], h.sequence)
	h.sequence++
	binary.BigEndian.PutUint16(b[11:], h.length)
	h.length += 17
	if h.length > 100 {
		h.length -= 50
	}
}

type srtp struct {
	header uint16
	number uint16
}

func (*srtp) size() int { return 4 }

func (h *srtp) serialize(b []byte) {
	h.number++
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], h.number)
}

type utp struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*utp) size() int { return 4 }

func (h *utp) serialize(b []byte) {
	binary.BigEndian.PutUint16(b, h.connectionID)
	b[2] = h.header
	b[3] = h.extension
}

type wechat struct {
	sn uint32
}

func (*wechat) size() int { return 13 }

func (h *wechat) serialize(b []byte) {
	h.sn++
	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], h.sn)
	copy(b[6:], []byte{0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30})
}

type wireguard struct{}

func (wireguard) size() int { return 4 }

func (wireguard) serialize(b []byte) {
	b[0], b[1], b[2], b[3] = 0x04, 0x00, 0x00, 0x00
}
