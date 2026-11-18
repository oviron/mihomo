// Package muxcool implements Mux.Cool, the connection multiplexing protocol of
// Xray-core and V2Ray, as described by Xray-core v26.11.9 (common/mux).
//
// One carrier connection, opened to the destination "v1.mux.cool", carries
// many sessions. A session is a TCP stream or a UDP association; frames of a
// session are tagged with its 16-bit ID. There is no flow control: a session
// whose reader is slow holds back the carrier.
//
// A frame is a metadata block prefixed with its 16-bit length, followed, when
// the data option is set, by a payload prefixed with its 16-bit length:
//
//	2 bytes  metadata length
//	2 bytes  session ID
//	1 byte   status (new, keep, end, keep-alive)
//	1 byte   options (data, error)
//	         new:  network, port, address [, XUDP GlobalID | source, local]
//	         keep: [network, port, address] for a UDP packet
//	2 bytes  payload length   (data option only)
//	         payload
package muxcool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	// Destination is where a carrier connection is addressed to.
	Destination = "v1.mux.cool"
	// DestinationPort is the port Xray-core puts next to Destination.
	DestinationPort = 9527

	// MaxPayload is the largest payload of one frame. Xray-core cuts streams
	// in chunks of this size and rejects longer packets.
	MaxPayload = 8192

	maxMetadata = 512
)

// Status is the session status a frame carries.
type Status byte

const (
	StatusNew       Status = 0x01
	StatusKeep      Status = 0x02
	StatusEnd       Status = 0x03
	StatusKeepAlive Status = 0x04
)

const (
	OptionData  byte = 0x01
	OptionError byte = 0x02
)

// Network is the target network of a session.
type Network byte

const (
	NetworkTCP Network = 0x01
	NetworkUDP Network = 0x02
)

const (
	addrIPv4   byte = 0x01
	addrDomain byte = 0x02
	addrIPv6   byte = 0x03
)

// Endpoint is a network address with its network.
type Endpoint struct {
	Network Network
	Addr    M.Socksaddr
}

// Metadata is the metadata block of a frame.
type Metadata struct {
	SessionID uint16
	Status    Status
	Option    byte

	// Target is set on a new session, and on a keep frame of a UDP session
	// that names the address of its packet. Its Network is zero otherwise.
	Target Endpoint

	// GlobalID is the XUDP GlobalID of a new UDP session; zero means none.
	GlobalID [8]byte

	// Source and Local are the endpoints of the original connection. Only a
	// reverse proxy portal sends them, on a new session, in place of GlobalID.
	Source, Local Endpoint
}

// HasData reports whether a payload follows the metadata.
func (m *Metadata) HasData() bool {
	return m.Option&OptionData != 0
}

// HasError reports whether an end frame closes its session with an error.
func (m *Metadata) HasError() bool {
	return m.Option&OptionError != 0
}

func appendAddr(b []byte, addr M.Socksaddr) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, addr.Port)
	switch {
	case addr.IsFqdn():
		if len(addr.Fqdn) > 255 {
			return nil, errors.New("muxcool: domain name too long")
		}
		b = append(b, addrDomain, byte(len(addr.Fqdn)))
		b = append(b, addr.Fqdn...)
	case addr.Addr.Is4() || addr.Addr.Is4In6():
		ip := addr.Addr.Unmap().As4()
		b = append(b, addrIPv4)
		b = append(b, ip[:]...)
	case addr.Addr.Is6():
		ip := addr.Addr.As16()
		b = append(b, addrIPv6)
		b = append(b, ip[:]...)
	default:
		return nil, errors.New("muxcool: invalid address")
	}
	return b, nil
}

func appendEndpoint(b []byte, e Endpoint) ([]byte, error) {
	return appendAddr(append(b, byte(e.Network)), e.Addr)
}

// Append appends the frame header of m to b: the metadata with its length
// prefix and, when the data option is set, the length prefix of a payload of
// payloadLen bytes. The payload itself follows the returned bytes. Keeping a
// payload within MaxPayload is up to the caller.
func (m *Metadata) Append(b []byte, payloadLen int) ([]byte, error) {
	start := len(b)
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint16(b, m.SessionID)
	b = append(b, byte(m.Status), m.Option)

	var err error
	switch {
	case m.Status == StatusNew:
		if b, err = appendEndpoint(b, m.Target); err != nil {
			return nil, err
		}
		if m.Source.Network != 0 {
			if b, err = appendEndpoint(b, m.Source); err != nil {
				return nil, err
			}
			if m.Local.Network != 0 {
				if b, err = appendEndpoint(b, m.Local); err != nil {
					return nil, err
				}
			}
		} else if m.GlobalID != [8]byte{} {
			b = append(b, m.GlobalID[:]...)
		}
	case m.Status == StatusKeep && m.Target.Network == NetworkUDP:
		if b, err = appendEndpoint(b, m.Target); err != nil {
			return nil, err
		}
	}

	metaLen := len(b) - start - 2
	if metaLen > maxMetadata {
		return nil, errors.New("muxcool: metadata too long")
	}
	binary.BigEndian.PutUint16(b[start:], uint16(metaLen))
	if m.HasData() {
		if payloadLen < 0 || payloadLen > 0xffff {
			return nil, errors.New("muxcool: invalid payload length")
		}
		b = binary.BigEndian.AppendUint16(b, uint16(payloadLen))
	}
	return b, nil
}

func readAddr(b []byte) (addr M.Socksaddr, rest []byte, err error) {
	if len(b) < 3 {
		return addr, nil, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(b)
	kind := b[2]
	b = b[3:]
	switch kind {
	case addrIPv4:
		if len(b) < 4 {
			return addr, nil, io.ErrUnexpectedEOF
		}
		return M.SocksaddrFrom(netip.AddrFrom4([4]byte(b[:4])), port), b[4:], nil
	case addrIPv6:
		if len(b) < 16 {
			return addr, nil, io.ErrUnexpectedEOF
		}
		return M.SocksaddrFrom(netip.AddrFrom16([16]byte(b[:16])), port), b[16:], nil
	case addrDomain:
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return addr, nil, io.ErrUnexpectedEOF
		}
		n := int(b[0])
		return M.Socksaddr{Fqdn: string(b[1 : 1+n]), Port: port}, b[1+n:], nil
	}
	return addr, nil, fmt.Errorf("muxcool: unknown address type %d", kind)
}

func readEndpoint(b []byte) (e Endpoint, rest []byte, err error) {
	if len(b) < 1 {
		return e, nil, io.ErrUnexpectedEOF
	}
	e.Network = Network(b[0])
	if e.Network != NetworkTCP && e.Network != NetworkUDP {
		return e, nil, fmt.Errorf("muxcool: unknown network %d", b[0])
	}
	e.Addr, rest, err = readAddr(b[1:])
	return
}

// ParseMetadata parses a metadata block without its length prefix.
//
// reverse tells how to read what follows the target of a new session: the
// source and local endpoints a reverse proxy portal sends, or the XUDP
// GlobalID an ordinary peer may send.
func ParseMetadata(b []byte, reverse bool) (m Metadata, err error) {
	if len(b) < 4 {
		return m, io.ErrUnexpectedEOF
	}
	m.SessionID = binary.BigEndian.Uint16(b)
	m.Status = Status(b[2])
	m.Option = b[3]
	b = b[4:]

	// A keep frame names an address only for a UDP packet.
	if m.Status == StatusNew || (m.Status == StatusKeep && len(b) > 0 && Network(b[0]) == NetworkUDP) {
		if m.Target, b, err = readEndpoint(b); err != nil {
			return m, err
		}
	}
	if m.Status != StatusNew {
		return m, nil
	}
	if reverse {
		// A zero network byte or the end of the block ends the list.
		if len(b) == 0 || b[0] == 0 {
			return m, nil
		}
		if m.Source, b, err = readEndpoint(b); err != nil {
			return m, err
		}
		if len(b) == 0 || b[0] == 0 {
			return m, nil
		}
		m.Local, _, err = readEndpoint(b)
		return m, err
	}
	if m.HasData() && m.Target.Network == NetworkUDP && len(b) >= 8 {
		copy(m.GlobalID[:], b)
	}
	return m, nil
}

// ReadMetadata reads the metadata block of the next frame from r.
func ReadMetadata(r io.Reader, reverse bool) (Metadata, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Metadata{}, err
	}
	metaLen := int(binary.BigEndian.Uint16(head[:]))
	if metaLen > maxMetadata {
		return Metadata{}, fmt.Errorf("muxcool: invalid metadata length %d", metaLen)
	}
	var block [maxMetadata]byte
	if _, err := io.ReadFull(r, block[:metaLen]); err != nil {
		return Metadata{}, err
	}
	return ParseMetadata(block[:metaLen], reverse)
}

// ReadPayloadLen reads the length prefix of the payload that follows a
// metadata block whose data option is set.
func ReadPayloadLen(r io.Reader) (int, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(head[:])), nil
}
