package xmc

import (
	"bufio"
	"crypto/aes"
	"errors"
	"fmt"
	"io"
	"net"
)

// The Minecraft protocol is a stream of packets: the length of what follows
// as a varint, the packet ID as a varint, the fields. A varint is a 32 bit
// number in groups of 7 bits, the lowest first, with the high bit of a byte
// telling that another byte follows. A string or byte array is its length as
// a varint and the bytes.

const (
	maxPacketData = 32 * 1024         // the fields of a packet
	maxPacketBody = maxPacketData + 5 // and its ID
	maxString     = 4096
	maxByteArray  = 1023
)

func varintSize(value int32) int {
	size := 1
	for v := uint32(value) >> 7; v != 0; v >>= 7 {
		size++
	}
	return size
}

func appendVarint(dst []byte, value int32) []byte {
	v := uint32(value)
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// appendPrefixed appends a string or a byte array.
func appendPrefixed(dst []byte, data string) []byte {
	return append(appendVarint(dst, int32(len(data))), data...)
}

// appendPacket appends a packet whose fields are the given parts.
func appendPacket(dst []byte, id int32, parts ...[]byte) []byte {
	length := varintSize(id)
	for _, part := range parts {
		length += len(part)
	}
	dst = appendVarint(appendVarint(dst, int32(length)), id)
	for _, part := range parts {
		dst = append(dst, part...)
	}
	return dst
}

// readVarint reads a varint from next and returns it with its encoded size.
// Only the shortest encoding of a number is accepted.
func readVarint(next func() (byte, error)) (int32, int, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		b, err := next()
		if err != nil {
			return 0, i, err
		}
		if i == 4 && b&0xf0 != 0 {
			break
		}
		value |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if i+1 != varintSize(int32(value)) {
				return 0, i + 1, errors.New("non-canonical varint")
			}
			return int32(value), i + 1, nil
		}
	}
	return 0, 5, errors.New("varint is too large")
}

// fields reads the fields of a packet one after another. After a failure
// every read returns a zero value and err tells what went wrong.
type fields struct {
	data []byte
	err  error
}

func (f *fields) take(n int) []byte {
	if f.err != nil {
		return nil
	}
	if n < 0 || n > len(f.data) {
		f.err = io.ErrUnexpectedEOF
		return nil
	}
	out := f.data[:n]
	f.data = f.data[n:]
	return out
}

func (f *fields) next() (byte, error) {
	if b := f.take(1); b != nil {
		return b[0], nil
	}
	return 0, f.err
}

func (f *fields) varint() int32 {
	if f.err != nil {
		return 0
	}
	value, _, err := readVarint(f.next)
	f.err = err
	return value
}

func (f *fields) prefixed(max int32) []byte {
	length := f.varint()
	if f.err == nil && (length < 0 || length > max) {
		f.err = fmt.Errorf("bad length %d", length)
	}
	return f.take(int(length))
}

func (f *fields) str() string {
	return string(f.prefixed(maxString))
}

func (f *fields) bytes() []byte {
	return f.prefixed(maxByteArray)
}

func (f *fields) boolean() bool {
	b, _ := f.next()
	if b > 1 && f.err == nil {
		f.err = fmt.Errorf("bad boolean %d", b)
	}
	return b == 1
}

// wire is the connection as the protocol sees it: buffered reads, and both
// directions encrypted once the keys are set. Reading and writing are
// independent; each takes one goroutine at a time.
type wire struct {
	r   *bufio.Reader
	w   io.Writer
	dec *cfb8
	enc *cfb8

	frame    []byte // the packet read last
	out      []byte // what is being written
	writeErr error  // the failure that ended the writing
}

func (w *wire) readByte() (byte, error) {
	b, err := w.r.ReadByte()
	if err == nil && w.dec != nil {
		one := [1]byte{b}
		w.dec.crypt(one[:], one[:])
		b = one[0]
	}
	return b, err
}

// discard reads n bytes nobody looks at.
func (w *wire) discard(n int) error {
	var buf [4096]byte
	for n > 0 {
		chunk := buf[:]
		if n < len(chunk) {
			chunk = chunk[:n]
		}
		if _, err := io.ReadFull(w.r, chunk); err != nil {
			return err
		}
		if w.dec != nil {
			w.dec.skip(chunk)
		}
		n -= len(chunk)
	}
	return nil
}

// readPacket reads one packet. The fields are valid until the next call.
// started tells whether a part of the packet was consumed: if it was not, a
// failed read left the stream where it was and may be repeated.
func (w *wire) readPacket() (id int32, data []byte, started bool, err error) {
	length, size, err := readVarint(w.readByte)
	if err != nil {
		if size > 0 && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, size > 0, err
	}
	if length < 1 || length > maxPacketBody {
		return 0, nil, true, fmt.Errorf("bad packet length %d", length)
	}
	if cap(w.frame) < int(length) {
		w.frame = make([]byte, (int(length)+4095)&^4095)
	}
	body := fields{data: w.frame[:length]}
	if _, err = io.ReadFull(w.r, body.data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, true, err
	}
	if w.dec != nil {
		w.dec.crypt(body.data, body.data)
	}
	id = body.varint()
	if body.err != nil {
		return 0, nil, true, fmt.Errorf("packet ID: %w", body.err)
	}
	if len(body.data) > maxPacketData {
		return 0, nil, true, fmt.Errorf("bad packet data length %d", len(body.data))
	}
	return id, body.data, true, nil
}

// write sends w.out as one write, encrypted when the keys are set. A write
// that ran into its deadline before a byte left can be repeated. After any
// other failure nothing more is written: a part of the data may be on its
// way, and the cipher has moved past it.
func (w *wire) write() error {
	if w.writeErr != nil {
		return w.writeErr
	}
	var before [aes.BlockSize]byte
	if w.enc != nil {
		before = w.enc.register()
		w.enc.crypt(w.out, w.out)
	}
	n, err := w.w.Write(w.out)
	if err == nil {
		return nil
	}
	var timeout net.Error
	if n == 0 && errors.As(err, &timeout) && timeout.Timeout() {
		if w.enc != nil {
			w.enc.restore(before)
		}
		return err
	}
	w.writeErr = err
	return err
}

// writePacket sends a packet as one write.
func (w *wire) writePacket(id int32, parts ...[]byte) error {
	w.out = appendPacket(w.out[:0], id, parts...)
	return w.write()
}
