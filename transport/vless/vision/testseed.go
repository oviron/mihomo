package vision

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/randv2"
)

// Testseed holds the four padding parameters of Xray-core's "testseed":
// a block shorter than [0] bytes that belongs to a TLS handshake is padded to
// [2]..[2]+[1] bytes, any other block gets 0..[3] bytes of padding.
//
// Setting it makes the writer follow Xray-core v26.11.9 (proxy/proxy.go
// VisionWriter) instead of the built-in behaviour: blocks of [0] bytes and
// more are padded too, and the switch to direct copy happens only when the
// written data ends on a TLS record boundary.
type Testseed [4]uint32

// DefaultTestseed is what Xray-core uses when "testseed" is not set.
var DefaultTestseed = Testseed{900, 500, 900, 256}

// NewTestseed reads the "testseed" option the way Xray-core does: the first
// four values count, fewer than four mean DefaultTestseed. Values above the
// block size behave like the block size because the padding is capped by it.
func NewTestseed(values []uint32) (*Testseed, error) {
	seed := DefaultTestseed
	if len(values) >= 4 {
		copy(seed[:], values)
	}
	for i, v := range seed {
		if v > xrayBufSize {
			seed[i] = xrayBufSize
		}
	}
	if seed[1] == 0 || seed[3] == 0 { // Xray-core draws random numbers below them
		return nil, errors.New("the second and the fourth testseed values must be positive")
	}
	return &seed, nil
}

// SetTestseed switches the writer to Xray-core's padding and direct copy rules.
func (vc *Conn) SetTestseed(seed *Testseed) {
	vc.testseed = seed
}

// maxPadding is the longest padding the seed can produce.
func (s *Testseed) maxPadding() int {
	longest := s[1] + s[2]
	if s[3] > longest {
		longest = s[3]
	}
	if longest > xrayBufSize-PaddingHeaderLen {
		longest = xrayBufSize - PaddingHeaderLen
	}
	return int(longest)
}

// paddingLen is the padding Xray-core's XtlsPadding adds to a block.
func (s *Testseed) paddingLen(contentLen int32, longPadding bool) int32 {
	var paddingLen int32
	if contentLen < int32(s[0]) && longPadding {
		paddingLen = randv2.Int32N(int32(s[1])) + int32(s[2]) - contentLen
	} else {
		paddingLen = randv2.Int32N(int32(s[3]))
	}
	if limit := xrayBufSize - PaddingHeaderLen - contentLen; paddingLen > limit {
		paddingLen = limit
	}
	if paddingLen < 0 {
		paddingLen = 0
	}
	return paddingLen
}

// applyPadding frames the block like ApplyPadding with the seed's padding length.
func (s *Testseed) applyPadding(buffer *buf.Buffer, command byte, userUUID *[]byte, longPadding bool) {
	contentLen := int32(buffer.Len())
	paddingLen := s.paddingLen(contentLen, longPadding)

	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(paddingLen))
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(contentLen))
	buffer.ExtendHeader(1)[0] = command
	if userUUID != nil && *userUUID != nil {
		copy(buffer.ExtendHeader(uuid.Size), *userUUID)
		*userUUID = nil
	}

	padding := buffer.Extend(int(paddingLen))
	for i := range padding { // the buffer may come from a pool with old data in it
		padding[i] = 0
	}
	log.Debugln("XTLS Vision write padding: command=%d, payloadLen=%d, paddingLen=%d", command, contentLen, paddingLen)
}

// reshape cuts a buffer that does not fit a block of Xray-core's size, like
// ReshapeBuffer, but sizes the pieces itself: a large seed asks for more rear
// headroom than a pooled buffer may have left.
func (vc *Conn) reshape(buffer *buf.Buffer) []*buf.Buffer {
	const bufferLimit = xrayBufSize - PaddingHeaderLen
	if buffer.Len() < bufferLimit {
		return []*buf.Buffer{buffer}
	}
	front, rear := N.CalculateFrontHeadroom(vc), N.CalculateRearHeadroom(vc)
	var buffers []*buf.Buffer
	for buffer.Len() >= bufferLimit {
		cutAt := bytes.LastIndex(buffer.Bytes(), tlsApplicationDataStart)
		if cutAt < PaddingHeaderLen || cutAt > bufferLimit {
			cutAt = xrayBufSize / 2
		}
		piece := buf.NewSize(front + cutAt + rear)
		piece.Resize(front, 0)
		buf.Must(buf.Error(piece.ReadFullFrom(buffer, cutAt)))
		buffers = append(buffers, piece)
	}
	return append(buffers, buffer)
}

// isCompleteRecords reports whether b consists of whole TLS application data
// records and nothing else.
func isCompleteRecords(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for len(b) > 0 {
		if len(b) < 5 || !bytes.Equal(b[:3], tlsApplicationDataStart) {
			return false
		}
		recordLen := int(binary.BigEndian.Uint16(b[3:]))
		if recordLen == 0 || len(b) < 5+recordLen {
			return false
		}
		b = b[5+recordLen:]
	}
	return true
}

// writeBufferWithTestseed is the padding phase of Xray-core's VisionWriter.
func (vc *Conn) writeBufferWithTestseed(buffer *buf.Buffer) (err error) {
	seed := vc.testseed
	if buffer.IsEmpty() {
		seed.applyPadding(buffer, commandPaddingContinue, &vc.writeOnceUserUUID, true) // we do a long padding to hide vless header
		return vc.ExtendedWriter.WriteBuffer(buffer)
	}

	vc.FilterTLS(buffer.Bytes())
	isComplete := isCompleteRecords(buffer.Bytes())
	buffers := vc.reshape(buffer)
	longPadding := vc.isTLS
	switchToDirect := false
	for i, buffer := range buffers {
		command := commandPaddingContinue
		last := i == len(buffers)-1
		if vc.isTLS && buffer.Len() >= 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) && isComplete {
			if vc.enableXTLS {
				switchToDirect = true
			}
			if last {
				command = commandPaddingEnd
				if vc.enableXTLS {
					command = commandPaddingDirect
				}
			}
			seed.applyPadding(buffer, command, &vc.writeOnceUserUUID, true)
			vc.writeFilterApplicationData = false // padding going to end
			longPadding = false
			continue
		} else if !vc.isTLS12orAbove && vc.packetsToFilter <= 1 { // for compatibility with earlier vision receiver, we finish padding 1 packet early
			vc.writeFilterApplicationData = false
			seed.applyPadding(buffer, commandPaddingEnd, &vc.writeOnceUserUUID, longPadding)
			break // the blocks after the end of padding are written as is
		}
		if last && !vc.writeFilterApplicationData {
			command = commandPaddingEnd
			if vc.enableXTLS {
				command = commandPaddingDirect
			}
		}
		seed.applyPadding(buffer, command, &vc.writeOnceUserUUID, longPadding)
	}

	for i, buffer := range buffers {
		err = vc.ExtendedWriter.WriteBuffer(buffer)
		if err != nil {
			buf.ReleaseMulti(buffers[i:]) // release unwritten buffers
			return
		}
	}
	if switchToDirect {
		vc.writeDirect = true
		vc.ExtendedWriter = N.NewExtendedWriter(vc.netConn)
		log.Debugln("XTLS Vision direct write start")
	}
	return nil
}
