package xmc

import (
	"crypto/aes"
	"crypto/cipher"
)

// cfb8Slide is how many bytes the shift register moves through its buffer
// before it is copied back to the start.
const cfb8Slide = 1024

// cfb8 is AES in CFB mode with 8 bits of feedback, the stream cipher of the
// Minecraft protocol. For every byte the cipher encrypts a 16 byte shift
// register, XORs the byte with the first byte of the result and shifts the
// ciphertext byte into the register. The register starts as the IV.
type cfb8 struct {
	block   cipher.Block
	decrypt bool
	// The register is buf[pos:pos+16]: shifting a byte in is one store.
	buf [aes.BlockSize + cfb8Slide]byte
	pos int
	out [aes.BlockSize]byte
}

func newCFB8(key, iv []byte, decrypt bool) (*cfb8, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	s := &cfb8{block: block, decrypt: decrypt}
	copy(s.buf[:aes.BlockSize], iv)
	return s, nil
}

// crypt encrypts or decrypts src into dst. They may be the same slice.
func (s *cfb8) crypt(dst, src []byte) {
	for i, in := range src {
		s.block.Encrypt(s.out[:], s.buf[s.pos:s.pos+aes.BlockSize])
		out := in ^ s.out[0]
		dst[i] = out
		if s.decrypt {
			s.shift(in)
		} else {
			s.shift(out)
		}
	}
}

// skip moves a decrypting stream past ciphertext nobody wants to read. The
// register is the last 16 bytes of ciphertext, so no block has to be
// encrypted for it.
func (s *cfb8) skip(ciphertext []byte) {
	if len(ciphertext) >= aes.BlockSize {
		copy(s.buf[:aes.BlockSize], ciphertext[len(ciphertext)-aes.BlockSize:])
		s.pos = 0
		return
	}
	for _, b := range ciphertext {
		s.shift(b)
	}
}

// register returns the shift register, the whole state of the stream.
func (s *cfb8) register() (register [aes.BlockSize]byte) {
	copy(register[:], s.buf[s.pos:])
	return register
}

// restore puts the stream back to where register was taken.
func (s *cfb8) restore(register [aes.BlockSize]byte) {
	copy(s.buf[:], register[:])
	s.pos = 0
}

func (s *cfb8) shift(b byte) {
	if s.pos == cfb8Slide {
		copy(s.buf[:], s.buf[s.pos+1:])
		s.buf[aes.BlockSize-1] = b
		s.pos = 0
		return
	}
	s.buf[s.pos+aes.BlockSize] = b
	s.pos++
}
