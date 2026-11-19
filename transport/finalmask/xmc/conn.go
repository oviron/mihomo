package xmc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/finalmask/mask"
)

const (
	protocolVersion = 775 // Minecraft 26.1.2
	defaultPort     = 25565
	stateLogin      = 2 // what the Handshake packet asks for

	// Packets of the handshake and login states.
	idHandshake         = 0x00
	idLoginStart        = 0x00
	idDisconnect        = 0x00
	idEncryption        = 0x01 // the request of the server, the response of the client
	idLoginSuccess      = 0x02
	idLoginAcknowledged = 0x03
	// Packets of the configuration state, which carries the payload.
	idPayloadFromServer = 0x01
	idPayloadFromClient = 0x02
	idKeepAlive         = 0x04

	payloadChannel = "xmc:data"
	// maxPayload is how much of the payload goes into one packet.
	maxPayload = 24 * 1024

	// handshakeTimeout bounds the login and the padding together.
	handshakeTimeout = 2 * time.Minute
)

var payloadChannelField = appendPrefixed(nil, payloadChannel)

// Conn is a connection under the mask. Every byte it carries is framed and
// encrypted for as long as it lives, so it gives the relay no way to the
// connection it wraps: no Upstream, ReaderReplaceable or WriterReplaceable.
type Conn struct {
	conn      net.Conn
	mask      *Mask
	wire      wire
	burst     int // see clientBursts
	deadlines deadlines

	handshakeOnce sync.Once
	handshakeDone chan struct{} // closed when the handshake is over
	handshakeErr  error         // set before that

	readMu  sync.Mutex
	readErr error
	pending []byte // payload of the last packet not yet returned

	writeMu  sync.Mutex   // one Write, or the keep-alive answers, at a time
	echoes   chan [8]byte // keep-alive answers to be written
	flushing atomic.Bool  // a goroutine is writing them

	closeOnce sync.Once
	closed    chan struct{}
}

var _ net.Conn = (*Conn)(nil)

// handshake waits until the connection is logged in and the padding is
// exchanged, which the first Read or Write starts. The caller waits no longer
// than its deadline allows, the read or the write one; the handshake goes on
// without it and may be waited for again. A failed handshake is final: the
// stream is in an unknown state after it.
func (c *Conn) handshake(read bool) error {
	select {
	case <-c.handshakeDone:
		return c.handshakeErr
	default:
	}
	c.handshakeOnce.Do(func() { go c.runHandshake() })
	if err := c.deadlines.wait(c.handshakeDone, read); err != nil {
		return err
	}
	return c.handshakeErr
}

// runHandshake ends when the handshake is done, the time for it is over or
// the connection is closed.
func (c *Conn) runHandshake() {
	err := c.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err == nil {
		err = c.login()
	}
	if err != nil {
		select {
		case <-c.closed:
			err = net.ErrClosed
		default:
		}
		c.handshakeErr = fmt.Errorf("xmc handshake: %w", err)
	}
	_ = c.deadlines.handOver()
	close(c.handshakeDone)
}

// login plays the client from the Handshake packet to the last padding turn.
func (c *Conn) login() error {
	m, w := c.mask, &c.wire

	// Handshake: protocol version, server address and port, next state.
	host, port := m.hostname, defaultPort
	if addr := c.conn.RemoteAddr(); addr != nil {
		if h, p, err := net.SplitHostPort(addr.String()); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
			if host == "" {
				host = h
			}
		}
	}
	hello := appendPrefixed(appendVarint(nil, protocolVersion), host)
	hello = appendVarint(append(hello, byte(port>>8), byte(port)), stateLogin)
	if err := w.writePacket(idHandshake, hello); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}

	// Login Start: the name and UUID of the player.
	player := m.profiles[mask.RandBetween(0, int64(len(m.profiles)))]
	if err := w.writePacket(idLoginStart, appendPrefixed(nil, player.username), player.uuid[:]); err != nil {
		return fmt.Errorf("write login start: %w", err)
	}

	// Encryption Request: server ID, public key, verify token.
	id, data, _, err := w.readPacket()
	if err != nil {
		return fmt.Errorf("read encryption request: %w", err)
	}
	if id != idEncryption {
		return fmt.Errorf("packet 0x%02x instead of the encryption request", id)
	}
	request := fields{data: data}
	_ = request.str() // the server ID, empty
	publicKey := request.bytes()
	verifyToken := request.bytes()
	if request.err != nil {
		return fmt.Errorf("read encryption request: %w", request.err)
	}
	// The key is derived from the password: a server that has another
	// password, or is not this mask at all, shows another key.
	if !bytes.Equal(publicKey, m.key.der) {
		return errors.New("server public key mismatch: the password differs from the server's")
	}

	// Encryption Response: the session key, and the verify token with the
	// password after it, each encrypted with the key of the server.
	secret := make([]byte, 16)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	encryptedSecret, err := rsa.EncryptPKCS1v15(rand.Reader, m.key.public, secret)
	if err != nil {
		return fmt.Errorf("encrypt shared secret: %w", err)
	}
	token := append(append([]byte(nil), verifyToken...), m.password...)
	encryptedToken, err := rsa.EncryptPKCS1v15(rand.Reader, m.key.public, token)
	if err != nil {
		return fmt.Errorf("encrypt verify token: %w", err)
	}
	err = w.writePacket(idEncryption, appendPrefixed(nil, string(encryptedSecret)), appendPrefixed(nil, string(encryptedToken)))
	if err != nil {
		return fmt.Errorf("write encryption response: %w", err)
	}
	// As in the game the session key is the IV too.
	if w.enc, err = newCFB8(secret, secret, false); err != nil {
		return err
	}
	if w.dec, err = newCFB8(secret, secret, true); err != nil {
		return err
	}

	// Login Success: the UUID and name of the player and one property, the
	// signed textures. Or Disconnect with the reason.
	if id, data, _, err = w.readPacket(); err != nil {
		return fmt.Errorf("read login success: %w", err)
	}
	reply := fields{data: data}
	switch id {
	case idLoginSuccess:
	case idDisconnect:
		return fmt.Errorf("the server refused the login: %s", reply.str())
	default:
		return fmt.Errorf("packet 0x%02x instead of the login success", id)
	}
	var confirmed profile
	copy(confirmed.uuid[:], reply.take(len(confirmed.uuid)))
	confirmed.username = reply.str()
	properties := reply.varint()
	property := reply.str()
	confirmed.texturesValue = reply.str()
	signed := reply.boolean()
	confirmed.texturesSignature = reply.str()
	if reply.err != nil {
		return fmt.Errorf("read login success: %w", reply.err)
	}
	if properties != 1 || property != "textures" || !signed {
		return errors.New("invalid login profile properties")
	}
	if confirmed != player {
		return errors.New("login profile mismatch")
	}
	if err = w.writePacket(idLoginAcknowledged); err != nil {
		return fmt.Errorf("write login acknowledged: %w", err)
	}

	for i := range schedule {
		if t := &schedule[i]; !t.fromClient {
			err = w.readPadding(t)
		} else if err = c.sleep(t.startDelay.rand()); err == nil {
			err = w.writePadding(clientChunks(i, c.burst))
		}
		if err != nil {
			return fmt.Errorf("padding turn %d: %w", i, err)
		}
	}
	return nil
}

// sleep pauses for d, or less if the connection is closed.
func (c *Conn) sleep(d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.handshake(true); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		id, data, started, err := c.wire.readPacket()
		if err != nil {
			if started {
				// half a packet is gone, nothing can be read after it
				err = fmt.Errorf("xmc: read packet: %w", err)
				c.readErr = err
			}
			return 0, err
		}
		switch id {
		case idPayloadFromServer:
			payload := fields{data: data}
			channel := payload.str()
			if payload.err != nil {
				return 0, fmt.Errorf("xmc: read payload channel: %w", payload.err)
			}
			if channel == payloadChannel {
				c.pending = payload.data
			}
		case idKeepAlive:
			// The server sends a number every 15 seconds and expects it back.
			if len(data) < 8 {
				return 0, errors.New("xmc: short keep-alive packet")
			}
			c.answerKeepAlive(data[:8])
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// answerKeepAlive has the number of a keep-alive packet sent back. Read does
// not wait for that: the writing side may be busy or stuck, and the read
// deadline does not reach there. A goroutine writes the answers unless one is
// at it already; it ends with the queue empty or the write failed, and a
// closed connection fails it.
func (c *Conn) answerKeepAlive(number []byte) {
	var echo [8]byte
	copy(echo[:], number)
	select {
	case c.echoes <- echo:
	default: // nothing was written for minutes, one answer more or less does not matter
	}
	if !c.flushing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		for {
			c.writeMu.Lock()
			err := c.writeEchoes()
			c.writeMu.Unlock()
			c.flushing.Store(false)
			// an answer may have been queued after the last look at the queue
			if err != nil || len(c.echoes) == 0 || !c.flushing.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

// writeEchoes writes the queued keep-alive answers. The caller holds writeMu.
func (c *Conn) writeEchoes() error {
	for {
		select {
		case echo := <-c.echoes:
			if err := c.wire.writePacket(idKeepAlive, echo[:]); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

// Write sends p in packets of at most maxPayload bytes. The packets of one
// call leave in a row: only keep-alive answers go between them.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.handshake(false); err != nil {
		return 0, err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for written < len(p) {
		end := written + maxPayload
		if end > len(p) {
			end = len(p)
		}
		if err := c.writeEchoes(); err != nil {
			return written, err
		}
		if err := c.wire.writePacket(idPayloadFromClient, payloadChannelField, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// Close closes the connection. A handshake in progress fails.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.deadlines.set(&t, &t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.deadlines.set(&t, nil)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.deadlines.set(nil, &t)
}

// deadlines are the deadlines of the caller. While the handshake runs the
// connection has the deadline of the handshake, and the caller's only bound
// how long its Read or Write waits for the handshake to end. After it they
// are the deadlines of the connection.
type deadlines struct {
	mu      sync.Mutex
	conn    net.Conn
	read    time.Time
	write   time.Time
	applied bool          // the handshake is over
	changed chan struct{} // closed when a deadline is set before that
}

// set changes the deadlines of the caller that are not nil.
func (d *deadlines) set(read, write *time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if read != nil {
		d.read = *read
	}
	if write != nil {
		d.write = *write
	}
	if !d.applied {
		// whoever waits for the handshake looks at its deadline again
		close(d.changed)
		d.changed = make(chan struct{})
		return nil
	}
	if read != nil {
		if err := d.conn.SetReadDeadline(d.read); err != nil {
			return err
		}
	}
	if write != nil {
		return d.conn.SetWriteDeadline(d.write)
	}
	return nil
}

// handOver gives the connection the deadlines of the caller.
func (d *deadlines) handOver() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.applied = true
	if err := d.conn.SetReadDeadline(d.read); err != nil {
		return err
	}
	return d.conn.SetWriteDeadline(d.write)
}

// wait returns when done is closed, or with a timeout error when the read or
// the write deadline of the caller passes first.
func (d *deadlines) wait(done <-chan struct{}, read bool) error {
	for {
		d.mu.Lock()
		deadline, changed := d.write, d.changed
		if read {
			deadline = d.read
		}
		d.mu.Unlock()
		timer := time.NewTimer(time.Until(deadline))
		expired := timer.C
		if deadline.IsZero() {
			expired = nil // no deadline
		}
		select {
		case <-done:
			timer.Stop()
			return nil
		case <-expired:
			select {
			case <-done: // both happened: the connection tells about the deadline
				return nil
			default:
				return os.ErrDeadlineExceeded
			}
		case <-changed:
			timer.Stop()
		}
	}
}
