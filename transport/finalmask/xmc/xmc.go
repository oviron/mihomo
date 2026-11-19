// Package xmc is the "xmc" TCP mask of Xray-core's finalmask: the connection
// looks like a Minecraft Java Edition client (protocol 775, Minecraft 26.1.2)
// logging in to a server and joining the world.
//
// The client sends the Handshake and Login Start packets with one of the
// configured player profiles, the server answers with an Encryption Request
// carrying an RSA key that both sides derive from the password, the client
// returns the session key and the password encrypted with it, and from then
// on both directions are AES-128-CFB8 as in the game. The server confirms the
// login with the signed profile of the player, the two sides exchange padding
// shaped like the traffic of a player joining, and after that the payload
// travels in plugin message packets of the "xmc:data" channel, with the
// server's keep-alive packets answered in between.
//
// The server needs the same settings.
package xmc

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/metacubex/mihomo/transport/finalmask/mask"

	"github.com/gofrs/uuid/v5"
)

func init() {
	mask.RegisterTCP("xmc", func(settings map[string]any) (mask.TCPMask, error) {
		return New(settings)
	})
}

// Options are the settings of the mask.
type Options struct {
	// Password is the secret shared with the server.
	Password string `mask:"password,omitempty"`
	// Hostname is the server address the client names in its Handshake
	// packet; when empty it is the address the connection goes to.
	Hostname string `mask:"hostname,omitempty"`
	// Profiles are the players the client logs in as, one picked at random
	// for every connection. The server must have every one of them.
	Profiles []ProfileOptions `mask:"profiles,omitempty"`
}

// ProfileOptions is a Minecraft account as the session server describes it
// (sessionserver.mojang.com/session/minecraft/profile/<uuid>?unsigned=false):
// the name, the UUID and the signed "textures" property.
type ProfileOptions struct {
	Username          string `mask:"username,omitempty"`
	UUID              string `mask:"uuid,omitempty"`
	TexturesValue     string `mask:"textures-value,omitempty"`
	TexturesSignature string `mask:"textures-signature,omitempty"`
}

type profile struct {
	username          string
	uuid              [16]byte
	texturesValue     string
	texturesSignature string
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

// Mask is a parsed xmc mask.
type Mask struct {
	password string
	hostname string
	profiles []profile
	key      *serverKey
}

// New builds the mask from its settings.
func New(settings map[string]any) (*Mask, error) {
	var options Options
	if err := mask.Decode(settings, &options); err != nil {
		return nil, err
	}
	m := &Mask{password: options.Password, hostname: options.Hostname}
	if len(options.Profiles) == 0 {
		return nil, errors.New("profiles are required")
	}
	if m.password == "" {
		return nil, errors.New("empty password")
	}
	if len(m.password) > maxPasswordLength {
		return nil, fmt.Errorf("the password is %d bytes long, the protocol carries at most %d", len(m.password), maxPasswordLength)
	}
	if len(m.hostname) > maxString {
		return nil, fmt.Errorf("the hostname is longer than %d bytes", maxString)
	}
	for i, p := range options.Profiles {
		if !usernamePattern.MatchString(p.Username) {
			return nil, fmt.Errorf("profiles[%d]: invalid username %q", i, p.Username)
		}
		id, err := parseUUID(p.UUID)
		if err != nil {
			return nil, fmt.Errorf("profiles[%d]: invalid uuid: %w", i, err)
		}
		if p.TexturesValue == "" || p.TexturesSignature == "" {
			return nil, fmt.Errorf("profiles[%d]: textures-value and textures-signature are required", i)
		}
		// The server sends them back as strings, which have this limit.
		if len(p.TexturesValue) > maxString || len(p.TexturesSignature) > maxString {
			return nil, fmt.Errorf("profiles[%d]: the textures are longer than %d bytes", i, maxString)
		}
		m.profiles = append(m.profiles, profile{
			username:          p.Username,
			uuid:              id,
			texturesValue:     p.TexturesValue,
			texturesSignature: p.TexturesSignature,
		})
	}
	// Derived here and not for every connection: it takes a prime search.
	key, err := keyFor(m.password)
	if err != nil {
		return nil, fmt.Errorf("derive the server key: %w", err)
	}
	m.key = key
	return m, nil
}

// parseUUID reads a UUID in the spellings Xray-core takes: 32 hex digits, the
// form with dashes, and that form in braces or after "urn:uuid:".
func parseUUID(s string) (uuid.UUID, error) {
	switch {
	case len(s) == 36+9 && strings.EqualFold(s[:9], "urn:uuid:"):
		s = s[9:]
	case len(s) == 36+2 && s[0] == '{' && s[37] == '}':
		s = s[1:37]
	case len(s) != 36 && len(s) != 32:
		return uuid.Nil, fmt.Errorf("%q is not a UUID", s)
	}
	return uuid.FromString(s)
}

// WrapConn returns a connection that logs in on its first Read or Write.
func (m *Mask) WrapConn(conn net.Conn) (net.Conn, error) {
	return &Conn{
		conn:          conn,
		mask:          m,
		wire:          wire{r: bufio.NewReader(conn), w: conn},
		burst:         pickBurst(),
		deadlines:     deadlines{conn: conn, changed: make(chan struct{})},
		handshakeDone: make(chan struct{}),
		echoes:        make(chan [8]byte, 32),
		closed:        make(chan struct{}),
	}, nil
}
