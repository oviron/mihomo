package muxcool

import (
	"net"

	"github.com/metacubex/mihomo/common/net/deadline"
)

// Handler takes the sessions a peer opens on a carrier. meta is the frame
// that opened the session: its Target is where the peer wants to go, and its
// Source and Local, when the peer is a reverse proxy portal, are the
// endpoints of the connection the portal received.
//
// Both methods are called on a goroutine of their own and own the connection.
type Handler interface {
	// NewStream takes a TCP session.
	NewStream(conn net.Conn, meta Metadata)
	// NewPacket takes a UDP session. ReadFrom returns the address a packet is
	// meant for, WriteTo takes the address a reply comes from.
	NewPacket(conn net.PacketConn, meta Metadata)
}

// NewServerCarrier starts Mux.Cool on conn in the role that accepts sessions.
// reverse says that the peer is the portal of a reverse proxy, whose sessions
// name the endpoints of the original connection. The carrier owns conn; it
// stays open until Close or until conn fails.
func NewServerCarrier(conn net.Conn, handler Handler, reverse bool) *Carrier {
	c := &Carrier{
		conn:         conn,
		handler:      handler,
		reverse:      reverse,
		writeTimeout: defaultWriteTimeout,
		sessions:     make(map[uint16]*session),
		done:         make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// accept registers a session the peer opened. A session that still has the
// ID is over as far as the peer is concerned.
func (c *Carrier) accept(meta *Metadata) *session {
	c.mu.Lock()
	old := c.sessions[meta.SessionID]
	delete(c.sessions, meta.SessionID)
	c.mu.Unlock()
	if old != nil {
		old.fail(ErrSessionClosed)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil
	}
	s := &session{
		accepted:    true,
		carrier:     c,
		id:          meta.SessionID,
		network:     meta.Target.Network,
		destination: meta.Target.Addr,
		readable:    make(chan struct{}, 1),
		writable:    make(chan struct{}, 1),
		failed:      make(chan struct{}),
		closed:      make(chan struct{}),
	}
	s.opened.Store(true) // the peer sent the new frame
	c.count++
	c.sessions[s.id] = s
	return s
}

func (c *Carrier) serve(s *session, meta Metadata) {
	if s.network == NetworkUDP {
		go c.handler.NewPacket(&packetConn{session: s, deadline: deadline.MakePipeDeadline()}, meta)
	} else {
		go c.handler.NewStream(&streamConn{session: s, deadline: deadline.MakePipeDeadline()}, meta)
	}
}
