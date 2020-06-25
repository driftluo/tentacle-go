package tentacle

import (
	"net"

	"github.com/driftluo/tentacle-go/secio"
)

const (
	// Outbound representing yourself as the active party means that you are the client side
	Outbound uint = iota
	// Inbound representing yourself as a passive recipient means that you are the server side
	Inbound
)

// SessionID index of session
type SessionID uint

// SessionContext context with current session
type SessionContext struct {
	id SessionID
	// Outbound or Inbound
	ty         uint
	remoteAddr net.Addr
	remotePub  secio.PublicKey
	closed     bool
}

// ServiceContext context with current service
type ServiceContext struct {
	listens []net.Addr
	key     secio.PrivKey
}

// ProtocolContext context with current protocol
type ProtocolContext struct {
	*ServiceContext
	pid ProtocolID
}

func (c *ProtocolContext) toRef(s *SessionContext) *ProtocolContextRef {
	return &ProtocolContextRef{c, s}
}

// ProtocolContextRef context with current protocol and session
type ProtocolContextRef struct {
	*ProtocolContext
	*SessionContext
}
