package tentacle

import (
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/yamux"
)

// NameFn define protocol name, default is "/p2p/protocol_id"
//
// Used to interact with the remote service to determine whether the protocol is supported.
//
// If not found, the protocol connection(not session just sub stream) will be closed,
// and return a `ProtocolSelectError` event.
type NameFn = func(ProtocolID) string

var defaultNameFn = func(id ProtocolID) string {
	return fmt.Sprintf("/p2p/%s", strconv.Itoa(int(id)))
}

type meta struct {
	id              ProtocolID
	name            NameFn
	supportVersions []string
	codec           CodecFn
	selectVersion   SelectFn
	beforeReceive   BeforeReceive
}

// ProtocolMeta define the minimum data required for a custom protocol
type ProtocolMeta struct {
	inner         *meta
	serviceHandle ServiceProtocol
	sessionHandle SessionProtocol
	beforeSend    BeforeSend
}

type serviceConfig struct {
	timeout             time.Duration
	yamuxConfig         *yamux.Config
	maxConnectionNumber uint
}

const (
	// All try open all protocol, target is nil
	All uint = iota
	// Single try open one protocol, target is ProtocolID
	Single
	// Multi try open some protocol, target is []ProtocolID
	Multi
)

// TargetProtocol when dial, specify which protocol want to open
type TargetProtocol struct {
	// must use All/Single/Try
	Tag    uint
	Target interface{}
}

const (
	running uint8 = iota
	forever
	preShutdown
)

type serviceState struct {
	workers uint
	tag     uint8
}

func (s *serviceState) decrease() {
	switch s.tag {
	case running:
		s.workers--
	}
}

func (s *serviceState) increase() {
	switch s.tag {
	case running:
		s.workers++
	}
}

func (s *serviceState) preShutdown() {
	s.tag = preShutdown
}

func (s *serviceState) isShutdown() bool {
	var res bool
	switch s.tag {
	case running:
		res = s.workers == 0
	case preShutdown:
		res = true
	case forever:
		res = false
	}
	return res
}
