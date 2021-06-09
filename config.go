package tentacle

import (
	"fmt"
	"strconv"
	"sync"
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

// DefaultNameFn default protocol name
var DefaultNameFn = func(id ProtocolID) string {
	return fmt.Sprintf("/p2p/%s", strconv.Itoa(int(id)))
}

type meta struct {
	id              ProtocolID
	name            NameFn
	supportVersions []string
	codec           CodecFn
	selectVersion   SelectFn
	beforeReceive   BeforeReceive
	spawn           ProtocolSpawn
}

// ProtocolMeta define the minimum data required for a custom protocol
type ProtocolMeta struct {
	inner           *meta
	serviceHandle   ServiceProtocol
	sessionHandleFn SessionProtocolFn
	beforeSend      BeforeSend
}

type serviceConfig struct {
	timeout             time.Duration
	yamuxConfig         *yamux.Config
	maxConnectionNumber uint
	tcpBind             *string
	wsBind              *string
}

const (
	// All try open all protocol, target is nil
	All uint8 = iota
	// Single try open one protocol, target is ProtocolID/SessionID
	Single
	// Multi try open some protocol, target is []ProtocolID/[]SessionID
	Multi
)

// TargetProtocol when dial, specify which protocol want to open
type TargetProtocol struct {
	// must use All/Single/Multi
	Tag    uint8
	Target interface{}
}

// TargetSession when sending a message, select the specified session
type TargetSession struct {
	// must use All/Single/Multi
	Tag    uint8
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
	sync.Mutex
}

func (s *serviceState) decrease() {
	s.Lock()
	defer s.Unlock()
	switch s.tag {
	case running:
		s.workers--
	}
}

func (s *serviceState) increase() {
	s.Lock()
	defer s.Unlock()
	switch s.tag {
	case running:
		s.workers++
	}
}

func (s *serviceState) preShutdown() {
	s.Lock()
	defer s.Unlock()
	s.tag = preShutdown
}

func (s *serviceState) isShutdown() bool {
	s.Lock()
	defer s.Unlock()
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

func (s *serviceState) inner() uint {
	switch s.tag {
	case running:
		return s.workers
	default:
		return 0
	}
}
