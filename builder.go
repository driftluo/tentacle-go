package tentacle

import (
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
	"github.com/libp2p/go-msgio"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

// Codec use on protocol stream to en/decode message
type Codec interface {
	// ReadMsg reads the next message from the Reader
	ReadMsg() ([]byte, error)
	// WriteMsg writes the msg in the passed
	WriteMsg([]byte) error
	io.Closer
}

// CodecFn generate a codec
type CodecFn func(net.Conn) Codec

// BeforeSend unified processing of messages before they are sent
type BeforeSend func([]byte) []byte

// BeforeReceive unified processing of messages before user received
type BeforeReceive func([]byte) []byte

// SessionProtocolFn generate SessionProtocol
type SessionProtocolFn func() SessionProtocol

// DefaultCodec use by default, is a LengthDelimitedCodec
var DefaultCodec = func(conn net.Conn) Codec {
	return msgio.Combine(msgio.NewWriter(conn), msgio.NewReader(conn))
}

// DefaultBeforeSend use by default, do nothing
var DefaultBeforeSend = func(b []byte) []byte {
	return b
}

// DefaultBeforeReceive use by default, do nothing
var DefaultBeforeReceive = func(b []byte) []byte {
	return b
}

// MetaBuilder builder for protocol meta
type MetaBuilder struct {
	id              ProtocolID
	name            NameFn
	supportVersions []string
	codec           CodecFn
	serviceHandle   ServiceProtocol
	sessionHandle   SessionProtocolFn
	selectVersion   SelectFn
	beforeSend      BeforeSend
	beforeReceive   BeforeReceive
}

// DefaultMeta make a default builder
func DefaultMeta() *MetaBuilder {
	return &MetaBuilder{
		id:              ProtocolID(0),
		name:            DefaultNameFn,
		supportVersions: []string{"0.0.1"},
		codec:           DefaultCodec,
		serviceHandle:   nil,
		sessionHandle:   nil,
		selectVersion:   SelectVersion,
		beforeSend:      DefaultBeforeSend,
		beforeReceive:   DefaultBeforeReceive,
	}
}

// ID define protocol id
//
// It is just an internal index of the system that
// identifies the open/close and message transfer for the specified protocol.
func (m *MetaBuilder) ID(pid ProtocolID) *MetaBuilder {
	m.id = pid
	return m
}

// Name define protocol name, default is "/p2p/protocol_id"
//
// Used to interact with the remote service to determine whether the protocol is supported.
//
// If not found, the protocol connection(not session just sub stream) will be closed,
// and return a `ProtocolSelectError` event.
func (m *MetaBuilder) Name(name NameFn) *MetaBuilder {
	m.name = name
	return m
}

// SupportVersions define protocol support versions, default is `[]string{"0.0.1"}`
//
// Used to interact with the remote service to confirm that both parties
// open the same version of the protocol.
//
// If not found, the protocol connection(not session just sub stream) will be closed,
// and return a `ProtocolSelectError` event.
func (m *MetaBuilder) SupportVersions(versions []string) *MetaBuilder {
	m.supportVersions = versions
	return m
}

// Codec define protocol codec, default is LengthDelimitedCodec
func (m *MetaBuilder) Codec(codec CodecFn) *MetaBuilder {
	m.codec = codec
	return m
}

// ServiceHandle define protocol service handle, default is nil
func (m *MetaBuilder) ServiceHandle(service ServiceProtocol) *MetaBuilder {
	m.serviceHandle = service
	return m
}

// SessionHandle define protocol session handle, default is nil
func (m *MetaBuilder) SessionHandle(sessionFn SessionProtocolFn) *MetaBuilder {
	m.sessionHandle = sessionFn
	return m
}

// SelectVersion protocol version selection rule, default is `SelectVersion`
func (m *MetaBuilder) SelectVersion(selectfn SelectFn) *MetaBuilder {
	m.selectVersion = selectfn
	return m
}

// BeforeSend unified processing of messages before user received
func (m *MetaBuilder) BeforeSend(beforeSend BeforeSend) *MetaBuilder {
	m.beforeSend = beforeSend
	return m
}

// BeforeReceive unified processing of messages before user received
func (m *MetaBuilder) BeforeReceive(beforeRecv BeforeReceive) *MetaBuilder {
	m.beforeReceive = beforeRecv
	return m
}

// Build combine the configuration of this builder to create a ProtocolMeta
func (m *MetaBuilder) Build() ProtocolMeta {
	return ProtocolMeta{
		inner: &meta{
			id:              m.id,
			name:            m.name,
			supportVersions: m.supportVersions,
			codec:           m.codec,
			selectVersion:   m.selectVersion,
			beforeReceive:   m.beforeReceive,
		},
		serviceHandle:   m.serviceHandle,
		sessionHandleFn: m.sessionHandle,
		beforeSend:      m.beforeSend,
	}
}

// ServiceBuilder builder for Service
type ServiceBuilder struct {
	inner   map[ProtocolID]ProtocolMeta
	keyPair secio.PrivKey
	forever bool
	config  serviceConfig
}

// DefaultServiceBuilder create a default empty builder
func DefaultServiceBuilder() *ServiceBuilder {
	return &ServiceBuilder{
		inner:   make(map[ProtocolID]ProtocolMeta),
		keyPair: nil,
		forever: false,
		config: serviceConfig{
			timeout:             10 * time.Second,
			yamuxConfig:         yamux.DefaultConfig(),
			maxConnectionNumber: 65535,
		},
	}
}

// InsertProtocol insert a custom protocol
func (s *ServiceBuilder) InsertProtocol(protocol ProtocolMeta) *ServiceBuilder {
	s.inner[protocol.inner.id] = protocol
	return s
}

// KeyPair enable encrypted communication mode.
//
// If you do not need encrypted communication, you do not need to call this method
func (s *ServiceBuilder) KeyPair(key secio.PrivKey) *ServiceBuilder {
	s.keyPair = key
	return s
}

// Forever when the service has no tasks, it will be turned off by default.
// If you do not want to close service, set it to true.
func (s *ServiceBuilder) Forever(forever bool) *ServiceBuilder {
	s.forever = forever
	return s
}

// TimeOut for handshake and connect
// Default 10 second
func (s *ServiceBuilder) TimeOut(timeout time.Duration) *ServiceBuilder {
	s.config.timeout = timeout
	return s
}

// YamuxConfig for service
func (s *ServiceBuilder) YamuxConfig(config *yamux.Config) *ServiceBuilder {
	s.config.yamuxConfig = config
	return s
}

// MaxConnectionNumber the limit of max open connection(file descriptors)
// If not limited, service will try to serve as many connections as possible until it exhausts system resources(os error),
// and then close the listener, no longer accepting new connection requests, and the established connections remain working
//
// Default is 65535
func (s *ServiceBuilder) MaxConnectionNumber(num uint) *ServiceBuilder {
	s.config.maxConnectionNumber = num
	return s
}

// Build combine the configuration of this builder with service handle to create a Service.
func (s *ServiceBuilder) Build(handle ServiceHandle) *Service {
	var state *serviceState

	if s.forever {
		state = &serviceState{tag: forever}
	} else {
		state = &serviceState{tag: running, workers: 0}
	}

	quickTask := make(chan serviceTask, sendSize)
	task := make(chan serviceTask, sendSize)
	sessionChan := make(chan sessionEvent, sendSize)

	shutdown := atomic.Value{}
	shutdown.Store(false)

	service := service{
		protoclConfigs: s.inner,
		serviceContext: &ServiceContext{
			Listens: []ma.Multiaddr{},
			Key:     s.keyPair,

			quickTaskSender: quickTask,
			taskSender:      task,
		},
		state: state,

		listens:       make(map[ma.Multiaddr]manet.Listener),
		dialProtocols: make(map[ma.Multiaddr]TargetProtocol),
		config:        s.config,
		nextSession:   SessionID(0),
		beforeSends:   make(map[ProtocolID]BeforeSend),

		handle:              handle,
		serviceProtoHandles: make(map[ProtocolID]chan<- serviceProtocolEvent),
		sessionProtoHandles: make(map[sessionProto]chan<- sessionProtocolEvent),
		sessionEventChan:    sessionChan,
		sessions:            make(map[SessionID]sessionController),
		taskReceiver:        task,
		quickTaskReceiver:   quickTask,

		shutdown: shutdown,
	}

	go service.run()

	return service.control()
}
