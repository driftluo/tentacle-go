package tentacle

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

// ErrBrokenPipe service has been shutdown
var ErrBrokenPipe = errors.New("BrokenPipe")

// ErrNotSupport protocol doesn't support
var ErrNotSupport = errors.New("Protocol doesn't support")

// SessionType Outbound or Inbound
// Outbound representing yourself as the active party means that you are the client side
// Inbound representing yourself as a passive recipient means that you are the server side
type SessionType uint8

// Name type name
func (t *SessionType) Name() string {
	if *t == SessionType(0) {
		return "Outbound"
	}
	return "Inbound"
}

func (t *SessionType) String() string {
	return t.Name()
}

// SessionID index of session
type SessionID uint

// SessionContext context with current session
type SessionContext struct {
	// Sid session id
	Sid SessionID
	// Outbound or Inbound
	Ty SessionType
	// remote addr
	RemoteAddr ma.Multiaddr
	// remote pubkey, may nil on no secio mode
	RemotePub secio.PubKey
	closed    atomic.Value
}

// ServiceContext context with current service
type ServiceContext struct {
	Listens []ma.Multiaddr
	Key     secio.PrivKey

	quickTaskSender chan<- serviceTask
	taskSender      chan<- serviceTask
}

func (s *ServiceContext) sendInner(sender chan<- serviceTask, event serviceTask) {
	protectRun(func() { sender <- event }, nil)
}

func (s *ServiceContext) quickSend(event serviceTask) {
	s.sendInner(s.quickTaskSender, event)
}

func (s *ServiceContext) send(event serviceTask) {
	s.sendInner(s.taskSender, event)
}

// ListenAsync try create a new listener, if addr not support, return error
func (s *ServiceContext) ListenAsync(addr ma.Multiaddr) error {
	if !isSupport(addr) {
		return ErrNotSupport
	}
	s.quickSend(serviceTask{tag: taskListen, event: addr})
	return nil
}

// Dial initiate a connection request to address, if addr not support, return error
func (s *ServiceContext) Dial(addr ma.Multiaddr, target TargetProtocol) error {
	if !isSupport(addr) {
		return ErrNotSupport
	}
	s.quickSend(serviceTask{tag: taskDial, event: taskDialInner{addr: addr, target: target}})
	return nil
}

// Disconnect a connection
func (s *ServiceContext) Disconnect(id SessionID) {
	s.quickSend(serviceTask{tag: taskDisconnect, event: id})
}

// SendMessageTo send message
func (s *ServiceContext) SendMessageTo(id SessionID, pid ProtocolID, data []byte) {
	s.FilterBroadcast(TargetSession{Tag: Single, Target: id}, pid, data)
}

// QuickSendMessageTo send message on quick channel
func (s *ServiceContext) QuickSendMessageTo(id SessionID, pid ProtocolID, data []byte) {
	s.QuickFilterBroadcast(TargetSession{Tag: Single, Target: id}, pid, data)
}

// FilterBroadcast send data to the specified protocol for the specified sessions.
func (s *ServiceContext) FilterBroadcast(target TargetSession, pid ProtocolID, data []byte) {
	s.send(serviceTask{tag: taskProtocolMessage, event: taskProtocolMessageInner{target: target, pid: pid, data: data}})
}

// QuickFilterBroadcast send data to the specified protocol for the specified sessions on quick channel
func (s *ServiceContext) QuickFilterBroadcast(target TargetSession, pid ProtocolID, data []byte) {
	s.quickSend(serviceTask{tag: taskProtocolMessage, event: taskProtocolMessageInner{target: target, pid: pid, data: data}})
}

// OpenProtocol try open a protocol, if the protocol has been open, do nothing
func (s *ServiceContext) OpenProtocol(sid SessionID, pid ProtocolID) {
	s.OpenProtocols(sid, TargetProtocol{Tag: Single, Target: pid})
}

// OpenProtocols try open protocols, if the protocol has been open, do nothing
func (s *ServiceContext) OpenProtocols(sid SessionID, target TargetProtocol) {
	s.quickSend(serviceTask{tag: taskProtocolOpen, event: taskProtocolOpenInner{sid: sid, target: target}})
}

// CloseProtocol try close a protocol, if the protocol has been closed, do nothing
func (s *ServiceContext) CloseProtocol(sid SessionID, pid ProtocolID) {
	s.quickSend(serviceTask{tag: taskProtocolClose, event: taskProtocolCloseInner{sid: sid, pid: pid}})
}

// SetServiceNotify set a service notify token
func (s *ServiceContext) SetServiceNotify(pid ProtocolID, interval time.Duration, token uint64) {
	s.send(serviceTask{tag: taskSetProtocolNotify, event: taskSetProtocolNotifyInner{pid: pid, interval: interval, token: token}})
}

// RemoveServiceNotify remove a service notify token
func (s *ServiceContext) RemoveServiceNotify(pid ProtocolID, token uint64) {
	s.send(serviceTask{tag: taskRemoveProtocolNotify, event: taskRemoveProtocolNotifyInner{pid: pid, token: token}})
}

// SetSessionNotify set a session notify token
func (s *ServiceContext) SetSessionNotify(sid SessionID, pid ProtocolID, interval time.Duration, token uint64) {
	s.send(serviceTask{tag: taskSetProtocolSessionNotify, event: taskSetProtocolSessionNotifyInner{sid: sid, pid: pid, interval: interval, token: token}})
}

// RemoveSessionNotify remove a session notify token
func (s *ServiceContext) RemoveSessionNotify(sid SessionID, pid ProtocolID, token uint64) {
	s.send(serviceTask{tag: taskRemoveProtocolSessionNotify, event: taskRemoveProtocolSessionNotifyInner{sid: sid, pid: pid, token: token}})
}

// Shutdown service,
// Order:
// 1. close all listens
// 2. try close all session's protocol stream
// 3. try close all session
// 4. close service
func (s *ServiceContext) Shutdown() {
	s.send(serviceTask{tag: taskShutdown})
}

// ProtocolContext context with current protocol
type ProtocolContext struct {
	*ServiceContext
	Pid ProtocolID
}

func (c *ProtocolContext) toRef(s *SessionContext) *ProtocolContextRef {
	return &ProtocolContextRef{c, s}
}

// ProtocolContextRef context with current protocol and session
type ProtocolContextRef struct {
	*ProtocolContext
	*SessionContext
}

// SendMessage send message to current protocol current session
func (c *ProtocolContextRef) SendMessage(data []byte) {
	c.SendMessageTo(c.Sid, c.Pid, data)
}

// QuickSendMessage send message to current protocol current session on quick channel
func (c *ProtocolContextRef) QuickSendMessage(data []byte) {
	c.QuickSendMessageTo(c.Sid, c.Pid, data)
}

type sessionController struct {
	quickSender chan<- sessionEvent
	eventSender chan<- sessionEvent
	inner       *SessionContext
}

// Service user handle
type Service struct {
	state  *serviceState
	key    secio.PrivKey
	closed *atomic.Value
	config *serviceConfig

	quickTaskSender chan<- serviceTask
	taskSender      chan<- serviceTask
}

func (s *Service) sendInner(sender chan<- serviceTask, event serviceTask) {
	protectRun(func() { sender <- event }, nil)
}

func (s *Service) quickSend(event serviceTask) error {
	if s.closed.Load().(bool) {
		return ErrBrokenPipe
	}
	s.sendInner(s.quickTaskSender, event)
	return nil
}

func (s *Service) send(event serviceTask) error {
	if s.closed.Load().(bool) {
		return ErrBrokenPipe
	}
	s.sendInner(s.taskSender, event)
	return nil
}

// Key get local private key
func (s *Service) Key() secio.PrivKey {
	return s.key
}

// Listen create a new listener, blocking here util listen finished and return listen addr
func (s *Service) Listen(addr ma.Multiaddr) (ma.Multiaddr, error) {
	if !isSupport(addr) {
		return nil, ErrNotSupport
	}
	listener, err := multiListen(addr, s.config.timeout)
	if err != nil {
		return nil, err
	}

	err = s.quickSend(serviceTask{tag: taskListenStart, event: listenStartInner{listener: listener}})

	if err != nil {
		return nil, err
	}
	s.state.increase()
	return listener.Multiaddr(), nil
}

// ListenAsync try create a new listener, if service is shutdown/addr not support, return error
func (s *Service) ListenAsync(addr ma.Multiaddr) error {
	if !isSupport(addr) {
		return ErrNotSupport
	}
	return s.quickSend(serviceTask{tag: taskListen, event: addr})
}

// Dial initiate a connection request to address, if service is shutdown/addr not support, return error
func (s *Service) Dial(addr ma.Multiaddr, target TargetProtocol) error {
	if !isSupport(addr) {
		return ErrNotSupport
	}
	return s.quickSend(serviceTask{tag: taskDial, event: taskDialInner{addr: addr, target: target}})
}

// Disconnect a connection
func (s *Service) Disconnect(id SessionID) error {
	return s.quickSend(serviceTask{tag: taskDisconnect, event: id})
}

// SendMessageTo send message
func (s *Service) SendMessageTo(id SessionID, pid ProtocolID, data []byte) error {
	return s.FilterBroadcast(TargetSession{Tag: Single, Target: id}, pid, data)
}

// QuickSendMessageTo send message on quick channel
func (s *Service) QuickSendMessageTo(id SessionID, pid ProtocolID, data []byte) error {
	return s.QuickFilterBroadcast(TargetSession{Tag: Single, Target: id}, pid, data)
}

// FilterBroadcast send data to the specified protocol for the specified sessions.
func (s *Service) FilterBroadcast(target TargetSession, pid ProtocolID, data []byte) error {
	return s.send(serviceTask{tag: taskProtocolMessage, event: taskProtocolMessageInner{target: target, pid: pid, data: data}})
}

// QuickFilterBroadcast send data to the specified protocol for the specified sessions on quick channel
func (s *Service) QuickFilterBroadcast(target TargetSession, pid ProtocolID, data []byte) error {
	return s.quickSend(serviceTask{tag: taskProtocolMessage, event: taskProtocolMessageInner{target: target, pid: pid, data: data}})
}

// OpenProtocol try open a protocol, if the protocol has been open, do nothing
func (s *Service) OpenProtocol(sid SessionID, pid ProtocolID) error {
	return s.OpenProtocols(sid, TargetProtocol{Tag: Single, Target: pid})
}

// OpenProtocols try open protocols, if the protocol has been open, do nothing
func (s *Service) OpenProtocols(sid SessionID, target TargetProtocol) error {
	return s.quickSend(serviceTask{tag: taskProtocolOpen, event: taskProtocolOpenInner{sid: sid, target: target}})
}

// CloseProtocol try close a protocol, if the protocol has been closed, do nothing
func (s *Service) CloseProtocol(sid SessionID, pid ProtocolID) error {
	return s.quickSend(serviceTask{tag: taskProtocolClose, event: taskProtocolCloseInner{sid: sid, pid: pid}})
}

// SetServiceNotify set a service notify token
func (s *Service) SetServiceNotify(pid ProtocolID, interval time.Duration, token uint64) error {
	return s.send(serviceTask{tag: taskSetProtocolNotify, event: taskSetProtocolNotifyInner{pid: pid, interval: interval, token: token}})
}

// RemoveServiceNotify remove a service notify token
func (s *Service) RemoveServiceNotify(pid ProtocolID, token uint64) error {
	return s.send(serviceTask{tag: taskRemoveProtocolNotify, event: taskRemoveProtocolNotifyInner{pid: pid, token: token}})
}

// SetSessionNotify set a session notify token
func (s *Service) SetSessionNotify(sid SessionID, pid ProtocolID, interval time.Duration, token uint64) error {
	return s.send(serviceTask{tag: taskSetProtocolSessionNotify, event: taskSetProtocolSessionNotifyInner{sid: sid, pid: pid, interval: interval, token: token}})
}

// RemoveSessionNotify remove a session notify token
func (s *Service) RemoveSessionNotify(sid SessionID, pid ProtocolID, token uint64) error {
	return s.send(serviceTask{tag: taskRemoveProtocolSessionNotify, event: taskRemoveProtocolSessionNotifyInner{sid: sid, pid: pid, token: token}})
}

// Shutdown service,
// Order:
// 1. close all listens
// 2. try close all session's protocol stream
// 3. try close all session
// 4. close service
func (s *Service) Shutdown() error {
	return s.send(serviceTask{tag: taskShutdown})
}

// IsShutdown determine whether to shutdown
func (s *Service) IsShutdown() bool {
	return s.closed.Load().(bool)
}
