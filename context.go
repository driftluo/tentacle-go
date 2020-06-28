package tentacle

import (
	"errors"
	"net"
	"time"

	"github.com/driftluo/tentacle-go/secio"
)

// ErrBrokenPipe service has been shutdown
var ErrBrokenPipe = errors.New("BrokenPipe")

const (
	// Outbound representing yourself as the active party means that you are the client side
	Outbound uint8 = iota
	// Inbound representing yourself as a passive recipient means that you are the server side
	Inbound
)

// SessionID index of session
type SessionID uint

// SessionContext context with current session
type SessionContext struct {
	// Sid session id
	Sid SessionID
	// Outbound or Inbound
	Ty uint8
	// remote addr
	RemoteAddr net.Addr
	// remote pubkey, may nil on no secio mode
	RemotePub secio.PubKey
	closed    bool
}

// ServiceContext context with current service
type ServiceContext struct {
	Listens []net.Addr
	Key     secio.PrivKey

	quickTaskReceiver chan<- serviceTask
	taskReceiver      chan<- serviceTask
}

func (s *ServiceContext) sendInner(sender chan<- serviceTask, event serviceTask) {
	protectRun(func() { sender <- event }, nil)
}

func (s *ServiceContext) quickSend(event serviceTask) {
	s.sendInner(s.quickTaskReceiver, event)
}

func (s *ServiceContext) send(event serviceTask) {
	s.sendInner(s.quickTaskReceiver, event)
}

// ListenAsync try create a new listener, if service is shutdown, return error
func (s *ServiceContext) ListenAsync(addr net.Addr) {
	s.quickSend(serviceTask{tag: taskListen, event: addr})
}

// Dial initiate a connection request to address
func (s *ServiceContext) Dial(addr net.Addr, target TargetProtocol) {
	s.quickSend(serviceTask{tag: taskDial, event: taskDialInner{addr: addr, target: target}})
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
	closed *bool

	quickTaskReceiver chan<- serviceTask
	taskReceiver      chan<- serviceTask
}

func (s *Service) sendInner(sender chan<- serviceTask, event serviceTask) {
	protectRun(func() { sender <- event }, nil)
}

func (s *Service) quickSend(event serviceTask) error {
	if *s.closed {
		return ErrBrokenPipe
	}
	s.sendInner(s.quickTaskReceiver, event)
	return nil
}

func (s *Service) send(event serviceTask) error {
	if *s.closed {
		return ErrBrokenPipe
	}
	s.sendInner(s.quickTaskReceiver, event)
	return nil
}

// Listen create a new listener, blocking here util listen finished and return listen addr
func (s *Service) Listen(addr net.Addr) (net.Addr, error) {
	listener, err := net.Listen(addr.Network(), addr.String())

	if err != nil {
		return nil, err
	}

	err = s.quickSend(serviceTask{tag: taskListenStart, event: listenStartInner{addr: listener.Addr(), listener: listener}})

	if err != nil {
		return nil, err
	}
	s.state.increase()
	return listener.Addr(), nil
}

// ListenAsync try create a new listener, if service is shutdown, return error
func (s *Service) ListenAsync(addr net.Addr) error {
	return s.quickSend(serviceTask{tag: taskListen, event: addr})
}

// Dial initiate a connection request to address
func (s *Service) Dial(addr net.Addr, target TargetProtocol) error {
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
