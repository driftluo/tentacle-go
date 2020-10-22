package tentacle

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// ErrHandshakeTimeout secio handshake timeout
var ErrHandshakeTimeout = errors.New("Handshake timeout")

// ErrDialTimeout dial timeout
var ErrDialTimeout = errors.New("dial timeout")

// ErrListenerTimeout listen timeout
var ErrListenerTimeout = errors.New("listen timeout")

const receiveSize uint = 512

type sessionProto struct {
	sid SessionID
	pid ProtocolID
}

const (
	// Event from user
	external uint8 = iota
	// Event from session
	internal
)

const (
	high uint8 = iota
	low
)

type serviceListener struct {
	shutdown       *atomic.Value
	listener       manet.Listener
	eventSender    chan<- sessionEvent
	config         serviceConfig
	serviceContext *ServiceContext
}

func (s *serviceListener) run() {
	for {
		if s.shutdown.Load().(bool) {
			break
		}

		conn, err := s.listener.Accept()

		if err != nil {
			if s.shutdown.Load().(bool) {
				return
			}
			defer s.listener.Close()
			s.eventSender <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: IoError, Addr: s.listener.Multiaddr(), Inner: err}}
			return
		}
		go handshake(conn, SessionType(1), conn.RemoteMultiaddr(), s.serviceContext.Key, s.config.timeout, s.listener.Multiaddr(), s.eventSender)
	}
}

func handshake(conn manet.Conn, ty SessionType, remoteAddr ma.Multiaddr, selfKey secio.PrivKey, timeout time.Duration, listenAddr ma.Multiaddr, report chan<- sessionEvent) {
	// secio or not
	if selfKey != nil {
		resChan := make(chan sessionEvent)

		go func() {
			secConn, err := secio.NewConfig(selfKey).Handshake(conn)
			if err != nil {
				resChan <- sessionEvent{tag: handshakeError, event: handshakeErrorInner{ty: ty, err: err, remoteAddr: remoteAddr}}
				return
			}

			resChan <- sessionEvent{tag: handshakeSuccess, event: handshakeSuccessInner{ty: ty, conn: secConn, remoteAddr: remoteAddr, listenAddr: listenAddr, remotePubkey: secConn.RemotePub()}}
		}()

		select {
		case <-time.After(timeout):
			protectRun(
				func() {
					report <- sessionEvent{tag: handshakeError, event: handshakeErrorInner{ty: ty, err: ErrHandshakeTimeout, remoteAddr: remoteAddr}}
				},
				nil,
			)
		case event := <-resChan:
			protectRun(func() { report <- event }, nil)
		}

	} else {
		protectRun(
			func() {
				report <- sessionEvent{tag: handshakeSuccess, event: handshakeSuccessInner{ty: ty, conn: conn, remoteAddr: remoteAddr, listenAddr: listenAddr, remotePubkey: nil}}
			},
			nil,
		)
	}
}

type service struct {
	protoclConfigs map[ProtocolID]ProtocolMeta
	serviceContext *ServiceContext

	// service state
	state *serviceState

	// multi transport
	// upnp client

	listens       map[ma.Multiaddr]manet.Listener
	dialProtocols map[ma.Multiaddr]TargetProtocol
	config        serviceConfig
	nextSession   SessionID
	beforeSends   map[ProtocolID]BeforeSend

	handle ServiceHandle

	// Unified temporary storage
	serviceProtoHandles map[ProtocolID]chan<- serviceProtocolEvent
	sessionProtoHandles map[sessionProto]chan<- sessionProtocolEvent

	// Receive from sessions
	sessionEventChan chan sessionEvent

	// Distribute to sessions
	sessions map[SessionID]sessionController

	// External event receiver
	taskReceiver      <-chan serviceTask
	quickTaskReceiver <-chan serviceTask

	// Unable to use global variables, which can cause only one service to be started in a process
	once     sync.Once
	init     bool
	shutdown atomic.Value
}

func (s *service) run() {
	s.initServiceProtoHandles()
	for {
		if len(s.sessions) == 0 && len(s.listens) == 0 && s.state.isShutdown() && s.init {
			s.shutdown.Store(true)
			break
		}

		select {
		case event := <-s.quickTaskReceiver:
			s.handleServiceTask(event, high)
		default:
			select {
			case event := <-s.quickTaskReceiver:
				s.handleServiceTask(event, high)
			case event := <-s.taskReceiver:
				s.handleServiceTask(event, low)
			case event := <-s.sessionEventChan:
				s.handleSessionEvent(event)
			}
		}
	}
}

func (s *service) handleServiceTask(event serviceTask, priority uint8) {
	switch event.tag {
	case taskProtocolMessage:
		inner := event.event.(taskProtocolMessageInner)
		beforeSend := s.beforeSends[inner.pid]
		send := func(controller sessionController) {
			event := sessionEvent{tag: protocolMessage, event: protocolMessageInner{id: controller.inner.Sid, pid: inner.pid, data: beforeSend(inner.data)}}
			switch priority {
			case high:
				controller.quickSender <- event
			case low:
				controller.eventSender <- event
			}
		}

		switch inner.target.Tag {
		case All:
			for _, v := range s.sessions {
				send(v)
			}

		case Single:
			id, ok := inner.target.Target.(SessionID)
			if !ok {
				return
			}
			control, ok := s.sessions[id]
			if ok {
				send(control)
			}

		case Multi:
			ids, ok := inner.target.Target.([]SessionID)
			if !ok {
				return
			}
			for _, id := range ids {
				control, ok := s.sessions[id]
				if ok {
					send(control)
				}
			}
		}

	case taskProtocolOpen:
		inner := event.event.(taskProtocolOpenInner)
		switch inner.target.Tag {
		case All:
			for _, v := range s.protoclConfigs {
				s.protocolOpen(inner.sid, v.inner.id)
			}

		case Single:
			pid, ok := inner.target.Target.(ProtocolID)
			if !ok {
				return
			}
			s.protocolOpen(inner.sid, pid)

		case Multi:
			pids, ok := inner.target.Target.([]ProtocolID)
			if !ok {
				return
			}
			for _, pid := range pids {
				s.protocolOpen(inner.sid, pid)
			}
		}

	case taskProtocolClose:
		inner := event.event.(taskProtocolCloseInner)
		s.protocolClose(inner.sid, inner.pid)

	case taskDial:
		inner := event.event.(taskDialInner)
		_, ok := s.dialProtocols[inner.addr]
		if !ok {
			s.once.Do(func() {
				s.init = true
			})
			s.state.increase()
			s.dial(inner.addr, inner.target)
		}

	case taskListen:
		addr := event.event.(ma.Multiaddr)
		_, ok := s.listens[addr]
		if !ok {
			s.once.Do(func() {
				s.init = true
			})
			s.state.increase()
			go s.listen(addr)
		}

	case taskListenStart:
		s.once.Do(func() {
			s.init = true
		})
		inner := event.event.(listenStartInner)
		s.listenerstart(inner)

	case taskDisconnect:
		id := event.event.(SessionID)
		s.sessionClose(id, external)

	case taskSetProtocolNotify:
		inner := event.event.(taskSetProtocolNotifyInner)
		sender, ok := s.serviceProtoHandles[inner.pid]
		if ok {
			sender <- serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: inner.interval, token: inner.token}}
		}

	case taskRemoveProtocolNotify:
		inner := event.event.(taskRemoveProtocolNotifyInner)
		sender, ok := s.serviceProtoHandles[inner.pid]
		if ok {
			sender <- serviceProtocolEvent{tag: serviceProtocolRemoveNotify, event: inner.token}
		}

	case taskSetProtocolSessionNotify:
		inner := event.event.(taskSetProtocolSessionNotifyInner)
		sender, ok := s.sessionProtoHandles[sessionProto{sid: inner.sid, pid: inner.pid}]
		if ok {
			sender <- sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{token: inner.token, interval: inner.interval}}
		}

	case taskRemoveProtocolSessionNotify:
		inner := event.event.(taskRemoveProtocolSessionNotifyInner)
		sender, ok := s.sessionProtoHandles[sessionProto{sid: inner.sid, pid: inner.pid}]
		if ok {
			sender <- sessionProtocolEvent{tag: sessionProtocolRemoveNotify, event: inner.token}
		}

	case taskShutdown:
		s.state.preShutdown()
		for addr, listen := range s.listens {
			listen.Close()
			if s.handle != nil {
				s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenClose, Event: addr})
			}
		}
		s.listens = make(map[ma.Multiaddr]manet.Listener)

		for id := range s.sessions {
			s.sessionClose(id, external)
		}
		s.shutdown.Store(true)
	}
}

func (s *service) handleSessionEvent(event sessionEvent) {
	switch event.tag {
	case sessionClose:
		id := event.event.(SessionID)
		s.sessionClose(id, internal)

	case handshakeSuccess:
		inner := event.event.(handshakeSuccessInner)
		if inner.ty.Name() == "Outbound" {
			s.state.decrease()
		}
		if inner.ty.Name() == "Inbound" && len(s.sessions)+len(s.listens)+int(s.state.inner()) >= int(s.config.maxConnectionNumber) {
			defer inner.conn.Close()
			return
		}

		s.sessionOpen(inner.conn, inner.remotePubkey, inner.remoteAddr, inner.ty, inner.listenAddr)

	case handshakeError:
		inner := event.event.(handshakeErrorInner)
		if inner.ty.Name() == "Outbound" {
			s.state.decrease()
			delete(s.dialProtocols, inner.remoteAddr)
			if s.handle != nil {
				s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: HandshakeError, Inner: inner.err, Addr: inner.remoteAddr}})
			}
		}

	case protocolSelectError:
		inner := event.event.(protocolSelectErrorInner)
		control, ok := s.sessions[inner.id]
		if !ok {
			return
		}
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolSelectError, Event: ProtocolSelectErrorInner{Name: inner.protoName, Context: control.inner}})
		}

	case protocolHandleError:
		inner := event.event.(protocolHandleErrorInner)
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolHandleError, Event: ProtocolHandleErrorInner{PID: inner.pid, SID: inner.sid}})
		}
		s.handleServiceTask(serviceTask{tag: taskShutdown}, high)

	case protocolError:
		inner := event.event.(protocolErrorInner)
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolError, Event: ProtocolErrorInner{PID: inner.pid, SID: inner.id, Err: inner.err}})
		}

	case dialError:
		inner := event.event.(DialerErrorInner)
		s.state.decrease()
		delete(s.dialProtocols, inner.Addr)
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: inner})
		}

	case listenError:
		s.state.decrease()
		inner := event.event.(ListenErrorInner)
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: ListenError, Event: inner})
		}
		_, ok := s.listens[inner.Addr]
		if ok {
			deleteSlice(s.serviceContext.Listens, inner.Addr)
			delete(s.listens, inner.Addr)
			if s.handle != nil {
				s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenClose, Event: inner.Addr})
			}
		}

	case sessionTimeout:
		id := event.event.(SessionID)
		control, ok := s.sessions[id]
		if !ok {
			return
		}
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: SessionTimeout, Event: SessionTimeoutInner{Context: control.inner}})
		}

	case muxerError:
		inner := event.event.(muxerErrorInner)
		control, ok := s.sessions[inner.id]
		if !ok {
			return
		}
		if s.handle != nil {
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: MuxerError, Event: MuxerErrorInner{Context: control.inner, Err: inner.err}})
		}

	case listenStart:
		inner := event.event.(listenStartInner)
		s.listenerstart(inner)
	}
}

func (s *service) sessionOpen(conn net.Conn, remotePubkey secio.PubKey, remoteAddr ma.Multiaddr, ty SessionType, listenAddr ma.Multiaddr) {
	var target TargetProtocol
	var ok bool

	target, ok = s.dialProtocols[remoteAddr]
	if !ok {
		target = TargetProtocol{Tag: All}
	}
	delete(s.dialProtocols, remoteAddr)

	if remotePubkey != nil {
		// check if repeated connection
		for _, control := range s.sessions {
			if remotePubkey.Equals(control.inner.RemotePub) {
				defer conn.Close()
				switch ty.Name() {
				case "Outbound":
					if s.handle != nil {
						s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: RepeatedConnection, Inner: control.inner.Sid, Addr: remoteAddr}})
					}

				case "Inbound":
					if s.handle != nil {
						s.handle.HandleError(s.serviceContext, ServiceError{Tag: ListenError, Event: ListenErrorInner{Tag: RepeatedConnection, Inner: control.inner.Sid, Addr: listenAddr}})
					}
				}
				return
			}
		}
		// check peer id
		// if not match, output error and close
		// if not have, push its peer id to multiaddr
		peerid, err := ExtractPeerID(remoteAddr)
		if err != nil {
			paddr, _ := ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", remotePubkey.PeerID().Bese58String()))
			remoteAddr = remoteAddr.Encapsulate(paddr)
		} else {
			if !peerid.IsKey(remotePubkey) {
				defer conn.Close()
				if s.handle != nil {
					s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: PeerIDNotMatch, Addr: remoteAddr}})
				}
				return
			}
		}
	}

	for {
		s.nextSession++
		_, ok := s.sessions[s.nextSession]
		if !ok && s.nextSession != 0 {
			break
		}
	}

	quick := make(chan sessionEvent, sendSize)
	event := make(chan sessionEvent, sendSize)

	closed := atomic.Value{}
	closed.Store(false)

	control := sessionController{
		quickSender: quick,
		eventSender: event,
		inner: &SessionContext{
			Sid:        s.nextSession,
			RemoteAddr: remoteAddr,
			Ty:         ty,
			closed:     closed,
			RemotePub:  remotePubkey,
		},
	}
	// must insert here, otherwise, the session protocol handle cannot be opened
	s.sessions[s.nextSession] = control

	// open all session handles
	s.sessionHandlesOpen(s.nextSession)

	var socket *yamux.Session
	var sessionProtoConfigsByName = make(map[string]*meta)
	var sessionProtoConfigsByID = make(map[ProtocolID]*meta)
	var sessionProtoSenders = make(map[ProtocolID]chan<- sessionProtocolEvent)

	for k, v := range s.protoclConfigs {
		sessionProtoConfigsByName[v.inner.name(v.inner.id)] = v.inner
		sessionProtoConfigsByID[k] = v.inner
	}

	for k, v := range s.sessionProtoHandles {
		if k.sid == s.nextSession {
			sessionProtoSenders[k.pid] = v
		}
	}

	if ty.Name() == "Outbound" {
		socket, _ = yamux.Client(conn, s.config.yamuxConfig)
	} else {
		socket, _ = yamux.Server(conn, s.config.yamuxConfig)
	}

	state := atomic.Value{}
	state.Store(normal)

	session := session{
		socket:                socket,
		protocolConfigsByName: sessionProtoConfigsByName,
		protocolConfigsByID:   sessionProtoConfigsByID,
		context:               control.inner,
		nextStreamID:          streamID(0),
		protoStreams:          make(map[ProtocolID]streamID),
		serviceProtoSenders:   s.serviceProtoHandles,
		sessionProtoSenders:   sessionProtoSenders,
		sessionState:          state,
		timeout:               s.config.timeout,

		protoEventChan: make(chan protocolEvent, receiveSize),
		serviceSender:  s.sessionEventChan,

		subStreams:      make(map[streamID]chan<- protocolEvent),
		serviceReceiver: event,
		quickReceiver:   quick,
	}

	if ty.Name() == "Outbound" {
		openAllProtos := func() {
			for _, v := range s.protoclConfigs {
				session.openProtoStream(v.inner.name(v.inner.id))
			}
		}
		switch target.Tag {
		case All:
			openAllProtos()

		case Single:
			pid, ok := target.Target.(ProtocolID)
			if ok {
				v, ok := s.protoclConfigs[pid]
				if ok {
					session.openProtoStream(v.inner.name(v.inner.id))
				}
			} else {
				openAllProtos()
			}

		case Multi:
			pids, ok := target.Target.([]ProtocolID)
			if ok {
				for _, p := range pids {
					v, ok := s.protoclConfigs[p]
					if ok {
						session.openProtoStream(v.inner.name(v.inner.id))
					}
				}
			} else {
				openAllProtos()
			}
		}
	}

	go session.runAccept()
	go session.runReceiver()

	if s.handle != nil {
		s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: SessionOpen, Event: control.inner})
	}
}

func (s *service) sessionClose(id SessionID, source uint8) {
	if source == external {
		control, ok := s.sessions[id]
		if !ok {
			return
		}

		control.eventSender <- sessionEvent{tag: sessionClose, event: control.inner.Sid}
	}

	control, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)

	var deleteHandle = []sessionProto{}

	// clean all session handle
	for i := range s.sessionProtoHandles {
		if i.sid == id {
			deleteHandle = append(deleteHandle, i)
		}
	}

	for _, v := range deleteHandle {
		delete(s.sessionProtoHandles, v)
	}

	if s.handle != nil {
		s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: SessionClose, Event: control.inner})
	}
}

func (s *service) protocolClose(sid SessionID, pid ProtocolID) {
	control, ok := s.sessions[sid]
	if !ok {
		return
	}

	control.eventSender <- sessionEvent{tag: protocolClose, event: pid}
}

func (s *service) protocolOpen(sid SessionID, pid ProtocolID) {
	// session not exist
	control, ok := s.sessions[sid]
	if !ok {
		return
	}

	control.eventSender <- sessionEvent{tag: protocolOpen, event: pid}
}

func (s *service) sessionHandlesOpen(sid SessionID) {
	for _, v := range s.protoclConfigs {
		if v.sessionHandleFn != nil {
			control, ok := s.sessions[sid]
			if !ok {
				continue
			}
			sessionChan := make(chan sessionProtocolEvent, receiveSize)

			s.sessionProtoHandles[sessionProto{pid: v.inner.id, sid: sid}] = sessionChan

			pctx := ProtocolContext{Pid: v.inner.id}
			pctx.ServiceContext = s.serviceContext

			stream := sessionProtocolStream{
				handle:        v.sessionHandleFn(),
				handleContext: pctx,
				context:       control.inner,
				notifys:       make(map[uint64]time.Duration),
				shutdown:      false,

				eventReceiver: sessionChan,
				notifyChan:    make(chan uint64, 16),
				reportChan:    s.sessionEventChan,
			}
			go stream.run()
		}
	}
}

func (s *service) initServiceProtoHandles() {
	for _, v := range s.protoclConfigs {
		if v.serviceHandle != nil {
			serviceChan := make(chan serviceProtocolEvent, receiveSize)
			s.serviceProtoHandles[v.inner.id] = serviceChan
			pctx := ProtocolContext{Pid: v.inner.id}
			pctx.ServiceContext = s.serviceContext

			stream := serviceProtocolStream{
				handle:        v.serviceHandle,
				handleContext: pctx,
				shutdown:      &s.shutdown,
				sessions:      make(map[SessionID]*SessionContext),
				notifys:       make(map[uint64]time.Duration),

				eventReceiver: serviceChan,
				notifyChan:    make(chan uint64, 16),
				reportChan:    s.sessionEventChan,
			}

			stream.handleEvent(serviceProtocolEvent{tag: serviceProtocolInit})

			go stream.run()
		}

		s.beforeSends[v.inner.id] = v.beforeSend
	}
}

func (s *service) dial(addr ma.Multiaddr, target TargetProtocol) {
	if !isSupport(addr) {
		s.sessionEventChan <- sessionEvent{tag: dialError, event: DialerErrorInner{Tag: TransportError, Addr: addr, Inner: ErrNotSupport}}
		return
	}

	s.dialProtocols[addr] = target
	go func() {
		conn, err := multiDial(addr, s.config)
		if err != nil {
			protectRun(func() {
				s.sessionEventChan <- sessionEvent{tag: dialError, event: DialerErrorInner{Tag: TransportError, Addr: addr, Inner: err}}
			}, nil)
			return
		}
		go handshake(conn, SessionType(0), addr, s.serviceContext.Key, s.config.timeout, nil, s.sessionEventChan)
	}()
}

func (s *service) listen(addr ma.Multiaddr) {
	if !isSupport(addr) {
		s.sessionEventChan <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: TransportError, Addr: addr, Inner: ErrNotSupport}}
		return
	}

	listener, err := multiListen(addr, s.config)

	if err != nil {
		protectRun(func() {
			s.sessionEventChan <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: TransportError, Addr: addr, Inner: err}}
		}, nil)
		return
	}
	protectRun(func() {
		s.sessionEventChan <- sessionEvent{tag: listenStart, event: listenStartInner{listener: listener}}
	}, nil)
}

func (s *service) listenerstart(inner listenStartInner) {
	if s.handle != nil {
		s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenStarted, Event: inner.listener.Multiaddr()})
	}
	s.state.decrease()
	s.listens[inner.listener.Multiaddr()] = inner.listener
	s.serviceContext.Listens = append(s.serviceContext.Listens, inner.listener.Multiaddr())

	listen := serviceListener{
		shutdown:       &s.shutdown,
		listener:       inner.listener,
		eventSender:    s.sessionEventChan,
		config:         s.config,
		serviceContext: s.serviceContext,
	}
	go listen.run()
}

func (s *service) control() *Service {
	return &Service{
		state:  s.state,
		key:    s.serviceContext.Key,
		closed: &s.shutdown,
		config: &s.config,

		quickTaskSender: s.serviceContext.quickTaskSender,
		taskSender:      s.serviceContext.taskSender,
	}
}
