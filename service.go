package tentacle

import (
	"errors"
	"net"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
)

// ErrHandshakeTimeout secio handshake timeout
var ErrHandshakeTimeout = errors.New("Handshake timeout")

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

type serviceListener struct {
	shutdown       *bool
	listener       net.Listener
	addr           net.Addr
	eventSender    chan<- sessionEvent
	config         serviceConfig
	serviceContext *ServiceContext
}

func (s *serviceListener) run() {
	for {
		if *s.shutdown {
			break
		}

		conn, err := s.listener.Accept()

		if err != nil {
			if *s.shutdown {
				return
			}
			defer s.listener.Close()
			s.eventSender <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: IoError, Addr: s.addr, Inner: err}}
			return
		}
		go handshake(conn, Inbound, conn.RemoteAddr(), s.serviceContext.key, s.config.timeout, s.addr, s.eventSender)
	}
}

func handshake(conn net.Conn, ty uint8, remoteAddr net.Addr, selfKey secio.PrivKey, timeout time.Duration, listenAddr net.Addr, report chan<- sessionEvent) {
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
	protoclConfigs map[string]ProtocolMeta
	serviceContext *ServiceContext

	// service state
	state serviceState

	// multi transport
	// upnp client

	listens       map[net.Addr]net.Listener
	dialProtocols map[net.Addr]TargetProtocol
	config        serviceConfig
	nextSession   SessionID
	beforeSends   map[ProtocolID]BeforeSend

	handle ServiceHandle

	// The service protocols open with the session
	sessionServiceProtos map[SessionID]map[ProtocolID]bool

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

	shutdown *bool
}

func (s *service) run() {
	s.initServiceProtoHandles()
	for {
		select {
		case event := <-s.quickTaskReceiver:
			s.handleServiceTask(event)
		default:
			select {
			case event := <-s.quickTaskReceiver:
				s.handleServiceTask(event)
			case event := <-s.taskReceiver:
				s.handleServiceTask(event)
			case event := <-s.sessionEventChan:
				s.handleSessionEvent(event)
			}
		}
	}
}

func (s *service) handleServiceTask(event serviceTask) {
	switch event.tag {
	case taskProtocolMessage:
	case taskProtocolOpen:
	case taskProtocolClose:
	case taskDial:
	case taskListen:
	case taskDisconnect:
	case taskSetProtocolNotify:
	case taskRemoveProtocolNotify:
	case taskSetProtocolSessionNotify:
	case taskRemoveProtocolSessionNotify:
	}
}

func (s *service) handleSessionEvent(event sessionEvent) {
	switch event.tag {
	case sessionClose:
		id := event.event.(SessionID)
		s.sessionClose(id, internal)

	case handshakeSuccess:
		inner := event.event.(handshakeSuccessInner)
		s.sessionOpen(inner.conn, inner.remotePubkey, inner.remoteAddr, inner.ty, inner.listenAddr)

	case handshakeError:
		inner := event.event.(handshakeErrorInner)
		if inner.ty == Outbound {
			s.state.decrease()
			delete(s.dialProtocols, inner.remoteAddr)
			s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: HandshakeError, Inner: inner.err, Addr: inner.remoteAddr}})
		}

	case protocolClose:
		inner := event.event.(protocolCloseInner)
		s.protocolClose(inner.id, inner.pid, internal)

	case protocolOpen:
		inner := event.event.(protocolOpenInner)
		s.protocolOpen(inner.id, inner.pid, inner.version, internal)

	case protocolSelectError:
		inner := event.event.(protocolSelectErrorInner)
		control, ok := s.sessions[inner.id]
		if !ok {
			return
		}
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolSelectError, Event: ProtocolSelectErrorInner{Name: inner.protoName, Context: control.inner}})

	case protocolHandleError:
		inner := event.event.(protocolHandleErrorInner)
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolHandleError, Event: ProtocolHandleErrorInner{PID: inner.pid, SID: inner.sid}})
		s.handleServiceTask(serviceTask{tag: taskShutdown})

	case protocolError:
		inner := event.event.(protocolErrorInner)
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: ProtocolError, Event: ProtocolErrorInner{PID: inner.pid, SID: inner.id, Err: inner.err}})

	case dialError:
		inner := event.event.(DialerErrorInner)
		s.state.decrease()
		delete(s.dialProtocols, inner.Addr)
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: inner})

	case listenError:
		s.state.decrease()
		inner := event.event.(ListenErrorInner)
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: listenError, Event: inner})

	case sessionTimeout:
		id := event.event.(SessionID)
		control, ok := s.sessions[id]
		if !ok {
			return
		}
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: SessionTimeout, Event: SessionTimeoutInner{Context: control.inner}})

	case muxerError:
		inner := event.event.(muxerErrorInner)
		control, ok := s.sessions[inner.id]
		if !ok {
			return
		}
		s.handle.HandleError(s.serviceContext, ServiceError{Tag: MuxerError, Event: MuxerErrorInner{Context: control.inner, Err: inner.err}})

	case listenStart:
		inner := event.event.(listenStartInner)
		s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenStarted, Event: inner.addr})
		s.listens[inner.addr] = inner.listener
		s.state.decrease()

		listen := serviceListener{
			shutdown:       s.shutdown,
			listener:       inner.listener,
			addr:           inner.addr,
			eventSender:    s.sessionEventChan,
			config:         s.config,
			serviceContext: s.serviceContext,
		}
		go listen.run()

	case dialStart:
		inner := event.event.(dialStartInner)
		go handshake(inner.conn, Outbound, inner.remoteAddr, s.serviceContext.key, s.config.timeout, nil, s.sessionEventChan)
	}
}

func (s *service) sessionOpen(conn net.Conn, remotePubkey secio.PubKey, remoteAddr net.Addr, ty uint8, listenAddr net.Addr) {
	if ty == Outbound {
		s.state.decrease()
	}
	var target TargetProtocol
	var ok bool

	target, ok = s.dialProtocols[remoteAddr]
	if !ok {
		target = TargetProtocol{Tag: All}
	}
	delete(s.dialProtocols, remoteAddr)

	if remotePubkey != nil {
		for _, control := range s.sessions {
			if remotePubkey.Equals(control.inner.remotePub) {
				defer conn.Close()
				switch ty {
				case Outbound:
					s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: RepeatedConnection, Inner: control.inner.id, Addr: remoteAddr}})
				case Inbound:
					s.handle.HandleError(s.serviceContext, ServiceError{Tag: ListenError, Event: ListenErrorInner{Tag: RepeatedConnection, Inner: control.inner.id, Addr: listenAddr}})
				}
				return
			}
		}
		// TODO: check peerid here
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

	control := sessionController{
		quickSender: quick,
		eventSender: event,
		inner: &SessionContext{
			id:         s.nextSession,
			remoteAddr: remoteAddr,
			ty:         ty,
			closed:     false,
			remotePub:  remotePubkey,
		},
	}
	// must insert here, otherwise, the session protocol handle cannot be opened
	s.sessions[s.nextSession] = control

	// open all session handles
	for _, v := range s.protoclConfigs {
		if v.sessionHandle != nil {
			s.handleOpen(v.sessionHandle, v.inner.id, s.nextSession)
		}
	}

	var socket *yamux.Session
	var sessionProtoConfigs map[string]*meta
	var sessionProtoSenders map[ProtocolID]chan<- sessionProtocolEvent

	if ty == Outbound {
		socket, _ = yamux.Client(conn, s.config.yamuxConfig)
	} else {
		socket, _ = yamux.Server(conn, s.config.yamuxConfig)
	}

	for k, v := range s.protoclConfigs {
		sessionProtoConfigs[k] = v.inner
	}

	for k, v := range s.sessionProtoHandles {
		if k.sid == s.nextSession {
			sessionProtoSenders[k.pid] = v
		}
	}

	session := session{
		socket:              socket,
		protocolConfigs:     sessionProtoConfigs,
		context:             control.inner,
		nextStreamID:        streamID(0),
		protoStreams:        make(map[ProtocolID]streamID),
		serviceProtoSenders: s.serviceProtoHandles,
		sessionProtoSenders: sessionProtoSenders,
		sessionState:        normal,
		timeout:             s.config.timeout,

		protoEventChan: make(chan protocolEvent, receiveSize),
		serviceSender:  s.sessionEventChan,

		subStreams:      make(map[streamID]chan<- protocolEvent),
		serviceReceiver: event,
		quickReceiver:   quick,
	}

	if ty == Outbound {
		switch target.Tag {
		case All:
			for name := range s.protoclConfigs {
				session.openProtoStream(name)
			}
		case Single:
			pid := target.Target.(ProtocolID)
			for name, v := range s.protoclConfigs {
				if pid == v.inner.id {
					session.openProtoStream(name)
					break
				}
			}
		case Multi:
			pids := target.Target.([]ProtocolID)

			for _, p := range pids {
				for name, v := range s.protoclConfigs {
					if p == v.inner.id {
						session.openProtoStream(name)
						break
					}
				}
			}
		}
	}

	go session.runAccept()
	go session.runReceiver()

	s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: SessionOpen, Event: control.inner})
}

func (s *service) sessionClose(id SessionID, source uint8) {
	if source == external {
		control, ok := s.sessions[id]
		if !ok {
			return
		}

		control.eventSender <- sessionEvent{tag: sessionClose, event: control.inner.id}
	}

	closeProtoids, ok := s.sessionServiceProtos[id]
	if !ok {
		return
	}
	delete(s.sessionServiceProtos, id)

	for pid := range closeProtoids {
		s.protocolClose(id, pid, internal)
		delete(s.sessionProtoHandles, sessionProto{sid: id, pid: pid})
	}

	control, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)

	s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: SessionClose, Event: control.inner})
}

func (s *service) protocolClose(sid SessionID, pid ProtocolID, source uint8) {
	if source == external {
		control, ok := s.sessions[sid]
		if !ok {
			return
		}

		control.eventSender <- sessionEvent{tag: protocolClose, event: protocolCloseInner{id: sid, pid: pid}}
	}

	protoids, ok := s.sessionServiceProtos[sid]
	if !ok {
		return
	}
	delete(protoids, pid)
}

func (s *service) protocolOpen(sid SessionID, pid ProtocolID, version string, source uint8) {
	if source == external {
		// session not exist
		control, ok := s.sessions[sid]
		if !ok {
			return
		}

		// uninit
		protos, ok := s.sessionServiceProtos[sid]
		if !ok {
			goto SEND_EVENT
		}
		// protocol exist
		_, ok = protos[pid]
		if ok {
			return
		}

	SEND_EVENT:
		control.eventSender <- sessionEvent{tag: protocolOpen, event: protocolOpenInner{id: sid, pid: pid, version: version}}
	}

	var protos = make(map[ProtocolID]bool)
	var ok bool

	protos, ok = s.sessionServiceProtos[sid]

	if !ok {
		s.sessionServiceProtos[sid] = protos
	}

	protos[pid] = true
}

func (s *service) handleOpen(handle interface{}, pid ProtocolID, sid SessionID) {
	switch handle.(type) {
	case ServiceProtocol:
		serviceChan := make(chan serviceProtocolEvent, receiveSize)
		s.serviceProtoHandles[pid] = serviceChan

		stream := serviceProtocolStream{
			handle:        handle.(ServiceProtocol),
			handleContext: ProtocolContext{serviceContext: s.serviceContext, pid: pid},
			shutdown:      s.shutdown,
			sessions:      make(map[SessionID]*SessionContext),
			notifys:       make(map[uint64]time.Duration),

			eventReceiver: serviceChan,
			notifyChan:    make(chan uint64, 16),
			reportChan:    s.sessionEventChan,
		}

		stream.handleEvent(serviceProtocolEvent{tag: serviceProtocolInit})

		go stream.run()

	case SessionProtocol:
		control, ok := s.sessions[sid]
		if !ok {
			return
		}
		sessionChan := make(chan sessionProtocolEvent, receiveSize)

		s.sessionProtoHandles[sessionProto{pid: pid, sid: sid}] = sessionChan

		stream := sessionProtocolStream{
			handle:        handle.(SessionProtocol),
			handleContext: ProtocolContext{serviceContext: s.serviceContext, pid: pid},
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

func (s *service) initServiceProtoHandles() {
	for _, v := range s.protoclConfigs {
		if v.serviceHandle != nil {
			s.handleOpen(v.serviceHandle, v.inner.id, SessionID(0))
		}

		s.beforeSends[v.inner.id] = v.beforeSend
	}
}
