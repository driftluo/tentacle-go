package tentacle

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
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
	shutdown       *bool
	listener       manet.Listener
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
			s.eventSender <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: IoError, Addr: s.listener.Multiaddr(), Inner: err}}
			return
		}
		go handshake(conn, Inbound, conn.RemoteMultiaddr(), s.serviceContext.Key, s.config.timeout, s.listener.Multiaddr(), s.eventSender)
	}
}

func handshake(conn net.Conn, ty uint8, remoteAddr ma.Multiaddr, selfKey secio.PrivKey, timeout time.Duration, listenAddr ma.Multiaddr, report chan<- sessionEvent) {
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
	state *serviceState

	// multi transport
	// upnp client

	listens       map[ma.Multiaddr]manet.Listener
	dialProtocols map[ma.Multiaddr]TargetProtocol
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

	// Unable to use global variables, which can cause only one service to be started in a process
	once     sync.Once
	shutdown bool
}

func (s *service) run() {
	init := 1
	for {
		if len(s.sessions) == 0 && len(s.listens) == 0 && s.state.isShutdown() && init == 0 {
			s.shutdown = true
			break
		}
		s.once.Do(func() {
			init--
			s.initServiceProtoHandles()
		})

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
			switch priority {
			case high:
				controller.quickSender <- sessionEvent{tag: protocolMessage, event: protocolMessageInner{id: controller.inner.Sid, pid: inner.pid, data: beforeSend(inner.data)}}
			case low:
				controller.eventSender <- sessionEvent{tag: protocolMessage, event: protocolMessageInner{id: controller.inner.Sid, pid: inner.pid, data: beforeSend(inner.data)}}
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
				s.protocolOpen(inner.sid, v.inner.id, "", external)
			}

		case Single:
			pid, ok := inner.target.Target.(ProtocolID)
			if !ok {
				return
			}
			s.protocolOpen(inner.sid, pid, "", external)

		case Multi:
			pids, ok := inner.target.Target.([]ProtocolID)
			if !ok {
				return
			}
			for _, pid := range pids {
				s.protocolOpen(inner.sid, pid, "", external)
			}
		}

	case taskProtocolClose:
		inner := event.event.(taskProtocolCloseInner)
		s.protocolClose(inner.sid, inner.pid, external)

	case taskDial:
		inner := event.event.(taskDialInner)
		_, ok := s.dialProtocols[inner.addr]
		if !ok {
			s.state.increase()
			go s.dial(inner.addr, inner.target)
		}

	case taskListen:
		addr := event.event.(ma.Multiaddr)
		_, ok := s.listens[addr]
		if !ok {
			go s.listen(addr)
		}

	case taskListenStart:
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
		inner := event.event.(taskRemoveProtocolSessionNotifyInner)
		sender, ok := s.sessionProtoHandles[sessionProto{sid: inner.sid, pid: inner.pid}]
		if ok {
			sender <- sessionProtocolEvent{tag: sessionProtocolNotify, event: inner.token}
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
			s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenClose, Event: addr})
		}
		s.listens = make(map[ma.Multiaddr]manet.Listener)

		for id := range s.sessions {
			s.sessionClose(id, external)
		}
		s.shutdown = true
	}
}

func (s *service) handleSessionEvent(event sessionEvent) {
	switch event.tag {
	case sessionClose:
		id := event.event.(SessionID)
		s.sessionClose(id, internal)

	case handshakeSuccess:
		inner := event.event.(handshakeSuccessInner)

		if inner.ty == Inbound && len(s.sessions)+len(s.listens)+int(s.state.inner()) > int(s.config.maxConnectionNumber) {
			defer inner.conn.Close()
			return
		}

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
		s.handleServiceTask(serviceTask{tag: taskShutdown}, high)

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
		deleteSlice(s.serviceContext.Listens, inner.Addr)
		delete(s.listens, inner.Addr)
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
		s.listenerstart(inner)

	case dialStart:
		inner := event.event.(dialStartInner)
		go handshake(inner.conn, Outbound, inner.remoteAddr, s.serviceContext.Key, s.config.timeout, nil, s.sessionEventChan)
	}
}

func (s *service) sessionOpen(conn net.Conn, remotePubkey secio.PubKey, remoteAddr ma.Multiaddr, ty uint8, listenAddr ma.Multiaddr) {
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
		// check if repeated connection
		for _, control := range s.sessions {
			if remotePubkey.Equals(control.inner.RemotePub) {
				defer conn.Close()
				switch ty {
				case Outbound:
					s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: RepeatedConnection, Inner: control.inner.Sid, Addr: remoteAddr}})
				case Inbound:
					s.handle.HandleError(s.serviceContext, ServiceError{Tag: ListenError, Event: ListenErrorInner{Tag: RepeatedConnection, Inner: control.inner.Sid, Addr: listenAddr}})
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
			if peerid.IsKey(remotePubkey) {
				defer conn.Close()
				s.handle.HandleError(s.serviceContext, ServiceError{Tag: DialerError, Event: DialerErrorInner{Tag: PeerIDNotMatch, Addr: remoteAddr}})
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

	control := sessionController{
		quickSender: quick,
		eventSender: event,
		inner: &SessionContext{
			Sid:        s.nextSession,
			RemoteAddr: remoteAddr,
			Ty:         ty,
			closed:     false,
			RemotePub:  remotePubkey,
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
	var sessionProtoConfigs = make(map[string]*meta)
	var sessionProtoSenders = make(map[ProtocolID]chan<- sessionProtocolEvent)

	for k, v := range s.protoclConfigs {
		sessionProtoConfigs[k] = v.inner
	}

	for k, v := range s.sessionProtoHandles {
		if k.sid == s.nextSession {
			sessionProtoSenders[k.pid] = v
		}
	}

	if ty == Outbound {
		socket, _ = yamux.Client(conn, s.config.yamuxConfig)
	} else {
		socket, _ = yamux.Server(conn, s.config.yamuxConfig)
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
		openAllProtos := func() {
			for name := range s.protoclConfigs {
				session.openProtoStream(name)
			}
		}
		switch target.Tag {
		case All:
			openAllProtos()

		case Single:
			pid, ok := target.Target.(ProtocolID)
			if ok {
				for name, v := range s.protoclConfigs {
					if pid == v.inner.id {
						session.openProtoStream(name)
						break
					}
				}
			} else {
				openAllProtos()
			}

		case Multi:
			pids, ok := target.Target.([]ProtocolID)
			if ok {
				for _, p := range pids {
					for name, v := range s.protoclConfigs {
						if p == v.inner.id {
							session.openProtoStream(name)
							break
						}
					}
				}
			} else {
				openAllProtos()
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

		control.eventSender <- sessionEvent{tag: sessionClose, event: control.inner.Sid}
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

	var protos map[ProtocolID]bool
	var ok bool

	protos, ok = s.sessionServiceProtos[sid]

	if !ok {
		s.sessionServiceProtos[sid] = make(map[ProtocolID]bool)
		protos = s.sessionServiceProtos[sid]
	}

	protos[pid] = true
}

func (s *service) handleOpen(handle interface{}, pid ProtocolID, sid SessionID) {
	switch handle.(type) {
	case ServiceProtocol:
		serviceChan := make(chan serviceProtocolEvent, receiveSize)
		s.serviceProtoHandles[pid] = serviceChan
		pctx := ProtocolContext{Pid: pid}
		pctx.ServiceContext = s.serviceContext

		stream := serviceProtocolStream{
			handle:        handle.(ServiceProtocol),
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

	case SessionProtocol:
		control, ok := s.sessions[sid]
		if !ok {
			return
		}
		sessionChan := make(chan sessionProtocolEvent, receiveSize)

		s.sessionProtoHandles[sessionProto{pid: pid, sid: sid}] = sessionChan

		pctx := ProtocolContext{Pid: pid}
		pctx.ServiceContext = s.serviceContext

		stream := sessionProtocolStream{
			handle:        handle.(SessionProtocol),
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

func (s *service) initServiceProtoHandles() {
	for _, v := range s.protoclConfigs {
		if v.serviceHandle != nil {
			s.handleOpen(v.serviceHandle, v.inner.id, SessionID(0))
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
	resChan := make(chan sessionEvent)
	go func() {
		conn, err := manet.Dial(addr)
		if err != nil {
			resChan <- sessionEvent{tag: dialError, event: DialerErrorInner{Tag: TransportError, Addr: addr, Inner: err}}
		}
		resChan <- sessionEvent{tag: dialStart, event: dialStartInner{remoteAddr: addr, conn: conn}}
	}()

	select {
	case <-time.After(s.config.timeout):
		protectRun(
			func() {
				s.sessionEventChan <- sessionEvent{tag: dialError, event: DialerErrorInner{Tag: TransportError, Addr: addr, Inner: ErrDialTimeout}}
			},
			nil,
		)
	case event := <-resChan:
		protectRun(func() { s.sessionEventChan <- event }, nil)
	}
}

func (s *service) listen(addr ma.Multiaddr) {
	if !isSupport(addr) {
		s.sessionEventChan <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: TransportError, Addr: addr, Inner: ErrNotSupport}}
		return
	}
	resChan := make(chan sessionEvent)
	go func() {
		listener, err := manet.Listen(addr)
		if err != nil {
			resChan <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: TransportError, Addr: addr, Inner: err}}
		}
		resChan <- sessionEvent{tag: listenStart, event: listenStartInner{listener: listener}}
	}()

	select {
	case <-time.After(s.config.timeout):
		protectRun(
			func() {
				s.sessionEventChan <- sessionEvent{tag: listenError, event: ListenErrorInner{Tag: TransportError, Addr: addr, Inner: ErrListenerTimeout}}
			},
			nil,
		)
	case event := <-resChan:
		protectRun(func() { s.sessionEventChan <- event }, nil)
	}
}

func (s *service) listenerstart(inner listenStartInner) {
	s.handle.HandleEvent(s.serviceContext, ServiceEvent{Tag: ListenStarted, Event: inner.listener.Multiaddr()})
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

		quickTaskSender: s.serviceContext.quickTaskSender,
		taskSender:      s.serviceContext.taskSender,
	}
}
