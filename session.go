package tentacle

import (
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	/// Close by remote, accept all data as much as possible
	remoteClose uint8 = iota
	/// Close by self, don't receive any more
	localClose
	/// Normal communication
	normal
	/// Abnormal state
	abnormal
)

const (
	sessionClose uint = iota
	listenStart
	dialStart
	handshakeSuccess
	handshakeError
	dialError
	listenError
	protocolMessage
	protocolOpen
	protocolClose
	protocolSelectError
	sessionTimeout
	protocolError
	muxerError
	protocolHandleError
)

const sendSize int = 512

// As a firm believer in the type system, this is the last stubborn stand against the Go type!
type sessionEvent struct {
	tag   uint
	event interface{}
}

type protocolSelectErrorInner struct {
	id        SessionID
	protoName string
}

type protocolErrorInner struct {
	id  SessionID
	pid ProtocolID
	err error
}

type protocolOpenInner struct {
	id      SessionID
	pid     ProtocolID
	version string
}

type protocolCloseInner struct {
	id  SessionID
	pid ProtocolID
}

type protocolMessageInner struct {
	id   SessionID
	pid  ProtocolID
	data []byte
}

type protocolHandleErrorInner struct {
	PID ProtocolID
	// If SID == 0, it means that can not locate which session case this error
	SID SessionID
}

type muxerErrorInner struct {
	id  SessionID
	err error
}

type session struct {
	// Common
	socket              yamux.Session
	protocolConfigs     map[string]*meta
	context             *SessionContext
	nextStreamID        streamID
	protoStreams        map[ProtocolID]streamID
	serviceProtoSenders map[ProtocolID]chan<- serviceProtocolEvent
	sessionProtoSenders map[ProtocolID]chan<- sessionProtocolEvent
	sessionState        uint8
	timeout             time.Duration

	// Read substream event and then output to service
	protoEventChan chan protocolEvent
	serviceSender  chan<- sessionEvent

	// Read session event and then distribute to substream
	subStreams      map[streamID]chan<- protocolEvent
	serviceReceiver <-chan sessionEvent
	quickReceiver   <-chan sessionEvent
}

func (s *session) runReceiver() {
	// In theory, this value will not appear, but if it does, it means that the channel was accidentally closed.
	closed := func(ok bool) bool {
		if !ok {
			s.context.closed = true
			if s.sessionState == normal {
				s.sessionState = localClose
			}
			return true
		}
		return false
	}

	for {
		if s.sessionState == localClose {
			goto CASE_STATE
		}

		select {
		// Priority queue
		case event, ok := <-s.quickReceiver:
			if closed(ok) {
				goto CASE_STATE
			}
			s.handleSessionEvent(event)
		default:
			select {
			case event, ok := <-s.quickReceiver:
				if closed(ok) {
					goto CASE_STATE
				}
				s.handleSessionEvent(event)
			case event, ok := <-s.serviceReceiver:
				if closed(ok) {
					goto CASE_STATE
				}
				s.handleSessionEvent(event)
			case event, ok := <-s.protoEventChan:
				if closed(ok) {
					goto CASE_STATE
				}
				s.handleStreamEvent(event)
			}
		}

	CASE_STATE:
		switch s.sessionState {
		case localClose, abnormal:
			s.closeSession()
			return
		case remoteClose:
			if len(s.protoStreams) != 0 {
				s.closeAllProto()
			} else {
				s.closeSession()
				return
			}
		}
	}
}

func (s *session) runAccept() {
	for {
		if s.sessionState != normal {
			break
		}

		conn, err := s.socket.Accept()

		if err != nil {
			switch err {
			case yamux.ErrSessionShutdown:
				s.sessionState = remoteClose
			default:
				s.sessionState = abnormal
				s.serviceSender <- sessionEvent{tag: muxerError, event: muxerErrorInner{id: s.context.id, err: err}}
			}
			break
		}
		go s.handleSubstream(conn)
	}
}

func (s *session) handleSessionEvent(event sessionEvent) {
	switch event.tag {
	case protocolMessage:
		inner := event.event.(protocolMessageInner)
		streamid, ok := s.protoStreams[inner.pid]
		if !ok {
			return
		}
		sender := s.subStreams[streamid]
		sender <- protocolEvent{tag: subStreamMessage, event: subStreamMessageInner{sID: streamid, pID: inner.pid, data: inner.data}}

	case sessionClose:
		if len(s.subStreams) == 0 {
			s.closeSession()
		} else {
			s.sessionState = localClose
			s.closeAllProto()
		}

	case protocolOpen:
		inner := event.event.(protocolOpenInner)
		_, ok := s.protoStreams[inner.pid]

		if ok {
			return
		}

		for _, v := range s.protocolConfigs {
			if v.id == inner.pid {
				s.openProtoStream(v.name(inner.pid))
				return
			}
		}
		// log.Printf("This protocol [%d] is not supported", inner.pid)

	case protocolClose:
		inner := event.event.(protocolCloseInner)

		streamid, ok := s.protoStreams[inner.pid]
		if !ok {
			// log.Printf("This protocol [%d] has been closed", inner.pid)
			return
		}

		sender := s.subStreams[streamid]
		sender <- protocolEvent{tag: subStreamClose}
	}
}

func (s *session) handleStreamEvent(event protocolEvent) {
	switch event.tag {
	case subStreamOpen:
		inner := event.event.(subStreamOpenInner)
		s.openProtocol(inner)

	case subStreamClose:
		inner := event.event.(subStreamCloseInner)
		delete(s.subStreams, inner.sID)
		delete(s.protoStreams, inner.pID)
		s.serviceSender <- sessionEvent{tag: sessionProtocolClosed, event: protocolCloseInner{id: s.context.id, pid: inner.pID}}

	case subStreamSelectError:
		name := event.event.(string)
		s.serviceSender <- sessionEvent{tag: protocolSelectError, event: protocolSelectErrorInner{id: s.context.id, protoName: name}}

	case subStreamOtherError:
		inner := event.event.(subStreamOtherErrorInner)
		s.serviceSender <- sessionEvent{tag: protocolError, event: protocolErrorInner{id: s.context.id, pid: inner.pid, err: inner.err}}

	case subStreamTimeOutCheck:
		if len(s.subStreams) == 0 {
			s.serviceSender <- sessionEvent{tag: sessionTimeout, event: s.context.id}
		}
	}
}

func (s *session) handleSubstream(conn net.Conn) {
	infos := make(map[string]info, len(s.protocolConfigs))
	for _, v := range s.protocolConfigs {
		name := v.name(v.id)
		pinfo := ProtocolInfo{
			name:           name,
			supportVersion: v.supportVersions,
		}
		info := info{inner: pinfo, fn: v.selectVersion}
		infos[name] = info
	}

	fn := generateFn(
		func() (net.Conn, string, string, error) {
			version, name, err := serverSelect(conn, infos)
			return conn, version, name, err
		},
	)
	s.selectProcedure(fn)
}

func (s *session) openProtoStream(name string) {
	conn, err := s.socket.Open()

	if err != nil {
		return
	}

	versions := s.protocolConfigs[name].supportVersions
	info := ProtocolInfo{
		name:           name,
		supportVersion: versions,
	}

	fn := generateFn(
		func() (net.Conn, string, string, error) {
			version, name, err := clientSelect(conn, info)
			return conn, version, name, err
		},
	)
	s.selectProcedure(fn)
}

func (s *session) selectProcedure(f func(chan<- protocolEvent)) {
	go func() {
		resChan := make(chan protocolEvent, 1)

		go f(resChan)

		select {
		case event := <-resChan:
			s.protoEventChan <- event
		case <-time.After(s.timeout):
			s.protoEventChan <- protocolEvent{tag: subStreamSelectError, event: ""}
		}
	}()
}

func (s *session) openProtocol(event subStreamOpenInner) {
	proto, ok := s.protocolConfigs[event.name]

	if !ok {
		s.sessionState = abnormal
		s.serviceSender <- sessionEvent{tag: protocolSelectError, event: protocolSelectErrorInner{id: s.context.id, protoName: ""}}
		return
	}

	pid := proto.id

	_, ok = s.protoStreams[pid]
	if ok {
		return
	}

	protoChan := make(chan protocolEvent, sendSize)

	protoStream := subStream{
		socket:  proto.codec(event.conn),
		pID:     pid,
		sID:     s.nextStreamID,
		context: s.context,
		dead:    false,

		eventSender:        s.protoEventChan,
		eventReceiver:      protoChan,
		beforeReceive:      proto.beforeReceive,
		serviceProtoSender: s.serviceProtoSenders[pid],
		sessionProtoSender: s.sessionProtoSenders[pid],
	}

	s.subStreams[s.nextStreamID] = protoChan
	s.protoStreams[pid] = s.nextStreamID

	protoStream.protoOpen(event.version)

	s.serviceSender <- sessionEvent{tag: protocolOpen, event: protocolOpenInner{id: s.context.id, pid: pid, version: event.version}}
	s.nextStreamID++
	go protoStream.runWrite()
	go protoStream.runRead()
}

func (s *session) closeSession() {
	defer protectRun(func() { close(s.protoEventChan) }, nil)
	defer s.socket.Close()

	s.context.closed = true
	s.serviceSender <- sessionEvent{tag: sessionClose, event: s.context.id}
}

func (s *session) closeAllProto() {
	s.context.closed = true
}

func generateFn(f func() (net.Conn, string, string, error)) func(chan<- protocolEvent) {
	return func(resChan chan<- protocolEvent) {
		conn, version, name, err := f()
		if err != nil {
			defer conn.Close()
			protectRun(func() { resChan <- protocolEvent{tag: subStreamSelectError, event: name} }, nil)
			return
		}
		protectRun(
			func() {
				resChan <- protocolEvent{tag: subStreamOpen, event: subStreamOpenInner{name: name, version: version, conn: conn}}
			},
			nil,
		)
	}
}

func initTimeoutCheck(sender chan<- protocolEvent, ti time.Duration) {
	<-time.After(ti)
	protectRun(func() { sender <- protocolEvent{tag: subStreamTimeOutCheck} }, nil)
}
