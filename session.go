package tentacle

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

const (
	// Close by remote, accept all data as much as possible
	remoteClose uint8 = iota
	// Close by self, don't receive any more
	localClose
	// Normal communication
	normal
	// Abnormal state
	abnormal
	// close
	sessionShutdown
)

const (
	sessionClose uint = iota
	listenStart
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

type protocolMessageInner struct {
	id   SessionID
	pid  ProtocolID
	data []byte
}

type protocolHandleErrorInner struct {
	pid ProtocolID
	// If sid == 0, it means that can not locate which session case this error
	sid SessionID
}

type muxerErrorInner struct {
	id  SessionID
	err error
}

type handshakeErrorInner struct {
	ty         SessionType
	err        error
	remoteAddr ma.Multiaddr
}

type handshakeSuccessInner struct {
	ty           SessionType
	remoteAddr   ma.Multiaddr
	conn         net.Conn
	listenAddr   ma.Multiaddr
	remotePubkey secio.PubKey
}

type listenStartInner struct {
	listener manet.Listener
}

type session struct {
	// Common
	socket                *yamux.Session
	protocolConfigsByName map[string]*meta
	protocolConfigsByID   map[ProtocolID]*meta
	context               *SessionContext
	nextStreamID          streamID
	protoStreams          map[ProtocolID]streamID
	serviceProtoSenders   map[ProtocolID]chan<- serviceProtocolEvent
	sessionProtoSenders   map[ProtocolID]chan<- sessionProtocolEvent
	sessionState          uint8
	timeout               time.Duration

	// Read substream event and then output to service
	protoEventChan chan protocolEvent
	serviceSender  chan<- sessionEvent

	// Read session event and then distribute to substream
	subStreams      map[streamID]chan<- protocolEvent
	serviceReceiver <-chan sessionEvent
	quickReceiver   <-chan sessionEvent

	sync.Mutex
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
		case sessionShutdown:
			return
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
			case yamux.ErrSessionShutdown, io.EOF:
				s.sessionState = remoteClose
				if len(s.protoStreams) != 0 {
					s.closeAllProto()
				} else {
					s.closeSession()
				}
			default:
				s.sessionState = abnormal
				s.serviceSender <- sessionEvent{tag: muxerError, event: muxerErrorInner{id: s.context.Sid, err: err}}
				s.closeSession()
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
		pid := event.event.(ProtocolID)
		_, ok := s.protoStreams[pid]

		if ok {
			return
		}

		v, ok := s.protocolConfigsByID[pid]
		if ok {
			s.openProtoStream(v.name(pid))
			return
		}
		// log.Printf("This protocol [%d] is not supported", pid)

	case protocolClose:
		pid := event.event.(ProtocolID)

		streamid, ok := s.protoStreams[pid]
		if !ok {
			// log.Printf("This protocol [%d] has been closed", pid)
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

	case subStreamSelectError:
		name := event.event.(string)
		s.serviceSender <- sessionEvent{tag: protocolSelectError, event: protocolSelectErrorInner{id: s.context.Sid, protoName: name}}

	case subStreamOtherError:
		inner := event.event.(subStreamOtherErrorInner)
		s.serviceSender <- sessionEvent{tag: protocolError, event: protocolErrorInner{id: s.context.Sid, pid: inner.pid, err: inner.err}}

	case subStreamTimeOutCheck:
		if len(s.subStreams) == 0 {
			s.serviceSender <- sessionEvent{tag: sessionTimeout, event: s.context.Sid}
		}
	}
}

func (s *session) handleSubstream(conn net.Conn) {
	infos := make(map[string]info, len(s.protocolConfigsByName))
	for k, v := range s.protocolConfigsByName {

		pinfo := ProtocolInfo{
			name:           k,
			supportVersion: v.supportVersions,
		}
		info := info{inner: pinfo, fn: v.selectVersion}
		infos[k] = info
	}

	fn := generateFn(
		func() (net.Conn, string, string, error) {
			name, version, err := serverSelect(conn, infos)
			return conn, name, version, err
		},
	)
	s.selectProcedure(fn)
}

func (s *session) openProtoStream(name string) {
	conn, err := s.socket.Open()

	if err != nil {
		return
	}

	versions := s.protocolConfigsByName[name].supportVersions
	info := ProtocolInfo{
		name:           name,
		supportVersion: versions,
	}

	fn := generateFn(
		func() (net.Conn, string, string, error) {
			name, version, err := clientSelect(conn, info)
			return conn, name, version, err
		},
	)
	s.selectProcedure(fn)
}

func (s *session) selectProcedure(f func(chan<- protocolEvent)) {
	go func() {
		resChan := make(chan protocolEvent)

		go f(resChan)

		select {
		case event := <-resChan:
			protectRun(func() { s.protoEventChan <- event }, nil)
		case <-time.After(s.timeout):
			protectRun(func() { s.protoEventChan <- protocolEvent{tag: subStreamSelectError, event: ""} }, nil)
		}
	}()
}

func (s *session) openProtocol(event subStreamOpenInner) {
	proto, ok := s.protocolConfigsByName[event.name]

	if !ok {
		s.sessionState = abnormal
		s.serviceSender <- sessionEvent{tag: protocolSelectError, event: protocolSelectErrorInner{id: s.context.Sid, protoName: ""}}
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

	s.nextStreamID++
	go protoStream.runWrite()
	go protoStream.runRead()
}

func (s *session) closeSession() {
	s.Lock()
	defer s.Unlock()

	if s.sessionState == sessionShutdown {
		return
	}
	defer protectRun(func() { close(s.protoEventChan) }, nil)
	if !s.socket.IsClosed() {
		defer s.socket.GoAway()
		defer s.socket.Close()
	}

	for _, v := range s.sessionProtoSenders {
		v <- sessionProtocolEvent{tag: sessionProtocolDisconnected}
	}

	s.context.closed = true
	s.serviceSender <- sessionEvent{tag: sessionClose, event: s.context.Sid}
	s.sessionState = sessionShutdown
}

func (s *session) closeAllProto() {
	s.Lock()
	defer s.Unlock()
	if !s.context.closed {
		s.context.closed = true
		for _, sender := range s.subStreams {
			sender <- protocolEvent{tag: subStreamClose}
		}
	}
}

func generateFn(f func() (net.Conn, string, string, error)) func(chan<- protocolEvent) {
	return func(resChan chan<- protocolEvent) {
		conn, name, version, err := f()
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
