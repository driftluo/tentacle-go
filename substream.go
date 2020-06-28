package tentacle

import "net"

// ProtocolID define the protocol id
type ProtocolID uint

// StreamID define the substream id
type streamID uint

const (
	subStreamOpen uint = iota
	subStreamClose
	subStreamMessage
	subStreamSelectError
	subStreamOtherError
	subStreamTimeOutCheck
)

// As a firm believer in the type system, this is the last stubborn stand against the Go type!
type protocolEvent struct {
	tag   uint
	event interface{}
}

type subStreamOpenInner struct {
	name    string
	version string
	conn    net.Conn
}

type subStreamMessageInner struct {
	sID  streamID
	pID  ProtocolID
	data []byte
}

type subStreamCloseInner struct {
	sID streamID
	pID ProtocolID
}

type subStreamOtherErrorInner struct {
	err error
	pid ProtocolID
}

type subStream struct {
	// Common
	socket  Codec
	pID     ProtocolID
	sID     streamID
	context *SessionContext
	dead    bool

	// Output protocol event to session
	eventSender chan<- protocolEvent

	// Read protocol event and then send to socket
	eventReceiver <-chan protocolEvent

	// Read socket message and then send to handle
	beforeReceive      BeforeReceive
	serviceProtoSender chan<- serviceProtocolEvent
	sessionProtoSender chan<- sessionProtocolEvent
}

func (s *subStream) protoOpen(version string) {
	if s.serviceProtoSender != nil {
		s.serviceProtoSender <- serviceProtocolEvent{tag: serviceProtocolConnected, event: serviceProtocolConnectedInner{context: s.context, version: version}}
	}

	if s.sessionProtoSender != nil {
		s.sessionProtoSender <- sessionProtocolEvent{tag: sessionProtocolOpened, event: version}
	}
}

func (s *subStream) runWrite() {
	for event := range s.eventReceiver {
		if s.dead || s.context.closed {
			break
		}
		switch event.tag {
		case subStreamMessage:
			msg := event.event.(subStreamMessageInner)
			err := s.socket.WriteMsg(msg.data)
			if err != nil {
				s.dead = true
				s.errorClose(err)
				break
			}
		case subStreamClose:
			s.dead = true
			s.closeStream()
			break
		}
	}
}

func (s *subStream) runRead() {
	for {
		if s.context.closed {
			s.closeStream()
			return
		}
		readMsg, err := s.socket.ReadMsg()
		if err != nil {
			s.dead = true
			s.errorClose(err)
			break
		}

		s.sendToHandle(s.beforeReceive(readMsg))
	}
}

func (s *subStream) errorClose(err error) {
	s.eventSender <- protocolEvent{tag: subStreamOtherError, event: subStreamOtherErrorInner{err: err, pid: s.pID}}
	s.closeStream()
}

func (s *subStream) closeStream() {
	defer s.socket.Close()

	if s.serviceProtoSender != nil {
		s.serviceProtoSender <- serviceProtocolEvent{tag: serviceProtocolDisconnected, event: s.context.Sid}
	}
	if s.sessionProtoSender != nil {
		s.sessionProtoSender <- sessionProtocolEvent{tag: sessionProtocolClosed}
		s.sessionProtoSender <- sessionProtocolEvent{tag: sessionProtocolDisconnected}
		defer protectRun(func() { close(s.sessionProtoSender) }, nil)
	}

	// if session close receiver first, here may panic, just ignore it
	protectRun(
		func() {
			s.eventSender <- protocolEvent{tag: subStreamClose, event: subStreamCloseInner{sID: s.sID, pID: s.pID}}
		},
		nil,
	)
}

func (s *subStream) sendToHandle(msg []byte) {
	if s.serviceProtoSender != nil {
		s.serviceProtoSender <- serviceProtocolEvent{tag: serviceProtocolReceived, event: serviceProtocolReceivedInner{id: s.context.Sid, data: msg}}
	}

	if s.sessionProtoSender != nil {
		s.sessionProtoSender <- sessionProtocolEvent{tag: sessionProtocolReceived, event: msg}
	}
}
