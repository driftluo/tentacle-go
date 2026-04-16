package tentacle

import (
	"sync/atomic"
	"time"
)

const (
	serviceProtocolInit uint = iota
	serviceProtocolConnected
	serviceProtocolDisconnected
	serviceProtocolReceived
	serviceProtocolSetNotify
	serviceProtocolRemoveNotify
	serviceProtocolNotify
)

// As a firm believer in the type system, this is the last stubborn stand against the Go type!
type serviceProtocolEvent struct {
	tag   uint
	event any
}

type serviceProtocolConnectedInner struct {
	context *SessionContext
	version string
}

type serviceProtocolReceivedInner struct {
	id   SessionID
	data []byte
}

type protocolSetNotifyInner struct {
	interval time.Duration
	token    uint64
}

type protocolNotifyState struct {
	interval time.Duration
	cancel   chan struct{}
}

type protocolNotifyTrigger struct {
	token  uint64
	cancel chan struct{}
}

type serviceProtocolStream struct {
	handle        ServiceProtocol
	handleContext ProtocolContext
	sessions      map[SessionID]*SessionContext
	notifys       map[uint64]protocolNotifyState
	shutdown      *atomic.Value
	stop          <-chan struct{}

	eventReceiver <-chan serviceProtocolEvent
	notifyChan    chan protocolNotifyTrigger
	reportChan    chan<- sessionEvent
}

func (s *serviceProtocolStream) run() {
	// In theory, this value will not appear, but if it does, it means that the channel was accidentally closed.
	closed := func(ok bool) bool {
		if !ok {
			s.shutdown.Store(true)
			return true
		}
		return false
	}

	for {
		if s.shutdown.Load().(bool) {
			return
		}
		select {
		case <-s.stop:
			return
		case event, ok := <-s.eventReceiver:
			if closed(ok) {
				continue
			}
			s.handleEvent(event)
		case trigger, ok := <-s.notifyChan:
			if closed(ok) {
				continue
			}
			s.handleEvent(serviceProtocolEvent{tag: serviceProtocolNotify, event: trigger})
		}
	}
}

func (s *serviceProtocolStream) handleEvent(event serviceProtocolEvent) {
	reportFn := func(sid SessionID) func() {
		return func() {
			s.reportChan <- sessionEvent{tag: protocolHandleError, event: protocolHandleErrorInner{pid: s.handleContext.Pid, sid: sid}}
		}
	}

	switch event.tag {
	case serviceProtocolInit:
		protectRun(func() { s.handle.Init(&s.handleContext) }, reportFn(SessionID(0)))

	case serviceProtocolConnected:
		sessioninfo := event.event.(serviceProtocolConnectedInner)
		protectRun(func() { s.handle.Connected(s.handleContext.toRef(sessioninfo.context), sessioninfo.version) }, reportFn(sessioninfo.context.Sid))
		s.sessions[sessioninfo.context.Sid] = sessioninfo.context

	case serviceProtocolDisconnected:
		id := event.event.(SessionID)
		sessionctx, ok := s.sessions[id]
		if !ok {
			return
		}
		protectRun(func() { s.handle.Disconnected(s.handleContext.toRef(sessionctx)) }, reportFn(sessionctx.Sid))
		delete(s.sessions, id)

	case serviceProtocolReceived:
		data := event.event.(serviceProtocolReceivedInner)

		sessionctx, ok := s.sessions[data.id]
		if !ok {
			return
		}
		protectRun(func() { s.handle.Received(s.handleContext.toRef(sessionctx), data.data) }, reportFn(sessionctx.Sid))

	case serviceProtocolNotify:
		trigger := event.event.(protocolNotifyTrigger)
		notify, ok := s.notifys[trigger.token]
		if !ok || s.shutdown.Load().(bool) || notify.cancel != trigger.cancel {
			return
		}

		protectRun(func() { s.handle.Notify(&s.handleContext, trigger.token) }, reportFn(SessionID(0)))
		s.setNotify(trigger.token)

	case serviceProtocolSetNotify:
		notify := event.event.(protocolSetNotifyInner)
		if existing, ok := s.notifys[notify.token]; ok {
			close(existing.cancel)
		}
		s.notifys[notify.token] = protocolNotifyState{
			interval: notify.interval,
			cancel:   make(chan struct{}),
		}
		s.setNotify(notify.token)

	case serviceProtocolRemoveNotify:
		token := event.event.(uint64)
		if notify, ok := s.notifys[token]; ok {
			close(notify.cancel)
		}
		delete(s.notifys, token)
	}
}

func (s *serviceProtocolStream) setNotify(token uint64) {
	notify, ok := s.notifys[token]
	if !ok {
		return
	}

	go func() {
		timer := time.NewTimer(notify.interval)
		defer timer.Stop()

		select {
		case <-s.stop:
			return
		case <-notify.cancel:
			return
		case <-timer.C:
		}

		select {
		case <-s.stop:
			return
		case <-notify.cancel:
			return
		case s.notifyChan <- protocolNotifyTrigger{token: token, cancel: notify.cancel}:
		}
	}()
}

const (
	sessionProtocolOpened uint = iota
	sessionProtocolClosed
	sessionProtocolDisconnected
	sessionProtocolReceived
	sessionProtocolSetNotify
	sessionProtocolRemoveNotify
	sessionProtocolNotify
)

// As a firm believer in the type system, this is the last stubborn stand against the Go type!
type sessionProtocolEvent struct {
	tag   uint
	event any
}

type sessionProtocolStream struct {
	handle        SessionProtocol
	handleContext ProtocolContext
	context       *SessionContext
	notifys       map[uint64]protocolNotifyState
	shutdown      bool
	stop          chan struct{}

	eventReceiver <-chan sessionProtocolEvent
	notifyChan    chan protocolNotifyTrigger
	reportChan    chan<- sessionEvent
}

func (s *sessionProtocolStream) run() {
	defer func() {
		if s.stop != nil {
			close(s.stop)
		}
	}()
	// In theory, this value will not appear, but if it does, it means that the channel was accidentally closed.
	closed := func(ok bool) bool {
		if !ok {
			s.shutdown = true
			return true
		}
		return false
	}

	for {
		if s.shutdown || s.context.closed.Load().(bool) {
			break
		}
		select {
		case event, ok := <-s.eventReceiver:
			if closed(ok) {
				continue
			}
			s.handleEvent(event)
		case trigger, ok := <-s.notifyChan:
			if closed(ok) {
				continue
			}
			s.handleEvent(sessionProtocolEvent{tag: sessionProtocolNotify, event: trigger})
		}
	}
}

func (s *sessionProtocolStream) handleEvent(event sessionProtocolEvent) {
	reportFn := func() {
		s.reportChan <- sessionEvent{tag: protocolHandleError, event: protocolHandleErrorInner{sid: s.context.Sid, pid: s.handleContext.Pid}}
	}

	switch event.tag {
	case sessionProtocolOpened:
		version := event.event.(string)
		protectRun(func() { s.handle.Connected(s.handleContext.toRef(s.context), version) }, reportFn)

	case sessionProtocolClosed:
		protectRun(func() { s.handle.Disconnected(s.handleContext.toRef(s.context)) }, reportFn)

	case sessionProtocolDisconnected:
		s.shutdown = true

	case sessionProtocolReceived:
		data := event.event.([]byte)
		protectRun(func() { s.handle.Received(s.handleContext.toRef(s.context), data) }, reportFn)

	case sessionProtocolNotify:
		trigger := event.event.(protocolNotifyTrigger)
		notify, ok := s.notifys[trigger.token]
		if !ok || s.shutdown || s.context.closed.Load().(bool) || notify.cancel != trigger.cancel {
			return
		}
		protectRun(func() { s.handle.Notify(s.handleContext.toRef(s.context), trigger.token) }, reportFn)
		s.setNotify(trigger.token)

	case sessionProtocolSetNotify:
		notify := event.event.(protocolSetNotifyInner)
		if existing, ok := s.notifys[notify.token]; ok {
			close(existing.cancel)
		}
		s.notifys[notify.token] = protocolNotifyState{
			interval: notify.interval,
			cancel:   make(chan struct{}),
		}
		s.setNotify(notify.token)

	case sessionProtocolRemoveNotify:
		token := event.event.(uint64)
		if notify, ok := s.notifys[token]; ok {
			close(notify.cancel)
		}
		delete(s.notifys, token)
	}
}

func (s *sessionProtocolStream) setNotify(token uint64) {
	notify, ok := s.notifys[token]
	if !ok {
		return
	}

	go func() {
		timer := time.NewTimer(notify.interval)
		defer timer.Stop()

		select {
		case <-s.stop:
			return
		case <-notify.cancel:
			return
		case <-timer.C:
		}

		select {
		case <-s.stop:
			return
		case <-notify.cancel:
			return
		case s.notifyChan <- protocolNotifyTrigger{token: token, cancel: notify.cancel}:
		}
	}()
}
