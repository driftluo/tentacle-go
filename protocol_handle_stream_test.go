package tentacle

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceProtocolStreamSetNotifyReplacesExistingTimer(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	events := make(chan serviceProtocolEvent, 2)
	stop := make(chan struct{})
	handle := &recordingServiceProtocol{notifyCh: make(chan uint64, 4)}
	stream := serviceProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		sessions:      make(map[SessionID]*SessionContext),
		notifys:       make(map[uint64]protocolNotifyState),
		shutdown:      &shutdown,
		stop:          stop,
		eventReceiver: events,
		notifyChan:    make(chan protocolNotifyTrigger, 4),
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: 20 * time.Millisecond, token: 7}}
	events <- serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: 20 * time.Millisecond, token: 7}}

	select {
	case token := <-handle.notifyCh:
		if token != 7 {
			t.Fatalf("expected notify token 7, got %d", token)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected first service notify")
	}

	select {
	case token := <-handle.notifyCh:
		t.Fatalf("expected duplicate service notify timer to be replaced, got early token %d", token)
	case <-time.After(10 * time.Millisecond):
	}

	events <- serviceProtocolEvent{tag: serviceProtocolRemoveNotify, event: uint64(7)}
	shutdown.Store(true)
	close(stop)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected service protocol stream to stop")
	}
}

func TestServiceProtocolStreamNotifyTimerPausesWhileNotifyRuns(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	events := make(chan serviceProtocolEvent, 1)
	stop := make(chan struct{})
	notifyChan := make(chan protocolNotifyTrigger, 4)
	handle := &blockingServiceProtocol{
		started: make(chan uint64, 1),
		release: make(chan struct{}),
	}
	stream := serviceProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		sessions:      make(map[SessionID]*SessionContext),
		notifys:       make(map[uint64]protocolNotifyState),
		shutdown:      &shutdown,
		stop:          stop,
		eventReceiver: events,
		notifyChan:    notifyChan,
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: 10 * time.Millisecond, token: 7}}
	select {
	case token := <-handle.started:
		if token != 7 {
			t.Fatalf("expected notify token 7, got %d", token)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected service notify to start")
	}

	time.Sleep(35 * time.Millisecond)
	select {
	case trigger := <-notifyChan:
		t.Fatalf("expected no queued service notify while callback is running, got token %d", trigger.token)
	default:
	}

	close(handle.release)
	events <- serviceProtocolEvent{tag: serviceProtocolRemoveNotify, event: uint64(7)}
	shutdown.Store(true)
	close(stop)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected service protocol stream to stop")
	}
}

func TestServiceProtocolStreamIgnoresQueuedNotifyFromReplacedTimer(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	handle := &recordingServiceProtocol{notifyCh: make(chan uint64, 1)}
	stream := serviceProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		sessions:      make(map[SessionID]*SessionContext),
		notifys:       make(map[uint64]protocolNotifyState),
		shutdown:      &shutdown,
		stop:          make(chan struct{}),
		eventReceiver: make(chan serviceProtocolEvent, 1),
		notifyChan:    make(chan protocolNotifyTrigger, 1),
		reportChan:    make(chan sessionEvent, 1),
	}

	stream.handleEvent(serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: 10 * time.Millisecond, token: 7}})

	var queued protocolNotifyTrigger
	select {
	case queued = <-stream.notifyChan:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected first service timer to queue a notify")
	}

	stream.handleEvent(serviceProtocolEvent{tag: serviceProtocolSetNotify, event: protocolSetNotifyInner{interval: time.Second, token: 7}})
	stream.handleEvent(serviceProtocolEvent{tag: serviceProtocolNotify, event: queued})

	select {
	case token := <-handle.notifyCh:
		t.Fatalf("expected replaced service timer's queued notify to be ignored, got token %d", token)
	default:
	}
}

func TestSessionProtocolStreamRemoveNotifyPreventsLateNotify(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	events := make(chan sessionProtocolEvent, 2)
	handle := &recordingSessionProtocol{notifyCh: make(chan uint64, 1)}
	stream := sessionProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		context:       &SessionContext{closed: closed},
		notifys:       make(map[uint64]protocolNotifyState),
		stop:          make(chan struct{}),
		eventReceiver: events,
		notifyChan:    make(chan protocolNotifyTrigger, 1),
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: 20 * time.Millisecond, token: 7}}
	time.Sleep(5 * time.Millisecond)
	events <- sessionProtocolEvent{tag: sessionProtocolRemoveNotify, event: uint64(7)}

	select {
	case token := <-handle.notifyCh:
		t.Fatalf("expected removed notify token to be suppressed, got %d", token)
	case <-time.After(60 * time.Millisecond):
	}

	closed.Store(true)
	close(events)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session protocol stream to stop")
	}
}

func TestSessionProtocolStreamIgnoresQueuedNotifyFromReplacedTimer(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	handle := &recordingSessionProtocol{notifyCh: make(chan uint64, 1)}
	stream := sessionProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		context:       &SessionContext{closed: closed},
		notifys:       make(map[uint64]protocolNotifyState),
		stop:          make(chan struct{}),
		eventReceiver: make(chan sessionProtocolEvent, 1),
		notifyChan:    make(chan protocolNotifyTrigger, 1),
		reportChan:    make(chan sessionEvent, 1),
	}

	stream.handleEvent(sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: 10 * time.Millisecond, token: 7}})

	var queued protocolNotifyTrigger
	select {
	case queued = <-stream.notifyChan:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected first session timer to queue a notify")
	}

	stream.handleEvent(sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: time.Second, token: 7}})
	stream.handleEvent(sessionProtocolEvent{tag: sessionProtocolNotify, event: queued})

	select {
	case token := <-handle.notifyCh:
		t.Fatalf("expected replaced session timer's queued notify to be ignored, got token %d", token)
	default:
	}
}

func TestSessionProtocolStreamSetNotifyReplacesExistingTimer(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	events := make(chan sessionProtocolEvent, 2)
	handle := &recordingSessionProtocol{notifyCh: make(chan uint64, 4)}
	stream := sessionProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		context:       &SessionContext{closed: closed},
		notifys:       make(map[uint64]protocolNotifyState),
		stop:          make(chan struct{}),
		eventReceiver: events,
		notifyChan:    make(chan protocolNotifyTrigger, 4),
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: 20 * time.Millisecond, token: 7}}
	events <- sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: 20 * time.Millisecond, token: 7}}

	select {
	case token := <-handle.notifyCh:
		if token != 7 {
			t.Fatalf("expected notify token 7, got %d", token)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected first session notify")
	}

	select {
	case token := <-handle.notifyCh:
		t.Fatalf("expected duplicate session notify timer to be replaced, got early token %d", token)
	case <-time.After(10 * time.Millisecond):
	}

	events <- sessionProtocolEvent{tag: sessionProtocolRemoveNotify, event: uint64(7)}
	closed.Store(true)
	close(events)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session protocol stream to stop")
	}
}

func TestSessionProtocolStreamNotifyTimerPausesWhileNotifyRuns(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	events := make(chan sessionProtocolEvent, 1)
	notifyChan := make(chan protocolNotifyTrigger, 4)
	handle := &blockingSessionProtocol{
		started: make(chan uint64, 1),
		release: make(chan struct{}),
	}
	stream := sessionProtocolStream{
		handle:        handle,
		handleContext: ProtocolContext{},
		context:       &SessionContext{closed: closed},
		notifys:       make(map[uint64]protocolNotifyState),
		stop:          make(chan struct{}),
		eventReceiver: events,
		notifyChan:    notifyChan,
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- sessionProtocolEvent{tag: sessionProtocolSetNotify, event: protocolSetNotifyInner{interval: 10 * time.Millisecond, token: 7}}
	select {
	case token := <-handle.started:
		if token != 7 {
			t.Fatalf("expected notify token 7, got %d", token)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session notify to start")
	}

	time.Sleep(35 * time.Millisecond)
	select {
	case trigger := <-notifyChan:
		t.Fatalf("expected no queued session notify while callback is running, got token %d", trigger.token)
	default:
	}

	close(handle.release)
	events <- sessionProtocolEvent{tag: sessionProtocolRemoveNotify, event: uint64(7)}
	closed.Store(true)
	close(events)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session protocol stream to stop")
	}
}

func TestSessionProtocolStreamNotifyPanicReportsProtocolHandleError(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	events := make(chan sessionProtocolEvent, 1)
	report := make(chan sessionEvent, 1)
	stream := sessionProtocolStream{
		handle:        &panicSessionProtocol{},
		handleContext: ProtocolContext{Pid: ProtocolID(9)},
		context:       &SessionContext{Sid: SessionID(42), closed: closed},
		notifys: map[uint64]protocolNotifyState{
			11: {interval: time.Second, cancel: make(chan struct{})},
		},
		stop:          make(chan struct{}),
		eventReceiver: events,
		notifyChan:    make(chan protocolNotifyTrigger, 1),
		reportChan:    report,
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- sessionProtocolEvent{
		tag:   sessionProtocolNotify,
		event: protocolNotifyTrigger{token: 11, cancel: stream.notifys[11].cancel},
	}

	select {
	case event := <-report:
		if event.tag != protocolHandleError {
			t.Fatalf("expected protocolHandleError, got %d", event.tag)
		}
		inner := event.event.(protocolHandleErrorInner)
		if inner.sid != SessionID(42) {
			t.Fatalf("expected sid 42, got %d", inner.sid)
		}
		if inner.pid != ProtocolID(9) {
			t.Fatalf("expected pid 9, got %d", inner.pid)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected notify panic to be reported")
	}

	closed.Store(true)
	close(events)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session protocol stream to stop after panic test")
	}
}

func TestSessionProtocolStreamStopsOnDisconnectWithoutOpenedProtocol(t *testing.T) {
	var closed atomic.Value
	closed.Store(false)

	events := make(chan sessionProtocolEvent, 1)
	stream := sessionProtocolStream{
		handle:        &recordingSessionProtocol{notifyCh: make(chan uint64, 1)},
		handleContext: ProtocolContext{},
		context:       &SessionContext{closed: closed},
		notifys:       make(map[uint64]protocolNotifyState),
		stop:          make(chan struct{}),
		eventReceiver: events,
		notifyChan:    make(chan protocolNotifyTrigger, 1),
		reportChan:    make(chan sessionEvent, 1),
	}

	done := make(chan struct{})
	go func() {
		stream.run()
		close(done)
	}()

	events <- sessionProtocolEvent{tag: sessionProtocolDisconnected}

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected session protocol stream to stop after disconnect")
	}
}

type recordingServiceProtocol struct {
	notifyCh chan uint64
}

func (h *recordingServiceProtocol) Init(*ProtocolContext) {}

func (h *recordingServiceProtocol) Connected(*ProtocolContextRef, string) {}

func (h *recordingServiceProtocol) Disconnected(*ProtocolContextRef) {}

func (h *recordingServiceProtocol) Received(*ProtocolContextRef, []byte) {}

func (h *recordingServiceProtocol) Notify(_ *ProtocolContext, token uint64) {
	h.notifyCh <- token
}

type blockingServiceProtocol struct {
	started chan uint64
	release chan struct{}
}

func (h *blockingServiceProtocol) Init(*ProtocolContext) {}

func (h *blockingServiceProtocol) Connected(*ProtocolContextRef, string) {}

func (h *blockingServiceProtocol) Disconnected(*ProtocolContextRef) {}

func (h *blockingServiceProtocol) Received(*ProtocolContextRef, []byte) {}

func (h *blockingServiceProtocol) Notify(_ *ProtocolContext, token uint64) {
	h.started <- token
	<-h.release
}

type recordingSessionProtocol struct {
	notifyCh chan uint64
}

func (h *recordingSessionProtocol) Connected(*ProtocolContextRef, string) {}

func (h *recordingSessionProtocol) Disconnected(*ProtocolContextRef) {}

func (h *recordingSessionProtocol) Received(*ProtocolContextRef, []byte) {}

func (h *recordingSessionProtocol) Notify(_ *ProtocolContextRef, token uint64) {
	h.notifyCh <- token
}

type blockingSessionProtocol struct {
	started chan uint64
	release chan struct{}
}

func (h *blockingSessionProtocol) Connected(*ProtocolContextRef, string) {}

func (h *blockingSessionProtocol) Disconnected(*ProtocolContextRef) {}

func (h *blockingSessionProtocol) Received(*ProtocolContextRef, []byte) {}

func (h *blockingSessionProtocol) Notify(_ *ProtocolContextRef, token uint64) {
	h.started <- token
	<-h.release
}

type panicSessionProtocol struct{}

func (h *panicSessionProtocol) Connected(*ProtocolContextRef, string) {}

func (h *panicSessionProtocol) Disconnected(*ProtocolContextRef) {}

func (h *panicSessionProtocol) Received(*ProtocolContextRef, []byte) {}

func (h *panicSessionProtocol) Notify(*ProtocolContextRef, uint64) {
	panic("boom")
}
