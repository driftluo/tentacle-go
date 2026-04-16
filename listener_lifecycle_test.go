package tentacle

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func TestServiceListenerStartDoesNotRegisterUpgradePlaceholder(t *testing.T) {
	tcpAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000")
	wsAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000/ws")

	rawListener := &countingNetListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}}
	baseListener := &tcpBaseListener{
		inner:     rawListener,
		localAddr: "127.0.0.1:9000",
		incoming:  make(chan manet.Conn),
		closed:    make(chan uint, 1),
	}

	svc := newTestServiceForListenerLifecycle()

	svc.listenerstart(listenStartInner{
		listener: &TcpBaseListenerEnum{
			enum:     Normal,
			listener: baseListener,
			address:  tcpAddr,
		},
	})
	svc.listenerstart(listenStartInner{
		listener: &TcpBaseListenerEnum{
			enum:     UpgradeMode,
			listener: nil,
			address:  wsAddr,
		},
	})

	if _, ok := svc.listens[wsAddr.String()]; ok {
		t.Fatalf("expected upgrade placeholder listener %s to stay out of s.listens", wsAddr)
	}
	if got := len(svc.serviceContext.Listens); got != 2 {
		t.Fatalf("expected both logical listen addresses to be tracked, got %d", got)
	}

	svc.handleServiceTask(serviceTask{tag: taskShutdown}, high)

	if rawListener.closeCalls != 1 {
		t.Fatalf("expected backing listener to be closed once, got %d", rawListener.closeCalls)
	}
	if got := len(svc.listens); got != 0 {
		t.Fatalf("expected shutdown to clear listener map, got %d entries", got)
	}
	if got := len(svc.serviceContext.Listens); got != 0 {
		t.Fatalf("expected shutdown to clear logical listens, got %d entries", got)
	}
}

func TestServiceListenerRunHandlesMissingGlobalStatus(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	addr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000")
	listener := &erroringManetListener{
		addr:      addr,
		netAddr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		acceptErr: errors.New("boom"),
	}
	events := make(chan sessionEvent, 1)

	sl := serviceListener{
		shutdown:    &shutdown,
		listener:    listener,
		eventSender: events,
		config: serviceConfig{
			global: &globalListenState{status: make(map[string]*upgradeMode)},
		},
		serviceContext: &ServiceContext{},
	}

	sl.run()

	select {
	case event := <-events:
		if event.tag != listenError {
			t.Fatalf("expected listenError event, got tag %d", event.tag)
		}
		inner := event.event.(ListenErrorInner)
		if inner.Tag != IoError {
			t.Fatalf("expected IoError, got %d", inner.Tag)
		}
		if !inner.Addr.Equal(addr) {
			t.Fatalf("expected listen error addr %s, got %s", addr, inner.Addr)
		}
	default:
		t.Fatal("expected listen error event when global.status entry is missing")
	}

	if listener.closeCalls != 1 {
		t.Fatalf("expected listener close to be called once, got %d", listener.closeCalls)
	}
}

func TestTaskListenSkipsTrackedLogicalListenerWithoutBackingListener(t *testing.T) {
	addr := mustMultiaddr(t, "/ip4/127.0.0.1/udp/9000")
	svc := newTestServiceForListenerLifecycle()
	svc.serviceContext.Listens = []multiaddr.Multiaddr{addr}

	svc.handleServiceTask(serviceTask{tag: taskListen, event: addr}, high)

	if got := svc.state.inner(); got != 0 {
		t.Fatalf("expected duplicate logical listen to be ignored, got workers=%d", got)
	}
}

func TestTCPBaseListenerCloseIsIdempotent(t *testing.T) {
	rawListener := &countingNetListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}}
	listener := &tcpBaseListener{
		inner:     rawListener,
		localAddr: "127.0.0.1:9000",
		incoming:  make(chan manet.Conn),
		closed:    make(chan uint, 1),
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- listener.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second close: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("second close blocked")
	}

	if rawListener.closeCalls != 1 {
		t.Fatalf("expected inner listener to be closed once, got %d", rawListener.closeCalls)
	}
}

func TestTCPBaseListenerHandleConnectionReturnsWhenClosed(t *testing.T) {
	mode := upgradeMode(0b1)
	listener := &tcpBaseListener{
		timeout:     50 * time.Millisecond,
		upgradeMode: &mode,
		incoming:    make(chan manet.Conn),
		closed:      make(chan uint),
	}
	close(listener.closed)

	conn := &stubConn{
		reader:     bytes.NewReader([]byte("hello")),
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 9000},
	}

	done := make(chan struct{})
	go func() {
		listener.handleConnection(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected closed listener to stop handling accepted connection")
	}
}

func TestServiceListenerRunIgnoresClosedListener(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	addr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000")
	rawListener := &countingNetListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}}
	listener := &tcpBaseListener{
		inner:     rawListener,
		localAddr: "127.0.0.1:9000",
		incoming:  make(chan manet.Conn),
		closed:    make(chan uint, 1),
	}
	close(listener.closed)

	events := make(chan sessionEvent, 1)
	sl := serviceListener{
		shutdown:    &shutdown,
		listener:    listener,
		eventSender: events,
		config: serviceConfig{
			global: &globalListenState{status: make(map[string]*upgradeMode)},
		},
		serviceContext: &ServiceContext{},
	}

	sl.run()

	select {
	case event := <-events:
		t.Fatalf("expected closed listener to stop quietly, got event %+v", event)
	default:
	}

	if rawListener.closeCalls != 0 {
		t.Fatalf("expected closed listener path to avoid extra close, got %d", rawListener.closeCalls)
	}
	if !addr.Equal(listener.Multiaddr()) {
		t.Fatalf("expected closed listener multiaddr to remain %s, got %s", addr, listener.Multiaddr())
	}
}

func TestNewTCPBaseListenerPreservesWSAddressOnDynamicPort(t *testing.T) {
	mode := upgradeMode(0b10)
	global := &globalListenState{status: make(map[string]*upgradeMode)}

	listener, err := newTcpBaseListener(
		50*time.Millisecond,
		nil,
		mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0/ws"),
		&mode,
		nil,
		global,
	)
	if err != nil {
		t.Fatalf("new tcp base listener: %v", err)
	}
	defer listener.listener.Close()

	if got := listener.address.String(); !strings.HasSuffix(got, "/ws") {
		t.Fatalf("expected dynamic ws listener address to preserve /ws suffix, got %s", got)
	}
}

func TestTCPBaseListenerPropagatesInnerAcceptError(t *testing.T) {
	rawListener := &failOnceNetListener{
		addr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		acceptErr: errors.New("boom"),
		closed:    make(chan struct{}),
	}
	listener := &tcpBaseListener{
		inner:     rawListener,
		localAddr: "127.0.0.1:9000",
		global:    &globalListenState{status: make(map[string]*upgradeMode)},
		incoming:  make(chan manet.Conn),
		closed:    make(chan uint, 1),
	}
	defer listener.Close()

	go listener.serve()

	errCh := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, rawListener.acceptErr) {
			t.Fatalf("expected accept error %v, got %v", rawListener.acceptErr, err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("listener.Accept blocked instead of returning inner accept error")
	}
}

func TestServiceListenOnClosedServiceDoesNotLeakGlobalListenerState(t *testing.T) {
	var closed atomic.Value
	closed.Store(true)

	cfg := serviceConfig{
		timeout:        50 * time.Millisecond,
		global:         &globalListenState{status: make(map[string]*upgradeMode)},
		trustedProxies: nil,
	}
	service := &Service{
		closed: &closed,
		config: &cfg,
	}

	_, err := service.Listen(mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0"))
	if !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("expected ErrBrokenPipe, got %v", err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		cfg.global.lock.Lock()
		remaining := len(cfg.global.status)
		cfg.global.lock.Unlock()
		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected global listener state to be cleaned, still have %d entries", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServiceListenSkipsDuplicateLogicalAddress(t *testing.T) {
	handle := newListenEventHandle()
	service := DefaultServiceBuilder().Forever(true).Build(handle)

	listenAddr, err := service.Listen(mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0/ws"))
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}

	startedAddr := handle.waitForStarted(t)
	if !startedAddr.Equal(listenAddr) {
		t.Fatalf("expected first ListenStarted addr %s, got %s", listenAddr, startedAddr)
	}

	secondAddr, err := service.Listen(listenAddr)
	if err != nil {
		t.Fatalf("second listen: %v", err)
	}
	if !secondAddr.Equal(listenAddr) {
		t.Fatalf("expected duplicate listen to return %s, got %s", listenAddr, secondAddr)
	}

	handle.assertNoExtraStarted(t)

	shutdownServiceAndWait(t, service)

	if got := handle.startedCount(); got != 1 {
		t.Fatalf("expected one ListenStarted event, got %d", got)
	}
	if got := handle.closedCount(); got != 1 {
		t.Fatalf("expected one ListenClose event, got %d", got)
	}
}

func TestServiceListenerRunUsesAcceptedConnLocalMultiaddr(t *testing.T) {
	var shutdown atomic.Value
	shutdown.Store(false)

	listenerAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000")
	connListenAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000/ws")
	remoteAddr := mustMultiaddr(t, "/ip4/198.51.100.9/tcp/4000/ws")

	listener := &oneShotManetListener{
		addr:    listenerAddr,
		netAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		conn: &fixedMultiaddrConn{
			localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
			remoteAddr:      &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 4000},
			localMultiaddr:  connListenAddr,
			remoteMultiaddr: remoteAddr,
		},
	}

	events := make(chan sessionEvent, 2)
	sl := serviceListener{
		shutdown:       &shutdown,
		listener:       listener,
		eventSender:    events,
		config:         serviceConfig{},
		serviceContext: &ServiceContext{},
	}

	sl.run()

	select {
	case event := <-events:
		if event.tag != handshakeSuccess {
			t.Fatalf("expected handshakeSuccess event, got tag %d", event.tag)
		}
		inner := event.event.(handshakeSuccessInner)
		if !inner.listenAddr.Equal(connListenAddr) {
			t.Fatalf("expected listen addr %s, got %s", connListenAddr, inner.listenAddr)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected handshakeSuccess event")
	}
}

func newTestServiceForListenerLifecycle() *service {
	state := &serviceState{tag: running}
	shutdown := atomic.Value{}
	shutdown.Store(false)
	return &service{
		state:    state,
		listens:  make(map[string]manet.Listener),
		sessions: make(map[SessionID]sessionController),
		serviceContext: &ServiceContext{
			Listens: nil,
		},
		config: serviceConfig{
			global: &globalListenState{status: make(map[string]*upgradeMode)},
		},
		handleSender: make(chan any, 8),
		shutdown:     shutdown,
	}
}

type countingNetListener struct {
	addr       net.Addr
	closeCalls int
}

func (l *countingNetListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected accept")
}

func (l *countingNetListener) Close() error {
	l.closeCalls++
	return nil
}

func (l *countingNetListener) Addr() net.Addr {
	return l.addr
}

type listenEventHandle struct {
	startedCh chan multiaddr.Multiaddr
	errCh     chan error

	mu      sync.Mutex
	started []multiaddr.Multiaddr
	closed  []multiaddr.Multiaddr
}

func newListenEventHandle() *listenEventHandle {
	return &listenEventHandle{
		startedCh: make(chan multiaddr.Multiaddr, 4),
		errCh:     make(chan error, 1),
	}
}

func (h *listenEventHandle) HandleEvent(ctx *ServiceContext, event ServiceEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch event.Tag {
	case ListenStarted:
		addr := event.Event.(multiaddr.Multiaddr)
		h.started = append(h.started, addr)
		select {
		case h.startedCh <- addr:
		default:
		}
	case ListenClose:
		addr := event.Event.(multiaddr.Multiaddr)
		h.closed = append(h.closed, addr)
	}
}

func (h *listenEventHandle) HandleError(ctx *ServiceContext, event ServiceError) {
	select {
	case h.errCh <- errors.New(event.String()):
	default:
	}
}

func (h *listenEventHandle) waitForStarted(t *testing.T) multiaddr.Multiaddr {
	t.Helper()

	select {
	case addr := <-h.startedCh:
		return addr
	case err := <-h.errCh:
		t.Fatalf("unexpected service error before ListenStarted: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for ListenStarted")
	}
	return nil
}

func (h *listenEventHandle) assertNoExtraStarted(t *testing.T) {
	t.Helper()

	select {
	case addr := <-h.startedCh:
		t.Fatalf("expected no extra ListenStarted event, got %s", addr)
	case err := <-h.errCh:
		t.Fatalf("unexpected service error after duplicate listen: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func (h *listenEventHandle) startedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.started)
}

func (h *listenEventHandle) closedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.closed)
}

type failOnceNetListener struct {
	addr       net.Addr
	acceptErr  error
	closeCalls int
	closed     chan struct{}
	failed     atomic.Bool
}

func (l *failOnceNetListener) Accept() (net.Conn, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, l.acceptErr
	}

	<-l.closed
	return nil, net.ErrClosed
}

func (l *failOnceNetListener) Close() error {
	l.closeCalls++
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *failOnceNetListener) Addr() net.Addr {
	return l.addr
}

type erroringManetListener struct {
	addr       multiaddr.Multiaddr
	netAddr    net.Addr
	acceptErr  error
	closeCalls int
}

func (l *erroringManetListener) Accept() (manet.Conn, error) {
	return nil, l.acceptErr
}

func (l *erroringManetListener) Close() error {
	l.closeCalls++
	return nil
}

func (l *erroringManetListener) Addr() net.Addr {
	return l.netAddr
}

func (l *erroringManetListener) Multiaddr() multiaddr.Multiaddr {
	return l.addr
}

type oneShotManetListener struct {
	addr    multiaddr.Multiaddr
	netAddr net.Addr
	conn    manet.Conn
	served  bool
}

func (l *oneShotManetListener) Accept() (manet.Conn, error) {
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	return nil, errListenerClosed
}

func (l *oneShotManetListener) Close() error {
	return nil
}

func (l *oneShotManetListener) Addr() net.Addr {
	return l.netAddr
}

func (l *oneShotManetListener) Multiaddr() multiaddr.Multiaddr {
	return l.addr
}

type fixedMultiaddrConn struct {
	localAddr       net.Addr
	remoteAddr      net.Addr
	localMultiaddr  multiaddr.Multiaddr
	remoteMultiaddr multiaddr.Multiaddr
}

func (c *fixedMultiaddrConn) Read(b []byte) (int, error) {
	return 0, nil
}

func (c *fixedMultiaddrConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *fixedMultiaddrConn) Close() error {
	return nil
}

func (c *fixedMultiaddrConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *fixedMultiaddrConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *fixedMultiaddrConn) SetDeadline(time.Time) error {
	return nil
}

func (c *fixedMultiaddrConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *fixedMultiaddrConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *fixedMultiaddrConn) LocalMultiaddr() multiaddr.Multiaddr {
	return c.localMultiaddr
}

func (c *fixedMultiaddrConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return c.remoteMultiaddr
}
