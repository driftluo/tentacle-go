package tentacle

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	"github.com/hashicorp/yamux"
	"github.com/multiformats/go-multiaddr"
)

func TestHandshakeTimeoutClosesConn(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	localAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9000")
	remoteAddr := mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9001")
	conn := &trackingManetConn{
		Conn:            serverConn,
		localMultiaddr:  localAddr,
		remoteMultiaddr: remoteAddr,
		closed:          make(chan struct{}),
	}

	report := make(chan sessionEvent, 1)
	go handshake(conn, SessionType(1), remoteAddr, secio.GenerateSecp256k1(), 20*time.Millisecond, localAddr, report)

	select {
	case event := <-report:
		if event.tag != handshakeError {
			t.Fatalf("expected handshakeError event, got %d", event.tag)
		}
		inner := event.event.(handshakeErrorInner)
		if !errors.Is(inner.err, ErrHandshakeTimeout) {
			t.Fatalf("expected ErrHandshakeTimeout, got %v", inner.err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handshake timeout event")
	}

	select {
	case <-conn.closed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected timeout handshake to close the connection")
	}
}

func TestSelectProcedureClosesLateConnAfterTimeout(t *testing.T) {
	s := &session{
		timeout:        20 * time.Millisecond,
		protoEventChan: make(chan protocolEvent, 1),
	}
	conn := &trackingNetConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2448},
		closed:     make(chan struct{}),
	}

	done := make(chan struct{})
	s.selectProcedure(func(resChan chan<- protocolEvent, stop <-chan struct{}) {
		time.Sleep(50 * time.Millisecond)
		sendOrDropResult(
			resChan,
			stop,
			protocolEvent{
				tag: subStreamOpen,
				event: subStreamOpenInner{
					name:    "test",
					version: "1.0.0",
					conn:    conn,
				},
			},
			cleanupProtocolEvent,
		)
		close(done)
	})

	select {
	case event := <-s.protoEventChan:
		if event.tag != subStreamSelectError {
			t.Fatalf("expected subStreamSelectError after timeout, got %d", event.tag)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for protocol selection timeout")
	}

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected late protocol selection sender to return")
	}

	select {
	case <-conn.closed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected timeout path to close late-opened protocol conn")
	}
}

func TestSessionOpenTimesOutIdleSessionWithoutStreams(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	handleSender := make(chan any, 4)
	go func() {
		for event := range handleSender {
			wrapper, ok := event.(serviceEventWrapper)
			if ok {
				wrapper.waitSign <- true
			}
		}
	}()

	shutdown := atomic.Value{}
	shutdown.Store(false)
	svc := service{
		protoclConfigs:      make(map[ProtocolID]ProtocolMeta),
		serviceProtoHandles: make(map[ProtocolID]chan<- serviceProtocolEvent),
		sessionProtoHandles: make(map[sessionProto]chan<- sessionProtocolEvent),
		serviceContext:      &ServiceContext{},
		state:               &serviceState{tag: forever},
		config: serviceConfig{
			timeout:     20 * time.Millisecond,
			yamuxConfig: yamux.DefaultConfig(),
			channelSize: 16,
		},
		dialProtocols:    make(map[string]TargetProtocol),
		sessions:         make(map[SessionID]sessionController),
		handleSender:     handleSender,
		sessionEventChan: make(chan sessionEvent, 4),
		shutdown:         shutdown,
	}

	svc.sessionOpen(serverConn, nil, mustMultiaddr(t, "/ip4/127.0.0.1/tcp/9001"), SessionType(1), nil)

	deadline := time.After(time.Second)
	seenTimeout := false
	seenClose := false
	for !seenTimeout || !seenClose {
		select {
		case event := <-svc.sessionEventChan:
			switch event.tag {
			case sessionTimeout:
				seenTimeout = true
			case sessionClose:
				seenClose = true
			default:
				t.Fatalf("expected idle session timeout/close events, got %d", event.tag)
			}
		case <-deadline:
			t.Fatalf("timeout waiting for idle session timeout and close, seenTimeout=%v seenClose=%v", seenTimeout, seenClose)
		}
	}
}

func TestSessionTimeoutCheckIgnoresSessionThatOpenedAStream(t *testing.T) {
	closed := atomic.Value{}
	closed.Store(false)
	state := atomic.Value{}
	state.Store(normal)

	serviceSender := make(chan sessionEvent, 1)
	s := &session{
		context:         &SessionContext{closed: closed},
		protoStreams:    make(map[ProtocolID]streamID),
		subStreams:      make(map[streamID]chan<- protocolEvent),
		openedAnyStream: true,
		sessionState:    state,
		serviceSender:   serviceSender,
	}

	s.handleStreamEvent(protocolEvent{tag: subStreamTimeOutCheck})

	select {
	case event := <-serviceSender:
		t.Fatalf("expected no timeout event after a stream has already been opened, got %d", event.tag)
	default:
	}
}

type trackingManetConn struct {
	net.Conn
	localMultiaddr  multiaddr.Multiaddr
	remoteMultiaddr multiaddr.Multiaddr
	closed          chan struct{}
	closeOnce       sync.Once
}

func (c *trackingManetConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return err
}

func (c *trackingManetConn) LocalMultiaddr() multiaddr.Multiaddr {
	return c.localMultiaddr
}

func (c *trackingManetConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return c.remoteMultiaddr
}

type trackingNetConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     chan struct{}
	closeOnce  sync.Once
}

func (c *trackingNetConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *trackingNetConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *trackingNetConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *trackingNetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *trackingNetConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *trackingNetConn) SetDeadline(time.Time) error {
	return nil
}

func (c *trackingNetConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *trackingNetConn) SetWriteDeadline(time.Time) error {
	return nil
}
