package tentacle

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

type wsTransport struct {
	timeout time.Duration
}

func newWSTransport(timeout time.Duration) *wsTransport {
	return &wsTransport{timeout: timeout}
}

func (m *wsTransport) listen(addr multiaddr.Multiaddr) (manet.Listener, error) {
	netTy, host, err := manet.DialArgs(addr)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen(netTy, host)
	if err != nil {
		return nil, err
	}

	wsl, err := newWsListener(listener)
	if err != nil {
		return nil, err
	}

	go wsl.serve()

	return wsl, nil
}

func (m *wsTransport) dial(addr multiaddr.Multiaddr) (manet.Conn, error) {
	_, host, err := manet.DialArgs(addr)
	if err != nil {
		return nil, err
	}

	resChan := make(chan interface{})

	go func() {
		conn, _, err := websocket.DefaultDialer.Dial("ws://"+host, nil)
		if err != nil {
			resChan <- err
		}
		resChan <- conn
	}()

	select {
	case <-time.After(m.timeout):
		return nil, ErrDialTimeout
	case res := <-resChan:
		wsconn, ok := res.(*websocket.Conn)
		if ok {
			return newWsConn(wsconn), nil
		}
		return nil, res.(error)
	}
}

var _ manet.Listener = &wsListener{}

var upgrader = websocket.Upgrader{
	// Allow requests from *all* origins.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type wsListener struct {
	inner    net.Listener
	addr     multiaddr.Multiaddr
	incoming chan manet.Conn
	closed   chan uint
}

func newWsListener(l net.Listener) (*wsListener, error) {
	muladdr, err := manet.FromNetAddr(l.Addr())
	if err != nil {
		return nil, err
	}
	wsaddr, err := multiaddr.NewMultiaddr("/ws")
	if err != nil {
		return nil, err
	}
	muladdr = muladdr.Encapsulate(wsaddr)

	return &wsListener{
		inner:    l,
		addr:     muladdr,
		incoming: make(chan manet.Conn),
		closed:   make(chan uint),
	}, nil
}

func (l *wsListener) serve() {
	defer close(l.closed)
	_ = http.Serve(l.inner, l)
}

func (l *wsListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsconn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// The upgrader writes a response for us.
		return
	}

	l.incoming <- newWsConn(wsconn)
}

func (l *wsListener) Accept() (manet.Conn, error) {
	select {
	case conn, ok := <-l.incoming:
		if !ok {
			return nil, errors.New("listener is closed")
		}

		return conn, nil
	case <-l.closed:
		return nil, errors.New("listener is closed")
	}
}

func (l *wsListener) Multiaddr() multiaddr.Multiaddr {
	return l.addr
}

func (l *wsListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *wsListener) Close() error {
	return l.inner.Close()
}

var _ net.Conn = &wsStream{}
var _ manet.Conn = &wsStream{}

type wsStream struct {
	inner               *websocket.Conn
	closeOnce           sync.Once
	readLock, writeLock sync.Mutex
	buf                 []byte
}

func (w *wsStream) fillBuf() error {
start:
	ty, buf, err := w.inner.ReadMessage()
	if err != nil {
		return err
	}
	// only read BinaryMessage and respond PingMessage
	switch ty {
	case websocket.BinaryMessage:
		w.buf = append(w.buf, buf...)
	case websocket.CloseMessage:
		return io.EOF
	case websocket.PingMessage:
		w.inner.WriteControl(websocket.PongMessage, buf, time.Now().Add(100*time.Millisecond))
		goto start
	case websocket.PongMessage, websocket.TextMessage:
		goto start
	}

	return nil
}

func (w *wsStream) Read(buf []byte) (int, error) {
	if len(w.buf) == 0 {
		if err := w.fillBuf(); err != nil {
			return 0, err
		}
	}

	w.readLock.Lock()
	defer w.readLock.Unlock()

	var readLen int

	bufLen := len(w.buf)
	outputLen := len(buf)

	if bufLen < outputLen {
		readLen = bufLen
	} else {
		readLen = outputLen
	}

	if readLen == 0 {
		return 0, nil
	}

	copy(buf[:readLen], w.buf[:readLen])
	w.buf = w.buf[readLen:]

	return readLen, nil
}

func (w *wsStream) Write(b []byte) (n int, err error) {
	w.writeLock.Lock()
	defer w.writeLock.Unlock()

	// only send BinaryMessage
	if err := w.inner.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}

	return len(b), err
}

func (w *wsStream) Close() error {
	var err error
	w.closeOnce.Do(func() {
		err1 := w.inner.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "closed"),
			time.Now().Add(100*time.Millisecond),
		)
		err2 := w.inner.Close()
		switch {
		case err1 != nil:
			err = err1
		case err2 != nil:
			err = err2
		}
	})
	return err
}

func (w *wsStream) LocalAddr() net.Addr {
	return w.inner.LocalAddr()
}

func (w *wsStream) RemoteAddr() net.Addr {
	return w.inner.RemoteAddr()
}

func (w *wsStream) LocalMultiaddr() multiaddr.Multiaddr {
	a, _ := manet.FromNetAddr(w.LocalAddr())
	wsaddr, _ := multiaddr.NewMultiaddr("/ws")
	a = a.Encapsulate(wsaddr)
	return a
}

func (w *wsStream) RemoteMultiaddr() multiaddr.Multiaddr {
	a, _ := manet.FromNetAddr(w.RemoteAddr())
	wsaddr, _ := multiaddr.NewMultiaddr("/ws")
	a = a.Encapsulate(wsaddr)
	return a
}

func (w *wsStream) SetDeadline(t time.Time) error {
	if err := w.inner.SetReadDeadline(t); err != nil {
		return err
	}

	return w.inner.SetWriteDeadline(t)
}

func (w *wsStream) SetReadDeadline(t time.Time) error {
	return w.inner.SetReadDeadline(t)
}

func (w *wsStream) SetWriteDeadline(t time.Time) error {
	return w.inner.SetWriteDeadline(t)
}

func newWsConn(raw *websocket.Conn) *wsStream {
	return &wsStream{inner: raw}
}
