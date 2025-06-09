package tentacle

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

type wsTransport struct {
	timeout time.Duration
	bind    *string
}

func newWSTransport(timeout time.Duration, bind *string) *wsTransport {
	return &wsTransport{timeout: timeout, bind: bind}
}

func (m *wsTransport) dial(addr multiaddr.Multiaddr) (manet.Conn, error) {
	_, host, err := manet.DialArgs(addr)
	if err != nil {
		return nil, err
	}
	resChan := make(chan interface{})

	go func() {
		var defaultDialer *websocket.Dialer
		if m.bind != nil {
			defaultDialer = &websocket.Dialer{
				Proxy:            http.ProxyFromEnvironment,
				HandshakeTimeout: 45 * time.Second,
				NetDial: func(network, addr string) (net.Conn, error) {
					return reuseport.Dial(network, *m.bind, addr)
				},
			}
		} else {
			defaultDialer = websocket.DefaultDialer
		}

		conn, _, err := defaultDialer.Dial("ws://"+host, nil)
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
