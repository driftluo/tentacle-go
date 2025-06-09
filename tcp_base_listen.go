package tentacle

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

const (
	UpgradeMode uint8 = iota
	Normal
)

type upgradeMode uint32

func (m *upgradeMode) combine(other *upgradeMode) {
	for {
		old := atomic.LoadUint32((*uint32)(m))
		newVal := old | uint32(*other)
		if atomic.CompareAndSwapUint32((*uint32)(m), old, newVal) {
			return
		}
	}
}

type TcpBaseListenerEnum struct {
	enum     uint8
	listener *tcpBaseListener
	address  multiaddr.Multiaddr
}

type globalListenState struct {
	status map[string]*upgradeMode
	lock   sync.Mutex
}

type tcpBaseListener struct {
	inner       net.Listener
	upgradeMode *upgradeMode
	global      *globalListenState
	localAddr   string
	incoming    chan manet.Conn
	closed      chan uint
}

func newTcpBaseListener(timeout time.Duration, bind *string, addr multiaddr.Multiaddr, mode *upgradeMode, global *globalListenState) (*TcpBaseListenerEnum, error) {
	netTy, host, err := manet.DialArgs(addr)
	if err != nil {
		return nil, err
	}
	// Extract the port from the host:port format
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}

	var tcp net.Listener
	var local string
	var localAddr multiaddr.Multiaddr

	if port == "0" {
		tcp, err = tcpListener(netTy, host, bind)
		if err != nil {
			return nil, err
		}
		global.lock.Lock()
		local = tcp.Addr().String()
		localAddr, _ = manet.FromNetAddr(tcp.Addr())
		global.status[local] = mode
		global.lock.Unlock()
	} else {
		global.lock.Lock()
		defer global.lock.Unlock()
		local = host
		localAddr = addr
		if emode, ok := global.status[local]; ok {
			emode.combine(mode)
			return &TcpBaseListenerEnum{enum: UpgradeMode, listener: nil, address: addr}, nil
		} else {
			global.status[local] = mode
		}

		tcp, err = tcpListener(netTy, host, bind)
		if err != nil {
			return nil, err
		}
	}

	listener := &TcpBaseListenerEnum{
		enum: Normal,
		listener: &tcpBaseListener{
			inner:       tcp,
			upgradeMode: mode,
			global:      global,
			localAddr:   local,
			incoming:    make(chan manet.Conn),
			closed:      make(chan uint, 1),
		},
		address: localAddr,
	}

	go listener.listener.serve()

	return listener, nil
}

func (tl *tcpBaseListener) clean() {
	tl.global.lock.Lock()
	defer tl.global.lock.Unlock()
	delete(tl.global.status, tl.localAddr)
}

func (tl *tcpBaseListener) serve() {
	defer close(tl.closed)
	defer tl.clean()

	for {
		conn, err := tl.inner.Accept()
		if err != nil {
			select {
			case <-tl.closed:
				return
			default:
				continue
			}
		}

		go tl.handleConnection(conn)
	}
}

func (tl *tcpBaseListener) handleConnection(conn net.Conn) {
	mode := atomic.LoadUint32((*uint32)(tl.upgradeMode))
	switch mode {
	// only tcp
	case 0b1:
		mconn, err := manet.WrapNetConn(conn)
		if err != nil {
			conn.Close()
		} else {
			tl.incoming <- mconn
		}
		// only ws
	case 0b10:
		mconn, err := wsHandle(conn)
		if err != nil {
			conn.Close()
		} else {
			tl.incoming <- mconn
		}
		// both tcp and ws
	case 0b11:
		detector := &protocolDetector{conn: conn}
		peekData, err := detector.peek(16)
		if err != nil {
			conn.Close()
			return
		}

		dataStr := string(peekData)
		if len(dataStr) >= 3 && dataStr[:3] == "GET" {
			mconn, err := wsHandle(detector)
			if err != nil {
				conn.Close()
			} else {
				tl.incoming <- mconn
			}
		} else {
			mconn, err := manet.WrapNetConn(detector)
			if err != nil {
				conn.Close()
			} else {
				tl.incoming <- mconn
			}
		}
	}
}

func (tl *tcpBaseListener) Accept() (manet.Conn, error) {
	select {
	case conn, ok := <-tl.incoming:
		if !ok {
			return nil, errors.New("listener is closed")
		}
		return conn, nil
	case <-tl.closed:
		return nil, errors.New("listener is closed")
	}
}

func (tl *tcpBaseListener) Multiaddr() multiaddr.Multiaddr {
	muladdr, _ := manet.FromNetAddr(tl.inner.Addr())

	return muladdr
}

func (tl *tcpBaseListener) Addr() net.Addr {
	return tl.inner.Addr()
}

func (tl *tcpBaseListener) Close() error {
	tl.closed <- 0
	return tl.inner.Close()
}

var upgrader = websocket.Upgrader{
	// Allow requests from *all* origins.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func wsHandle(conn net.Conn) (manet.Conn, error) {
	reader := bufio.NewReader(conn)

	// read the HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}

	respWriter := &connResponseWriter{
		conn:   conn,
		header: make(http.Header),
	}

	ws, err := upgrader.Upgrade(respWriter, req, nil)
	if err != nil {
		return nil, err
	}

	return newWsConn(ws), nil
}

// connResponseWriter impl http.ResponseWriter interface
type connResponseWriter struct {
	conn        net.Conn
	header      http.Header
	wroteHeader bool
	hijacked    bool
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusSwitchingProtocols)
	}
	return w.conn.Write(data)
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	// write the HTTP status line
	statusText := http.StatusText(statusCode)
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, statusText)

	// Write Upgrade headers
	for key, values := range w.header {
		for _, value := range values {
			fmt.Fprintf(w.conn, "%s: %s\r\n", key, value)
		}
	}

	// write the empty Upgrade header
	fmt.Fprint(w.conn, "\r\n")
}

// Hijack impl http.Hijacker interface，WebSocket upgrade requires hijacking the connection
func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijacked {
		return nil, nil, errors.New("connection already hijacked")
	}
	w.hijacked = true

	reader := bufio.NewReader(w.conn)
	writer := bufio.NewWriter(w.conn)
	readWriter := bufio.NewReadWriter(reader, writer)

	return w.conn, readWriter, nil
}

func tcpListener(netTy, host string, bind *string) (net.Listener, error) {
	if bind != nil {
		return reuseport.Listen(netTy, host)
	}
	return net.Listen(netTy, host)
}

// protocolDetector is a wrapper around net.Conn that allows peeking at the first few bytes
type protocolDetector struct {
	conn       net.Conn
	peeked     []byte
	peekedRead int
}

func (pd *protocolDetector) peek(n int) ([]byte, error) {
	if len(pd.peeked) >= n {
		return pd.peeked[:n], nil
	}
	needed := n - len(pd.peeked)
	buf := make([]byte, needed)

	resChan := make(chan interface{})
	go func() {
		for {
			readCount, err := pd.conn.Read(buf)
			if err != nil {
				resChan <- err
			}
			pd.peeked = append(pd.peeked, buf[:readCount]...)
			if len(pd.peeked) >= n {
				resChan <- pd.peeked[:n]
				return
			}
		}
	}()

	select {
	case <-time.After(time.Second * 10):
		return nil, ErrListenerTimeout
	case res := <-resChan:
		b, ok := res.([]byte)
		if ok {
			return b, nil
		}
		return nil, res.(error)
	}
}

func (pd *protocolDetector) Read(b []byte) (int, error) {
	// read from peeked data first
	if pd.peekedRead < len(pd.peeked) {
		remaining := len(pd.peeked) - pd.peekedRead
		toCopy := len(b)
		if toCopy > remaining {
			toCopy = remaining
		}

		copy(b[:toCopy], pd.peeked[pd.peekedRead:pd.peekedRead+toCopy])
		pd.peekedRead += toCopy

		// need read more data from the connection
		if toCopy < len(b) && pd.peekedRead >= len(pd.peeked) {
			n, err := pd.conn.Read(b[toCopy:])
			return toCopy + n, err
		}

		return toCopy, nil
	}

	return pd.conn.Read(b)
}

func (pd *protocolDetector) Write(b []byte) (int, error) {
	return pd.conn.Write(b)
}

func (pd *protocolDetector) Close() error {
	return pd.conn.Close()
}

func (pd *protocolDetector) LocalAddr() net.Addr {
	return pd.conn.LocalAddr()
}

func (pd *protocolDetector) RemoteAddr() net.Addr {
	return pd.conn.RemoteAddr()
}

func (pd *protocolDetector) SetDeadline(t time.Time) error {
	return pd.conn.SetDeadline(t)
}

func (pd *protocolDetector) SetReadDeadline(t time.Time) error {
	return pd.conn.SetReadDeadline(t)
}

func (pd *protocolDetector) SetWriteDeadline(t time.Time) error {
	return pd.conn.SetWriteDeadline(t)
}
