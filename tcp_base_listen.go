package tentacle

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

var errListenerClosed = errors.New("listener is closed")

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
	inner          net.Listener
	timeout        time.Duration
	upgradeMode    *upgradeMode
	trustedProxies []net.IP
	global         *globalListenState
	localAddr      string
	incoming       chan manet.Conn
	closed         chan uint
	closeSignal    sync.Once
	closeInner     sync.Once
	closeErr       error
	acceptErrMu    sync.Mutex
	acceptErr      error
}

func newTcpBaseListener(timeout time.Duration, bind *string, addr multiaddr.Multiaddr, mode *upgradeMode, trustedProxies []net.IP, global *globalListenState) (*TcpBaseListenerEnum, error) {
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

	localAddr = preserveListenTransport(localAddr, addr)

	listener := &TcpBaseListenerEnum{
		enum: Normal,
		listener: &tcpBaseListener{
			inner:          tcp,
			timeout:        timeout,
			upgradeMode:    mode,
			trustedProxies: cloneIPs(trustedProxies),
			global:         global,
			localAddr:      local,
			incoming:       make(chan manet.Conn),
			closed:         make(chan uint, 1),
		},
		address: localAddr,
	}

	go listener.listener.serve()

	return listener, nil
}

func preserveListenTransport(localAddr, requested multiaddr.Multiaddr) multiaddr.Multiaddr {
	if findTy(requested) != ws || findTy(localAddr) == ws {
		return localAddr
	}

	wsaddr, err := multiaddr.NewMultiaddr("/ws")
	if err != nil {
		return localAddr
	}
	return localAddr.Encapsulate(wsaddr)
}

func (tl *tcpBaseListener) clean() {
	tl.global.lock.Lock()
	defer tl.global.lock.Unlock()
	delete(tl.global.status, tl.localAddr)
}

func (tl *tcpBaseListener) serve() {
	defer tl.closeSignal.Do(func() {
		close(tl.closed)
	})
	defer tl.clean()

	for {
		conn, err := tl.inner.Accept()
		if err != nil {
			select {
			case <-tl.closed:
				return
			default:
				tl.acceptErrMu.Lock()
				if tl.acceptErr == nil {
					tl.acceptErr = err
				}
				tl.acceptErrMu.Unlock()
				tl.closeInner.Do(func() {
					tl.closeErr = tl.inner.Close()
				})
				tl.closeSignal.Do(func() {
					close(tl.closed)
				})
				return
			}
		}

		go tl.handleConnection(conn)
	}
}

func (tl *tcpBaseListener) handleConnection(conn net.Conn) {
	detector := &protocolDetector{conn: conn, timeout: tl.timeout}
	mode := atomic.LoadUint32((*uint32)(tl.upgradeMode))
	switch mode {
	// only tcp
	case 0b1:
		mconn, err := tl.wrapTCPConn(detector)
		if err != nil {
			conn.Close()
		} else if !tl.deliverIncoming(mconn) {
			return
		}
		// only ws
	case 0b10:
		mconn, err := wsHandle(detector, tl.trustedProxies)
		if err != nil {
			conn.Close()
		} else if !tl.deliverIncoming(mconn) {
			return
		}
		// both tcp and ws
	case 0b11:
		peekData, err := detector.peek(16)
		if err != nil {
			conn.Close()
			return
		}

		if looksLikeHTTPRequestPrefix(peekData) {
			mconn, err := wsHandle(detector, tl.trustedProxies)
			if err != nil {
				conn.Close()
			} else if !tl.deliverIncoming(mconn) {
				return
			}
		} else {
			mconn, err := tl.wrapTCPConn(detector)
			if err != nil {
				conn.Close()
			} else if !tl.deliverIncoming(mconn) {
				return
			}
		}
	}
}

func (tl *tcpBaseListener) deliverIncoming(conn manet.Conn) bool {
	select {
	case <-tl.closed:
		_ = conn.Close()
		return false
	default:
	}

	select {
	case tl.incoming <- conn:
		return true
	case <-tl.closed:
		_ = conn.Close()
		return false
	}
}

func looksLikeHTTPRequestPrefix(peeked []byte) bool {
	if len(peeked) == 0 {
		return false
	}

	for i, b := range peeked {
		switch b {
		case ' ':
			if i == 0 {
				return false
			}
			return looksLikeHTTPRequestLinePrefix(peeked[i+1:])
		case '\r', '\n':
			return false
		default:
			if !isHTTPTokenByte(b) {
				return false
			}
		}
	}

	return false
}

func looksLikeHTTPRequestLinePrefix(peeked []byte) bool {
	if len(peeked) == 0 {
		return false
	}

	for i, b := range peeked {
		switch b {
		case ' ':
			if i == 0 {
				return false
			}
			return looksLikeHTTPVersionPrefix(peeked[i+1:])
		case '\r', '\n':
			return false
		default:
			if !isValidHTTPRequestTargetByte(b) {
				return false
			}
		}
	}

	return true
}

func looksLikeHTTPVersionPrefix(peeked []byte) bool {
	const prefix = "HTTP/"

	if len(peeked) <= len(prefix) {
		return bytes.Equal(peeked, []byte(prefix[:len(peeked)]))
	}
	if !bytes.Equal(peeked[:len(prefix)], []byte(prefix)) {
		return false
	}

	peeked = peeked[len(prefix):]
	if len(peeked) == 0 {
		return true
	}
	if !isDigit(peeked[0]) {
		return false
	}
	if len(peeked) == 1 {
		return true
	}
	if peeked[1] != '.' {
		return false
	}
	if len(peeked) == 2 {
		return true
	}
	if !isDigit(peeked[2]) {
		return false
	}
	if len(peeked) == 3 {
		return true
	}
	if peeked[3] != '\r' {
		return false
	}
	if len(peeked) == 4 {
		return true
	}
	return len(peeked) == 5 && peeked[4] == '\n'
}

func isValidHTTPRequestTargetByte(b byte) bool {
	return b > ' ' && b < 0x7f
}

func isHTTPTokenByte(b byte) bool {
	switch {
	case b >= '0' && b <= '9':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	}

	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func (tl *tcpBaseListener) wrapTCPConn(conn net.Conn) (manet.Conn, error) {
	detector, ok := conn.(*protocolDetector)
	if !ok {
		detector = &protocolDetector{conn: conn, timeout: tl.timeout}
	}

	remoteAddr := tcpAddrFromNetAddr(detector.RemoteAddr())
	if remoteAddr != nil && containsTrustedProxy(tl.trustedProxies, remoteAddr.IP) {
		proxyAddr, err := parseProxyProtocolFromConn(detector)
		if err != nil {
			return nil, err
		}
		if proxyAddr != nil {
			remoteAddr = proxyAddr
		}
	}

	mconn, err := manet.WrapNetConn(detector)
	if err != nil {
		return nil, err
	}

	return wrapObservedConn(mconn, remoteAddr)
}

func (tl *tcpBaseListener) Accept() (manet.Conn, error) {
	select {
	case conn, ok := <-tl.incoming:
		if !ok {
			return nil, errListenerClosed
		}
		return conn, nil
	case <-tl.closed:
		tl.acceptErrMu.Lock()
		err := tl.acceptErr
		tl.acceptErrMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, errListenerClosed
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
	tl.closeSignal.Do(func() {
		close(tl.closed)
	})
	tl.closeInner.Do(func() {
		tl.closeErr = tl.inner.Close()
	})
	return tl.closeErr
}

var upgrader = websocket.Upgrader{
	// Allow requests from *all* origins.
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func wsHandle(conn net.Conn, trustedProxies []net.IP) (manet.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeoutFromConn(conn))); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)

	// read the HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		if isReadTimeout(err) {
			return nil, ErrListenerTimeout
		}
		return nil, err
	}

	respWriter := &connResponseWriter{
		conn:   conn,
		reader: reader,
		header: make(http.Header),
	}

	ws, err := upgrader.Upgrade(respWriter, req, nil)
	if err != nil {
		if isReadTimeout(err) {
			return nil, ErrListenerTimeout
		}
		return nil, err
	}

	mconn := manet.Conn(newWsConn(ws))

	remoteAddr := tcpAddrFromNetAddr(conn.RemoteAddr())
	if remoteAddr != nil && containsTrustedProxy(trustedProxies, remoteAddr.IP) {
		remoteAddr = extractForwardedAddrFromHeaders(req.Header, remoteAddr)
	}

	return wrapObservedConn(mconn, remoteAddr)
}

func timeoutFromConn(conn net.Conn) time.Duration {
	if detector, ok := conn.(*protocolDetector); ok && detector.timeout > 0 {
		return detector.timeout
	}
	return 10 * time.Second
}

// connResponseWriter impl http.ResponseWriter interface
type connResponseWriter struct {
	conn        net.Conn
	reader      *bufio.Reader
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

	reader := w.reader
	if reader == nil {
		reader = bufio.NewReader(w.conn)
	}
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
	timeout    time.Duration
	peeked     []byte
	peekedRead int
}

const protocolDetectorScratchSize = 16

func (pd *protocolDetector) peek(n int) ([]byte, error) {
	peeked, err := pd.peekUpTo(n)
	if err != nil {
		return nil, err
	}
	if len(peeked) < n {
		return nil, ErrListenerTimeout
	}
	return peeked[:n], nil
}

func (pd *protocolDetector) peekAvailableUntil(n int, deadline time.Time) ([]byte, error) {
	if len(pd.peeked) > 0 {
		if len(pd.peeked) >= n {
			return pd.peeked[:n], nil
		}
		return pd.peeked, nil
	}

	if err := pd.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer pd.conn.SetReadDeadline(time.Time{})

	var scratch [protocolDetectorScratchSize]byte
	buf := scratch[:]
	if n < len(buf) {
		buf = buf[:n]
	} else if n > len(buf) {
		buf = make([]byte, n)
	}
	readCount, err := pd.conn.Read(buf)
	if readCount > 0 {
		pd.peeked = append(pd.peeked, buf[:readCount]...)
	}
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if len(pd.peeked) > 0 {
				return pd.peeked, nil
			}
			return nil, ErrListenerTimeout
		}
		if errors.Is(err, io.EOF) && len(pd.peeked) > 0 {
			return pd.peeked, nil
		}
		return nil, err
	}

	return pd.peeked, nil
}

func (pd *protocolDetector) peekUpTo(n int) ([]byte, error) {
	return pd.peekUpToUntil(n, time.Now().Add(pd.readTimeout()))
}

func (pd *protocolDetector) peekUpToUntil(n int, deadline time.Time) ([]byte, error) {
	if len(pd.peeked) >= n {
		return pd.peeked[:n], nil
	}

	if err := pd.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer pd.conn.SetReadDeadline(time.Time{})

	for len(pd.peeked) < n {
		remaining := n - len(pd.peeked)
		var scratch [protocolDetectorScratchSize]byte
		buf := scratch[:]
		if remaining < len(buf) {
			buf = buf[:remaining]
		} else if remaining > len(buf) {
			buf = make([]byte, remaining)
		}
		readCount, err := pd.conn.Read(buf)
		if readCount > 0 {
			pd.peeked = append(pd.peeked, buf[:readCount]...)
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if len(pd.peeked) > 0 {
					return pd.peeked, nil
				}
				return nil, ErrListenerTimeout
			}
			if errors.Is(err, io.EOF) && len(pd.peeked) > 0 {
				return pd.peeked, nil
			}
			return nil, err
		}
	}

	return pd.peeked[:n], nil
}

func (pd *protocolDetector) readTimeout() time.Duration {
	timeout := pd.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return timeout
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

type observedConn struct {
	manet.Conn
	remoteAddr      net.Addr
	remoteMultiaddr multiaddr.Multiaddr
}

func (c *observedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *observedConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return c.remoteMultiaddr
}

func wrapObservedConn(conn manet.Conn, remoteAddr *net.TCPAddr) (manet.Conn, error) {
	if remoteAddr == nil {
		return conn, nil
	}
	if sameTCPAddr(remoteAddr, tcpAddrFromNetAddr(conn.RemoteAddr())) {
		return conn, nil
	}

	remoteMultiaddr, err := manet.FromNetAddr(remoteAddr)
	if err != nil {
		return nil, err
	}
	if findTy(conn.RemoteMultiaddr()) == ws {
		wsaddr, _ := multiaddr.NewMultiaddr("/ws")
		remoteMultiaddr = remoteMultiaddr.Encapsulate(wsaddr)
	}

	return &observedConn{
		Conn:            conn,
		remoteAddr:      remoteAddr,
		remoteMultiaddr: remoteMultiaddr,
	}, nil
}

func sameTCPAddr(a, b *net.TCPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Port != b.Port || a.Zone != b.Zone {
		return false
	}
	return a.IP.Equal(b.IP)
}

func tcpAddrFromNetAddr(addr net.Addr) *net.TCPAddr {
	if addr == nil {
		return nil
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return cloneTCPAddr(tcpAddr)
	}

	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	parsedPort, err := parseStrictPort(port)
	if err != nil {
		return nil
	}

	zone := ""
	if zoneIndex := strings.LastIndex(host, "%"); zoneIndex >= 0 {
		zone = host[zoneIndex+1:]
		host = host[:zoneIndex]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}

	return &net.TCPAddr{IP: ip, Port: parsedPort, Zone: zone}
}

func cloneIPs(ips []net.IP) []net.IP {
	cloned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			cloned = append(cloned, nil)
			continue
		}
		cloned = append(cloned, append(net.IP(nil), ip...))
	}
	return cloned
}
