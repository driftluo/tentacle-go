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
	"testing"
	"time"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func TestParseProxyV1LineTCP4(t *testing.T) {
	addr, err := parseProxyV1Line("PROXY TCP4 203.0.113.9 192.0.2.20 4567 80\r\n")
	if err != nil {
		t.Fatalf("parse proxy v1 line: %v", err)
	}
	if addr == nil {
		t.Fatal("expected proxy v1 address")
	}
	if got := addr.String(); got != "203.0.113.9:4567" {
		t.Fatalf("expected proxy v1 address 203.0.113.9:4567, got %s", got)
	}
}

func TestParseProxyV1LineUnknown(t *testing.T) {
	addr, err := parseProxyV1Line("PROXY UNKNOWN\r\n")
	if err != nil {
		t.Fatalf("parse proxy v1 unknown: %v", err)
	}
	if addr != nil {
		t.Fatalf("expected nil proxy address for UNKNOWN, got %v", addr)
	}
}

func TestParseProxyV1LineRejectsServiceNamePort(t *testing.T) {
	addr, err := parseProxyV1Line("PROXY TCP4 203.0.113.9 192.0.2.20 http 80\r\n")
	if err == nil {
		t.Fatalf("expected invalid port error, got addr %v", addr)
	}
}

func TestParseProxyV1LineRejectsRepeatedSpaces(t *testing.T) {
	addr, err := parseProxyV1Line("PROXY  TCP4 203.0.113.9 192.0.2.20 4567 80\r\n")
	if err == nil {
		t.Fatalf("expected invalid header error for repeated spaces, got addr %v", addr)
	}
}

func TestParseProxyV1LineRejectsTabs(t *testing.T) {
	addr, err := parseProxyV1Line("PROXY\tTCP4 203.0.113.9 192.0.2.20 4567 80\r\n")
	if err == nil {
		t.Fatalf("expected invalid header error for tab separator, got addr %v", addr)
	}
}

func TestParseProxyV2BytesIPv4(t *testing.T) {
	header := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,
		0x11,
		0x00, 0x0C,
	}
	addrData := []byte{
		198, 51, 100, 7,
		192, 0, 2, 33,
		0x15, 0xB3,
		0x01, 0xBB,
	}

	addr, err := parseProxyV2Bytes(header, addrData)
	if err != nil {
		t.Fatalf("parse proxy v2 bytes: %v", err)
	}
	if addr == nil {
		t.Fatal("expected proxy v2 address")
	}
	if got := addr.String(); got != "198.51.100.7:5555" {
		t.Fatalf("expected proxy v2 address 198.51.100.7:5555, got %s", got)
	}
}

func TestParseProxyV2BytesLocalCommand(t *testing.T) {
	header := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x20,
		0x00,
		0x00, 0x00,
	}

	addr, err := parseProxyV2Bytes(header, nil)
	if err != nil {
		t.Fatalf("parse proxy v2 local command: %v", err)
	}
	if addr != nil {
		t.Fatalf("expected nil proxy address for LOCAL command, got %v", addr)
	}
}

func TestExtractForwardedAddrFromHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Forwarded-For", "198.51.100.30, 127.0.0.1")
	headers.Set("X-Forwarded-Port", "23456")

	fallback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	addr := extractForwardedAddrFromHeaders(headers, fallback)
	if got := addr.String(); got != "198.51.100.30:23456" {
		t.Fatalf("expected forwarded address 198.51.100.30:23456, got %s", got)
	}
}

func TestExtractForwardedAddrFromHeadersRejectsServiceNamePort(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Forwarded-For", "198.51.100.30")
	headers.Set("X-Forwarded-Port", "http")

	fallback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	addr := extractForwardedAddrFromHeaders(headers, fallback)
	if got := addr.String(); got != "198.51.100.30:8080" {
		t.Fatalf("expected forwarded address 198.51.100.30:8080, got %s", got)
	}
}

func TestServiceBuilderTrustedProxiesConfiguration(t *testing.T) {
	builder := DefaultServiceBuilder()

	if !containsTrustedProxy(builder.config.trustedProxies, net.ParseIP("127.0.0.1")) {
		t.Fatalf("default trusted proxies missing 127.0.0.1: %v", builder.config.trustedProxies)
	}
	if !containsTrustedProxy(builder.config.trustedProxies, net.ParseIP("::1")) {
		t.Fatalf("default trusted proxies missing ::1: %v", builder.config.trustedProxies)
	}

	builder = builder.TrustedProxies([]net.IP{net.ParseIP("10.0.0.8")})
	if len(builder.config.trustedProxies) != 1 {
		t.Fatalf("expected trusted proxies to be replaced, got %v", builder.config.trustedProxies)
	}
	if !builder.config.trustedProxies[0].Equal(net.ParseIP("10.0.0.8")) {
		t.Fatalf("expected trusted proxy 10.0.0.8, got %v", builder.config.trustedProxies)
	}
}

func TestWrapTCPConnUsesProxyProtocolForTrustedProxy(t *testing.T) {
	raw := []byte("PROXY TCP4 203.0.113.9 192.0.2.20 4567 80\r\nhello")
	conn := &stubConn{
		reader:     bytes.NewReader(raw),
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}

	listener := &tcpBaseListener{
		timeout:        time.Second,
		trustedProxies: []net.IP{net.ParseIP("127.0.0.1")},
	}

	wrapped, err := listener.wrapTCPConn(conn)
	if err != nil {
		t.Fatalf("wrap trusted proxy conn: %v", err)
	}

	if got := wrapped.RemoteMultiaddr().String(); got != "/ip4/203.0.113.9/tcp/4567" {
		t.Fatalf("expected trusted proxy remote addr /ip4/203.0.113.9/tcp/4567, got %s", got)
	}

	payload := make([]byte, 5)
	if _, err := wrapped.Read(payload); err != nil {
		t.Fatalf("read trusted proxy payload: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("expected trusted proxy payload hello, got %q", payload)
	}
}

func TestParseProxyProtocolFromConnTimesOutOnIncompleteHeader(t *testing.T) {
	conn := &deadlineAwareConn{
		prefix:          []byte("PROXY "),
		localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		noDeadlineDelay: 200 * time.Millisecond,
	}
	detector := &protocolDetector{conn: conn, timeout: 20 * time.Millisecond}

	start := time.Now()
	addr, err := parseProxyProtocolFromConn(detector)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout, got addr=%v err=%v", addr, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected timeout before 100ms, got %s", elapsed)
	}
}

func TestParseProxyProtocolFromConnDoesSingleReadForShortNonProxyPrefix(t *testing.T) {
	conn := &deadlineAwareConn{
		prefix:          []byte("HELLO"),
		localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		noDeadlineDelay: 200 * time.Millisecond,
	}
	detector := &protocolDetector{conn: conn, timeout: 20 * time.Millisecond}

	addr, err := parseProxyProtocolFromConn(detector)
	if err != nil {
		t.Fatalf("expected non-proxy without error, got addr=%v err=%v", addr, err)
	}
	if addr != nil {
		t.Fatalf("expected nil address for non-proxy prefix, got %v", addr)
	}
	if conn.readCalls != 1 {
		t.Fatalf("expected exactly one read for short non-proxy prefix, got %d", conn.readCalls)
	}
}

func TestParseProxyProtocolFromConnDetectsSplitProxyV1Prefix(t *testing.T) {
	conn := &segmentedConn{
		segments: [][]byte{
			[]byte("PRO"),
			[]byte("XY TCP4 203.0.113.9 192.0.2.20 4567 80\r\n"),
		},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}
	detector := &protocolDetector{conn: conn, timeout: time.Second}

	addr, err := parseProxyProtocolFromConn(detector)
	if err != nil {
		t.Fatalf("expected split proxy v1 header to parse, got err=%v", err)
	}
	if addr == nil {
		t.Fatal("expected proxy address from split proxy v1 header")
	}
	if got := addr.String(); got != "203.0.113.9:4567" {
		t.Fatalf("expected proxy v1 address 203.0.113.9:4567, got %s", got)
	}
}

func TestParseProxyProtocolFromConnDetectsSplitProxyV2Signature(t *testing.T) {
	conn := &segmentedConn{
		segments: [][]byte{
			append([]byte(nil), proxyV2Signature...),
			{
				0x21,
				0x11,
				0x00, 0x0C,
				198, 51, 100, 7,
				192, 0, 2, 33,
				0x15, 0xB3,
				0x01, 0xBB,
			},
		},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}
	detector := &protocolDetector{conn: conn, timeout: time.Second}

	addr, err := parseProxyProtocolFromConn(detector)
	if err != nil {
		t.Fatalf("expected split proxy v2 header to parse, got err=%v", err)
	}
	if addr == nil {
		t.Fatal("expected proxy address from split proxy v2 header")
	}
	if got := addr.String(); got != "198.51.100.7:5555" {
		t.Fatalf("expected proxy v2 address 198.51.100.7:5555, got %s", got)
	}
}

func TestParseProxyProtocolFromConnTimesOutOnPartialProxyV1Prefix(t *testing.T) {
	conn := &deadlineAwareConn{
		prefix:          []byte("PRO"),
		localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		noDeadlineDelay: 200 * time.Millisecond,
	}
	detector := &protocolDetector{conn: conn, timeout: 20 * time.Millisecond}

	start := time.Now()
	addr, err := parseProxyProtocolFromConn(detector)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout for partial proxy v1 prefix, got addr=%v err=%v", addr, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected timeout before 100ms, got %s", elapsed)
	}
}

func TestParseProxyProtocolFromConnTimesOutOnPartialProxyV2SignaturePrefix(t *testing.T) {
	conn := &deadlineAwareConn{
		prefix:          append([]byte(nil), proxyV2Signature[:11]...),
		localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		noDeadlineDelay: 200 * time.Millisecond,
	}
	detector := &protocolDetector{conn: conn, timeout: 20 * time.Millisecond}

	start := time.Now()
	addr, err := parseProxyProtocolFromConn(detector)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout for partial proxy v2 signature, got addr=%v err=%v", addr, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected timeout before 100ms, got %s", elapsed)
	}
}

func TestParseProxyProtocolFromConnDoesNotExtendDetectionDeadline(t *testing.T) {
	conn := &deadlineTrackingConn{
		prefix:         []byte("PRO"),
		firstReadDelay: 40 * time.Millisecond,
		localAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}
	detector := &protocolDetector{conn: conn, timeout: 50 * time.Millisecond}

	addr, err := parseProxyProtocolFromConn(detector)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout, got addr=%v err=%v", addr, err)
	}
	if len(conn.deadlines) == 0 {
		t.Fatal("expected at least one read deadline to be set")
	}
	if len(conn.deadlines) > 1 && conn.deadlines[1].After(conn.deadlines[0].Add(5*time.Millisecond)) {
		t.Fatalf("expected detection to reuse initial timeout budget, got deadlines %v", conn.deadlines)
	}
}

func TestParseProxyProtocolFromConnDoesNotExtendHeaderReadDeadline(t *testing.T) {
	conn := &deadlineTrackingConn{
		prefix:         []byte("PROXY TCP4 20"),
		firstReadDelay: 40 * time.Millisecond,
		localAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}
	detector := &protocolDetector{conn: conn, timeout: 50 * time.Millisecond}

	addr, err := parseProxyProtocolFromConn(detector)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout, got addr=%v err=%v", addr, err)
	}
	if len(conn.deadlines) < 2 {
		t.Fatalf("expected header read to set at least two deadlines, got %v", conn.deadlines)
	}
	if conn.deadlines[1].After(conn.deadlines[0].Add(5 * time.Millisecond)) {
		t.Fatalf("expected header read to reuse initial timeout budget, got deadlines %v", conn.deadlines)
	}
}

func TestParseProxyProtocolFromConnTimesOutOnExactProxyV2Signature(t *testing.T) {
	conn := &deadlineAwareConn{
		prefix:          append([]byte(nil), proxyV2Signature...),
		localAddr:       &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr:      &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		noDeadlineDelay: 200 * time.Millisecond,
	}
	detector := &protocolDetector{conn: conn, timeout: 20 * time.Millisecond}

	start := time.Now()
	addr, err := parseProxyProtocolFromConn(detector)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrListenerTimeout) {
		t.Fatalf("expected ErrListenerTimeout for exact proxy v2 signature, got addr=%v err=%v", addr, err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected timeout before 100ms, got %s", elapsed)
	}
}

func TestWrapTCPConnSkipsProxyProtocolForUntrustedPeer(t *testing.T) {
	raw := []byte("PROXY TCP4 203.0.113.9 192.0.2.20 4567 80\r\nhello")
	conn := &stubConn{
		reader:     bytes.NewReader(raw),
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 9000},
	}

	listener := &tcpBaseListener{
		timeout:        time.Second,
		trustedProxies: []net.IP{net.ParseIP("127.0.0.1")},
	}

	wrapped, err := listener.wrapTCPConn(conn)
	if err != nil {
		t.Fatalf("wrap untrusted proxy conn: %v", err)
	}

	if got := wrapped.RemoteMultiaddr().String(); got != "/ip4/10.0.0.9/tcp/9000" {
		t.Fatalf("expected untrusted peer remote addr /ip4/10.0.0.9/tcp/9000, got %s", got)
	}

	payload := make([]byte, len(raw))
	if _, err := wrapped.Read(payload); err != nil {
		t.Fatalf("read untrusted proxy payload: %v", err)
	}
	if string(payload) != string(raw) {
		t.Fatalf("expected untrusted peer payload %q, got %q", raw, payload)
	}
}

func TestWrapObservedConnPreservesWSProtocol(t *testing.T) {
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.30"), Port: 23456}
	originalAddr, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/8080/ws")
	if err != nil {
		t.Fatalf("new ws multiaddr: %v", err)
	}

	conn := &stubManetConn{
		stubConn: stubConn{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		},
		remoteMultiaddr: originalAddr,
	}

	wrapped, err := wrapObservedConn(conn, remoteAddr)
	if err != nil {
		t.Fatalf("wrap observed ws conn: %v", err)
	}

	if got := wrapped.RemoteMultiaddr().String(); got != "/ip4/198.51.100.30/tcp/23456/ws" {
		t.Fatalf("expected wrapped ws remote addr /ip4/198.51.100.30/tcp/23456/ws, got %s", got)
	}
}

func TestWrapObservedConnSkipsWrappingWhenRemoteAddrUnchanged(t *testing.T) {
	originalAddr, err := multiaddr.NewMultiaddr("/ip4/198.51.100.30/tcp/23456")
	if err != nil {
		t.Fatalf("new tcp multiaddr: %v", err)
	}

	conn := &stubManetConn{
		stubConn: stubConn{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("198.51.100.30"), Port: 23456},
		},
		remoteMultiaddr: originalAddr,
	}

	wrapped, err := wrapObservedConn(conn, &net.TCPAddr{IP: net.ParseIP("198.51.100.30"), Port: 23456})
	if err != nil {
		t.Fatalf("wrap observed tcp conn: %v", err)
	}

	got, ok := wrapped.(*stubManetConn)
	if !ok || got != conn {
		t.Fatalf("expected unchanged remote addr to reuse original conn, got %T", wrapped)
	}
}

func TestTCPAddrFromNetAddrParsesIPv6ZoneString(t *testing.T) {
	addr := tcpAddrFromNetAddr(staticNetAddr("[fe80::1%eth0]:1234"))
	if addr == nil {
		t.Fatal("expected tcp addr from ipv6 zone string")
	}
	if addr.Port != 1234 {
		t.Fatalf("expected port 1234, got %d", addr.Port)
	}
	if addr.Zone != "eth0" {
		t.Fatalf("expected zone eth0, got %q", addr.Zone)
	}
	if got := addr.IP.String(); got != "fe80::1" {
		t.Fatalf("expected ip fe80::1, got %s", got)
	}
}

func TestTCPAddrFromNetAddrRejectsServiceNamePort(t *testing.T) {
	addr := tcpAddrFromNetAddr(staticNetAddr("127.0.0.1:http"))
	if addr != nil {
		t.Fatalf("expected nil tcp addr for service-name port, got %v", addr)
	}
}

func TestWSHandleRejectsBufferedDataBeforeHandshakeComplete(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan struct{})
	errCh := make(chan error, 2)

	go func() {
		_, err := wsHandle(serverConn, nil)
		errCh <- err
		close(done)
	}()

	go func() {
		req := []byte(
			"GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"\r\n",
		)
		frame := maskedWSFrame([]byte("hi"))
		if _, err := clientConn.Write(append(req, frame...)); err != nil {
			errCh <- err
			return
		}

		<-done
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected websocket upgrade to reject buffered client data")
		}
		if !strings.Contains(err.Error(), "before handshake is complete") {
			t.Fatalf("expected early-data handshake error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for websocket handshake result")
	}
}

func TestWSHandleTimesOutOnIncompleteHandshake(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	detector := &protocolDetector{conn: serverConn, timeout: 20 * time.Millisecond}
	errCh := make(chan error, 1)
	start := time.Now()

	go func() {
		_, err := wsHandle(detector, nil)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrListenerTimeout) {
			t.Fatalf("expected ErrListenerTimeout, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("expected websocket handshake timeout before 100ms, got %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for websocket handshake timeout result")
	}
}

func TestLooksLikeHTTPRequestPrefix(t *testing.T) {
	if !looksLikeHTTPRequestPrefix([]byte("OPTIONS * HTTP/1.1\r\n")) {
		t.Fatal("expected OPTIONS request prefix to be detected")
	}
	if !looksLikeHTTPRequestPrefix([]byte("POST /rpc HTTP/1.")) {
		t.Fatal("expected POST request prefix to be detected")
	}
	if looksLikeHTTPRequestPrefix([]byte("P\x00ST /rpc HTTP/1.1")) {
		t.Fatal("expected invalid method token to be rejected")
	}
}

func TestMixedListenerRoutesNonGETHTTPRequestToWSHandler(t *testing.T) {
	mode := upgradeMode(0b11)
	listener := &tcpBaseListener{
		timeout:     100 * time.Millisecond,
		upgradeMode: &mode,
		incoming:    make(chan manet.Conn, 1),
		closed:      make(chan uint, 1),
	}

	conn := &stubConn{
		reader: bytes.NewReader([]byte(
			"OPTIONS * HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
		)),
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1337},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
	}

	listener.handleConnection(conn)

	select {
	case incoming := <-listener.incoming:
		t.Fatalf("expected non-GET HTTP request to stay out of tcp incoming path, got %T", incoming)
	default:
	}

	if !strings.HasPrefix(conn.writes.String(), "HTTP/1.1") {
		t.Fatalf("expected ws handler to write an HTTP response, got %q", conn.writes.String())
	}
}

func TestServiceListenerUsesProxyProtocolRemoteAddr(t *testing.T) {
	handle := newRecordingServiceHandle()
	service := DefaultServiceBuilder().
		TimeOut(time.Second).
		TrustedProxies([]net.IP{net.ParseIP("127.0.0.1")}).
		Build(handle)
	defer shutdownServiceAndWait(t, service)

	listenAddr, err := service.Listen(mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("listen tcp service: %v", err)
	}

	_, host, err := manet.DialArgs(listenAddr)
	if err != nil {
		t.Fatalf("dial args for tcp listener: %v", err)
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial tcp listener: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "PROXY TCP4 203.0.113.9 127.0.0.1 4567 80\r\n"); err != nil {
		t.Fatalf("write proxy header: %v", err)
	}

	addr := waitForRecordedRemoteAddr(t, handle)
	if got := addr.String(); got != "/ip4/203.0.113.9/tcp/4567" {
		t.Fatalf("expected inbound session remote addr /ip4/203.0.113.9/tcp/4567, got %s", got)
	}
}

func TestServiceListenerUsesForwardedHeadersForWSRemoteAddr(t *testing.T) {
	handle := newRecordingServiceHandle()
	service := DefaultServiceBuilder().
		TimeOut(time.Second).
		TrustedProxies([]net.IP{net.ParseIP("127.0.0.1")}).
		Build(handle)
	defer shutdownServiceAndWait(t, service)

	listenAddr, err := service.Listen(mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0/ws"))
	if err != nil {
		t.Fatalf("listen ws service: %v", err)
	}

	_, host, err := manet.DialArgs(listenAddr)
	if err != nil {
		t.Fatalf("dial args for ws listener: %v", err)
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial ws listener: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"X-Forwarded-For: 198.51.100.30\r\n"+
			"X-Forwarded-Port: 23456\r\n"+
			"\r\n",
		host,
	)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write ws upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read ws status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("expected websocket 101 response, got %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read ws response header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	addr := waitForRecordedRemoteAddr(t, handle)
	if got := addr.String(); got != "/ip4/198.51.100.30/tcp/23456/ws" {
		t.Fatalf("expected inbound ws session remote addr /ip4/198.51.100.30/tcp/23456/ws, got %s", got)
	}
}

func TestWSBindAllowsDialFromWSListenPort(t *testing.T) {
	remoteHandle := newRecordingServiceHandle()
	remote := DefaultServiceBuilder().
		TimeOut(time.Second).
		Build(remoteHandle)
	defer shutdownServiceAndWait(t, remote)

	remoteAddr, err := remote.Listen(mustMultiaddr(t, "/ip4/127.0.0.1/tcp/0/ws"))
	if err != nil {
		t.Fatalf("listen remote ws service: %v", err)
	}

	bindPort := reserveLocalTCPPort(t)
	localBindAddr := mustMultiaddr(t, fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/ws", bindPort))
	localHandle := newRecordingServiceHandle()
	local := DefaultServiceBuilder().
		TimeOut(time.Second).
		WsBind(localBindAddr).
		Build(localHandle)
	defer shutdownServiceAndWait(t, local)

	if _, err := local.Listen(localBindAddr); err != nil {
		t.Fatalf("listen local ws service on bind port: %v", err)
	}
	if err := local.Dial(remoteAddr, TargetProtocol{Tag: All}); err != nil {
		t.Fatalf("dial remote ws service: %v", err)
	}

	select {
	case addr := <-remoteHandle.addrCh:
		expected := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/ws", bindPort)
		if got := addr.String(); got != expected {
			t.Fatalf("expected remote service to observe ws bind addr %s, got %s", expected, got)
		}
	case err := <-localHandle.errCh:
		t.Fatalf("local service error before remote session open: %v", err)
	case err := <-remoteHandle.errCh:
		t.Fatalf("remote service error before session open: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for remote inbound ws session")
	}
}

func mustMultiaddr(t *testing.T, raw string) multiaddr.Multiaddr {
	t.Helper()

	addr, err := multiaddr.NewMultiaddr(raw)
	if err != nil {
		t.Fatalf("new multiaddr %s: %v", raw, err)
	}
	return addr
}

type recordingServiceHandle struct {
	addrCh chan multiaddr.Multiaddr
	errCh  chan error
}

func newRecordingServiceHandle() *recordingServiceHandle {
	return &recordingServiceHandle{
		addrCh: make(chan multiaddr.Multiaddr, 1),
		errCh:  make(chan error, 1),
	}
}

func (h *recordingServiceHandle) HandleEvent(ctx *ServiceContext, event ServiceEvent) {
	if event.Name() != "SessionOpen" {
		return
	}

	inner := event.Event.(*SessionContext)
	if inner.Ty.Name() != "Inbound" {
		return
	}

	select {
	case h.addrCh <- inner.RemoteAddr:
	default:
	}
}

func (h *recordingServiceHandle) HandleError(ctx *ServiceContext, event ServiceError) {
	select {
	case h.errCh <- fmt.Errorf("service error %s: %v", event.Name(), event.Event):
	default:
	}
}

func waitForRecordedRemoteAddr(t *testing.T, handle *recordingServiceHandle) multiaddr.Multiaddr {
	t.Helper()

	select {
	case addr := <-handle.addrCh:
		return addr
	case err := <-handle.errCh:
		t.Fatalf("unexpected service error before session open: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for inbound session open")
	}
	return nil
}

func reserveLocalTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local tcp port: %v", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected tcp listener addr, got %T", listener.Addr())
	}
	return addr.Port
}

func shutdownServiceAndWait(t *testing.T, service *Service) {
	t.Helper()

	if service == nil {
		return
	}
	if err := service.Shutdown(); err != nil && !errors.Is(err, ErrBrokenPipe) {
		t.Fatalf("shutdown service: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !service.IsShutdown() {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for service shutdown")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type stubConn struct {
	reader     *bytes.Reader
	writes     bytes.Buffer
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *stubConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *stubConn) Write(b []byte) (int, error) {
	return c.writes.Write(b)
}

func (c *stubConn) Close() error {
	return nil
}

func (c *stubConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *stubConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *stubConn) SetDeadline(time.Time) error {
	return nil
}

func (c *stubConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *stubConn) SetWriteDeadline(time.Time) error {
	return nil
}

type stubManetConn struct {
	stubConn
	remoteMultiaddr multiaddr.Multiaddr
}

func (c *stubManetConn) LocalMultiaddr() multiaddr.Multiaddr {
	addr, _ := manet.FromNetAddr(c.localAddr)
	return addr
}

func (c *stubManetConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return c.remoteMultiaddr
}

type staticNetAddr string

func (a staticNetAddr) Network() string { return "tcp" }
func (a staticNetAddr) String() string  { return string(a) }

type segmentedConn struct {
	segments      [][]byte
	segmentOffset int
	localAddr     net.Addr
	remoteAddr    net.Addr
}

func (c *segmentedConn) Read(b []byte) (int, error) {
	if len(c.segments) == 0 {
		return 0, io.EOF
	}

	segment := c.segments[0][c.segmentOffset:]
	n := copy(b, segment)
	c.segmentOffset += n
	if c.segmentOffset >= len(c.segments[0]) {
		c.segments = c.segments[1:]
		c.segmentOffset = 0
	}
	return n, nil
}

func (c *segmentedConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *segmentedConn) Close() error {
	return nil
}

func (c *segmentedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *segmentedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *segmentedConn) SetDeadline(time.Time) error {
	return nil
}

func (c *segmentedConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *segmentedConn) SetWriteDeadline(time.Time) error {
	return nil
}

type deadlineAwareConn struct {
	prefix          []byte
	sentPrefix      bool
	localAddr       net.Addr
	remoteAddr      net.Addr
	readDeadline    time.Time
	noDeadlineDelay time.Duration
	readCalls       int
}

func (c *deadlineAwareConn) Read(b []byte) (int, error) {
	c.readCalls++
	if !c.sentPrefix {
		c.sentPrefix = true
		return copy(b, c.prefix), nil
	}

	if !c.readDeadline.IsZero() {
		wait := time.Until(c.readDeadline)
		if wait > 0 {
			time.Sleep(wait)
		}
		return 0, timeoutNetError{}
	}

	time.Sleep(c.noDeadlineDelay)
	return 0, errors.New("read without deadline")
}

func (c *deadlineAwareConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *deadlineAwareConn) Close() error {
	return nil
}

func (c *deadlineAwareConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *deadlineAwareConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *deadlineAwareConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *deadlineAwareConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *deadlineAwareConn) SetWriteDeadline(time.Time) error {
	return nil
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

type deadlineTrackingConn struct {
	prefix         []byte
	sentPrefix     bool
	firstReadDelay time.Duration
	localAddr      net.Addr
	remoteAddr     net.Addr
	readDeadline   time.Time
	deadlines      []time.Time
}

func (c *deadlineTrackingConn) Read(b []byte) (int, error) {
	if !c.sentPrefix {
		c.sentPrefix = true
		time.Sleep(c.firstReadDelay)
		return copy(b, c.prefix), nil
	}

	if !c.readDeadline.IsZero() {
		if wait := time.Until(c.readDeadline); wait > 0 {
			time.Sleep(wait)
		}
		return 0, timeoutNetError{}
	}

	return 0, errors.New("read without deadline")
}

func (c *deadlineTrackingConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *deadlineTrackingConn) Close() error {
	return nil
}

func (c *deadlineTrackingConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *deadlineTrackingConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *deadlineTrackingConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	if !t.IsZero() {
		c.deadlines = append(c.deadlines, t)
	}
	return nil
}

func (c *deadlineTrackingConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	if !t.IsZero() {
		c.deadlines = append(c.deadlines, t)
	}
	return nil
}

func (c *deadlineTrackingConn) SetWriteDeadline(time.Time) error {
	return nil
}

func maskedWSFrame(payload []byte) []byte {
	mask := []byte{1, 2, 3, 4}
	frame := []byte{0x82, 0x80 | byte(len(payload))}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	return frame
}
