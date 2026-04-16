package tentacle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var proxyV2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

var proxyV1Prefix = []byte("PROXY")

const (
	proxyV1MaxLength  = 108
	proxyV2HeaderLen  = 16
	proxyV2MaxAddrLen = 512
)

func parseProxyProtocolFromConn(conn *protocolDetector) (*net.TCPAddr, error) {
	deadline := time.Now().Add(conn.readTimeout())

	peeked, err := conn.peekAvailableUntil(13, deadline)
	if err != nil {
		return nil, err
	}

	if requiresMoreProxyDetectionBytes(peeked) {
		peeked, err = conn.peekUpToUntil(13, deadline)
		if err != nil {
			return nil, err
		}
		if requiresMoreProxyDetectionBytes(peeked) {
			return nil, ErrListenerTimeout
		}
	}

	if len(peeked) >= 13 && bytes.Equal(peeked[:12], proxyV2Signature) && (peeked[12]&0xF0) == 0x20 {
		return conn.withReadDeadline(deadline, func() (*net.TCPAddr, error) {
			return parseProxyV2FromConn(conn)
		})
	}

	if len(peeked) >= 5 && bytes.Equal(peeked[:5], proxyV1Prefix) {
		return conn.withReadDeadline(deadline, func() (*net.TCPAddr, error) {
			return parseProxyV1FromConn(conn)
		})
	}

	return nil, nil
}

// requiresMoreProxyDetectionBytes returns true when the peeked bytes are an
// ambiguous prefix that could still turn into a valid PROXY v1 or v2 header.
// Short prefixes (< 5 bytes) may match both "PROXY" and the v2 binary
// signature simultaneously — this is expected because at that length we
// cannot yet distinguish the two protocols and must wait for more data.
func requiresMoreProxyDetectionBytes(peeked []byte) bool {
	if len(peeked) == 0 || len(peeked) >= 13 {
		return false
	}

	if len(peeked) < len(proxyV1Prefix) && bytes.HasPrefix(proxyV1Prefix, peeked) {
		return true
	}

	if len(peeked) <= len(proxyV2Signature) && bytes.HasPrefix(proxyV2Signature, peeked) {
		return true
	}

	if len(peeked) > len(proxyV2Signature) {
		return bytes.Equal(peeked[:len(proxyV2Signature)], proxyV2Signature)
	}

	return false
}

func parseProxyV1FromConn(conn io.Reader) (*net.TCPAddr, error) {
	var buf [proxyV1MaxLength]byte
	pos := 0

	for {
		if pos >= proxyV1MaxLength {
			return nil, fmt.Errorf("PROXY v1 header too long")
		}

		if _, err := io.ReadFull(conn, buf[pos:pos+1]); err != nil {
			if isReadTimeout(err) {
				return nil, ErrListenerTimeout
			}
			return nil, fmt.Errorf("read PROXY v1 header: %w", err)
		}
		pos++

		if pos >= 2 && buf[pos-2] == '\r' && buf[pos-1] == '\n' {
			break
		}
	}

	return parseProxyV1Line(string(buf[:pos]))
}

func parseProxyV1Line(line string) (*net.TCPAddr, error) {
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")

	parts := strings.Split(line, " ")
	if len(parts) < 2 || parts[0] != "PROXY" {
		return nil, fmt.Errorf("invalid PROXY v1 header")
	}

	switch parts[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
		if len(parts) != 6 {
			return nil, fmt.Errorf("invalid PROXY v1 header, expected 6 parts, got %d", len(parts))
		}

		ip := net.ParseIP(parts[2])
		if ip == nil {
			return nil, fmt.Errorf("invalid PROXY v1 source IP %q", parts[2])
		}

		port, err := parseStrictPort(parts[4])
		if err != nil {
			return nil, fmt.Errorf("invalid PROXY v1 source port %q", parts[4])
		}

		return &net.TCPAddr{IP: ip, Port: port}, nil
	default:
		return nil, fmt.Errorf("unsupported PROXY v1 protocol %q", parts[1])
	}
}

func parseProxyV2FromConn(conn io.Reader) (*net.TCPAddr, error) {
	var header [proxyV2HeaderLen]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		if isReadTimeout(err) {
			return nil, ErrListenerTimeout
		}
		return nil, fmt.Errorf("read PROXY v2 header: %w", err)
	}

	addrLen := int(header[14])<<8 | int(header[15])
	if addrLen > proxyV2MaxAddrLen {
		return nil, fmt.Errorf("PROXY v2 address length %d exceeds maximum %d", addrLen, proxyV2MaxAddrLen)
	}

	var addrBuf [proxyV2MaxAddrLen]byte
	addrData := addrBuf[:addrLen]
	if _, err := io.ReadFull(conn, addrData); err != nil {
		if isReadTimeout(err) {
			return nil, ErrListenerTimeout
		}
		return nil, fmt.Errorf("read PROXY v2 address: %w", err)
	}

	return parseProxyV2Bytes(header[:], addrData)
}

func parseProxyV2Bytes(header []byte, addrData []byte) (*net.TCPAddr, error) {
	if len(header) != proxyV2HeaderLen {
		return nil, fmt.Errorf("invalid PROXY v2 header length %d", len(header))
	}
	if !bytes.Equal(header[:12], proxyV2Signature) {
		return nil, fmt.Errorf("invalid PROXY v2 signature")
	}

	version := (header[12] & 0xF0) >> 4
	command := header[12] & 0x0F
	if version != 2 {
		return nil, fmt.Errorf("unsupported PROXY v2 version %d", version)
	}

	switch command {
	case 0x00:
		return nil, nil
	case 0x01:
	default:
		return nil, fmt.Errorf("unsupported PROXY v2 command %d", command)
	}

	family := (header[13] & 0xF0) >> 4
	switch family {
	case 0x00:
		return nil, nil
	case 0x01:
		if len(addrData) < 12 {
			return nil, fmt.Errorf("PROXY v2 IPv4 address data too short")
		}
		return &net.TCPAddr{
			IP:   net.IPv4(addrData[0], addrData[1], addrData[2], addrData[3]),
			Port: int(addrData[8])<<8 | int(addrData[9]),
		}, nil
	case 0x02:
		if len(addrData) < 36 {
			return nil, fmt.Errorf("PROXY v2 IPv6 address data too short")
		}
		return &net.TCPAddr{
			IP:   append(net.IP(nil), addrData[:16]...),
			Port: int(addrData[32])<<8 | int(addrData[33]),
		}, nil
	case 0x03:
		return nil, nil
	default:
		return nil, nil
	}
}

func extractForwardedAddrFromHeaders(headers http.Header, fallback *net.TCPAddr) *net.TCPAddr {
	if fallback == nil {
		return nil
	}

	rawForwardedFor := headers.Get("X-Forwarded-For")
	if rawForwardedFor == "" {
		return cloneTCPAddr(fallback)
	}

	firstIP := strings.TrimSpace(strings.Split(rawForwardedFor, ",")[0])
	ip := net.ParseIP(firstIP)
	if ip == nil {
		return cloneTCPAddr(fallback)
	}

	port := fallback.Port
	if rawForwardedPort := headers.Get("X-Forwarded-Port"); rawForwardedPort != "" {
		firstPort := strings.TrimSpace(strings.Split(rawForwardedPort, ",")[0])
		if parsedPort, err := parseStrictPort(firstPort); err == nil {
			port = parsedPort
		}
	}

	return &net.TCPAddr{IP: ip, Port: port}
}

func containsTrustedProxy(trusted []net.IP, ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, candidate := range trusted {
		if candidate != nil && candidate.Equal(ip) {
			return true
		}
	}

	return false
}

func cloneTCPAddr(addr *net.TCPAddr) *net.TCPAddr {
	if addr == nil {
		return nil
	}

	return &net.TCPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func (pd *protocolDetector) withReadDeadline(deadline time.Time, fn func() (*net.TCPAddr, error)) (*net.TCPAddr, error) {
	if err := pd.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	defer pd.conn.SetReadDeadline(time.Time{})

	return fn()
}

func isReadTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func parseStrictPort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return port, nil
}
