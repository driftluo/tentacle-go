package tentacle

import (
	"net"
	"time"

	reuseport "github.com/libp2p/go-reuseport"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

type tcpTransport struct {
	timeout time.Duration
	bind    *string
}

func newTCPTransport(timeout time.Duration, bind *string) *tcpTransport {
	return &tcpTransport{timeout: timeout, bind: bind}
}

func (m *tcpTransport) dial(addr multiaddr.Multiaddr) (manet.Conn, error) {
	netTy, host, err := manet.DialArgs(addr)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
	if m.bind != nil {
		conn, err = reuseport.DialTimeout(netTy, *m.bind, host, m.timeout)
	} else {
		conn, err = net.DialTimeout(netTy, host, m.timeout)
	}
	if err != nil {
		if isTimeoutErr(err) {
			return nil, ErrDialTimeout
		}
		return nil, err
	}

	return manet.WrapNetConn(conn)
}
