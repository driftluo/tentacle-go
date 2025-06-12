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

	resChan := make(chan any)
	go func() {
		var conn net.Conn
		var erro error

		if m.bind != nil {
			conn, erro = reuseport.Dial(netTy, *m.bind, host)
			if erro != nil {
				resChan <- erro
			}
			resChan <- conn
		} else {
			conn, erro = net.Dial(netTy, host)
			if erro != nil {
				resChan <- erro
			}
			resChan <- conn
		}
	}()

	select {
	case <-time.After(m.timeout):
		return nil, ErrDialTimeout
	case res := <-resChan:
		conn, ok := res.(net.Conn)
		if ok {
			return manet.WrapNetConn(conn)
		}
		return nil, res.(error)
	}
}
