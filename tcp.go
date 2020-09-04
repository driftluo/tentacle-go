package tentacle

import (
	"time"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

type tcpTransport struct {
	timeout time.Duration
}

func newTCPTransport(timeout time.Duration) *tcpTransport {
	return &tcpTransport{timeout: timeout}
}

func (m *tcpTransport) listen(addr multiaddr.Multiaddr) (manet.Listener, error) {
	return manet.Listen(addr)
}

func (m *tcpTransport) dial(addr multiaddr.Multiaddr) (manet.Conn, error) {
	resChan := make(chan interface{})
	go func() {
		conn, err := manet.Dial(addr)
		if err != nil {
			resChan <- err
		}
		resChan <- conn
	}()

	select {
	case <-time.After(m.timeout):
		return nil, ErrDialTimeout
	case res := <-resChan:
		conn, ok := res.(manet.Conn)
		if ok {
			return conn, nil
		}
		return nil, res.(error)
	}
}
