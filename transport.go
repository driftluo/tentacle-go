package tentacle

import (
	"time"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

type transport interface {
	listen(multiaddr.Multiaddr) (manet.Listener, error)
	dial(multiaddr.Multiaddr) (manet.Conn, error)
}

func multiListen(addr multiaddr.Multiaddr, timeout time.Duration) (manet.Listener, error) {
	switch findTy(addr) {
	case tcp:
		return newTCPTransport(timeout).listen(addr)
	case ws:
		return newWSTransport(timeout).listen(addr)
	default:
		return nil, ErrNotSupport
	}
}

func multiDial(addr multiaddr.Multiaddr, timeout time.Duration) (manet.Conn, error) {
	switch findTy(addr) {
	case tcp:
		return newTCPTransport(timeout).dial(addr)
	case ws:
		return newWSTransport(timeout).dial(addr)
	default:
		return nil, ErrNotSupport
	}
}

const (
	tcp int8 = iota
	ws
)

func findTy(addr multiaddr.Multiaddr) int8 {
	var ty int8 = tcp
	ps := addr.Protocols()
	for _, p := range ps {
		switch p.Name {
		case "ws":
			ty = ws
		}
	}
	return ty
}
