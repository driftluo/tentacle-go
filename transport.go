package tentacle

import (
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

type transport interface {
	listen(multiaddr.Multiaddr) (manet.Listener, error)
	dial(multiaddr.Multiaddr) (manet.Conn, error)
}

func multiListen(addr multiaddr.Multiaddr, config serviceConfig) (manet.Listener, error) {
	switch findTy(addr) {
	case tcp:
		return newTCPTransport(config.timeout, config.tcpBind).listen(addr)
	case ws:
		return newWSTransport(config.timeout, config.wsBind).listen(addr)
	default:
		return nil, ErrNotSupport
	}
}

func multiDial(addr multiaddr.Multiaddr, config serviceConfig) (manet.Conn, error) {
	switch findTy(addr) {
	case tcp:
		return newTCPTransport(config.timeout, config.tcpBind).dial(addr)
	case ws:
		return newWSTransport(config.timeout, config.wsBind).dial(addr)
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
