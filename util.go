package tentacle

import (
	"errors"

	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

func deleteSlice(source []ma.Multiaddr, item ma.Multiaddr) []ma.Multiaddr {
	j := 0
	for _, val := range source {
		if val != item {
			source[j] = val
			j++
		}
	}
	return source[:j]
}

func protectRun(entry func(), report func()) {
	defer func() {
		err := recover()
		if err != nil {
			if report != nil {
				report()
			}
		}
	}()
	entry()
}

func isSupport(addr ma.Multiaddr) bool {
	ps := addr.Protocols()
	if len(ps) < 2 {
		return false
	}
	for _, p := range ps {
		switch p.Name {
		case "tcp", "ip", "ip6", "ip4", "dns", "dns4", "dns6", "p2p":
			continue
		default:
			return false
		}
	}
	return true
}

// ExtractPeerID get peer id from multiaddr
func ExtractPeerID(addr ma.Multiaddr) (secio.PeerID, error) {
	var peerid secio.PeerID
	var has bool
	var err error

	ma.ForEach(addr, func(c ma.Component) bool {
		switch c.Protocol().Code {
		case ma.P_P2P:
			peerid, err = secio.PeerIDFromBytes(c.RawValue())
			if err != nil {
				has = false
			}
			has = true
			return false
		default:
			return true
		}
	})

	if has {
		return peerid, nil
	}
	return nil, errors.New("Can't find")
}
