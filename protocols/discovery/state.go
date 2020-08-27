package discovery

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/multiformats/go-multiaddr"
	cuckoo "github.com/seiflotfy/cuckoofilter"
)

const (
	initState uint8 = iota
	listen
)

type discoveryState struct {
	addrKnown          addrKnown
	remoteAddr         remoteAddress
	announce           bool
	lastAnnounce       time.Time
	announceMultiaddrs []multiaddr.Multiaddr
	receivedGetNodes   bool
	receivedNodes      bool
}

func newState(ctx *tentacle.ProtocolContextRef, codec *codec) *discoveryState {
	addrKnown := newAddrKnown()
	var remoteAddrinner remoteAddress
	switch ctx.Ty.Name() {
	case "Outbound":
		remoteAddrinner = remoteAddress{tag: listen, addr: ctx.RemoteAddr}
		var port uint16 = 0
		var err error
		for _, x := range ctx.Listens {
			port, err = getTCPPort(x)
			if err != nil {
				continue
			} else {
				break
			}
		}
		msg := discoveryMessage{tag: getNode, inner: getNodes{version: version, count: maxAddrToSend, listenPort: port}}
		ctx.SendMessage(codec.encode(msg))
		addrKnown.insert(ctx.RemoteAddr)

	case "Inbound":
		remoteAddrinner = remoteAddress{tag: initState, addr: ctx.RemoteAddr}
	}

	return &discoveryState{addrKnown: addrKnown, remoteAddr: remoteAddrinner, announce: false, lastAnnounce: time.Now(), announceMultiaddrs: []multiaddr.Multiaddr{}, receivedGetNodes: false, receivedNodes: false}
}

func (d *discoveryState) checkTimer(now time.Time, announceInterval time.Duration) {
	duration := now.Sub(d.lastAnnounce)
	if duration > announceInterval {
		d.announce = true
	}
}

func (d *discoveryState) sendMessage(ctx *tentacle.ProtocolContext, id tentacle.SessionID, codec *codec) {
	if len(d.announceMultiaddrs) != 0 {
		addrses := make([]node, len(d.announceMultiaddrs))
		for idx, addr := range d.announceMultiaddrs {
			addrses[idx] = node{addresses: []multiaddr.Multiaddr{addr}}
		}
		// clear all
		d.announceMultiaddrs = []multiaddr.Multiaddr{}
		msg := discoveryMessage{tag: sendNodes, inner: nodes{announce: true, items: addrses}}

		ctx.SendMessageTo(id, ctx.Pid, codec.encode(msg))
	}
}

type remoteAddress struct {
	tag  uint8
	addr multiaddr.Multiaddr
}

func (r *remoteAddress) updatePort(port uint16) {
	r.addr = updateTCPPort(r.addr, port)
	r.tag = listen
}

type addrKnown struct {
	filter *cuckoo.Filter
}

func newAddrKnown() addrKnown {
	return addrKnown{filter: cuckoo.NewFilter(defaultMaxKnown)}
}

func (k *addrKnown) insert(addr multiaddr.Multiaddr) {
	k.filter.InsertUnique(addr.Bytes())
}

func (k *addrKnown) contain(addr multiaddr.Multiaddr) bool {
	return k.filter.Lookup(addr.Bytes())
}

func (k *addrKnown) remove(addr multiaddr.Multiaddr) {
	k.filter.Delete(addr.Bytes())
}

func deleteSlice(source []multiaddr.Multiaddr, item multiaddr.Multiaddr) []multiaddr.Multiaddr {
	j := 0
	for _, val := range source {
		if val != item {
			source[j] = val
			j++
		}
	}
	return source[:j]
}

func updateTCPPort(addr multiaddr.Multiaddr, port uint16) multiaddr.Multiaddr {
	var origin multiaddr.Multiaddr
	new, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/tcp/%d", port))
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_TCP:
			origin, _ = multiaddr.NewMultiaddrBytes(c.Bytes())
			return false
		default:
			return true
		}
	})
	if origin != nil {
		addr = addr.Decapsulate(origin)
	}
	addr = addr.Encapsulate(new)
	return addr
}

func getTCPPort(addr multiaddr.Multiaddr) (uint16, error) {
	var port int
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_TCP:
			s, _ := c.Protocol().Transcoder.BytesToString(c.RawValue())
			list := strings.Split(s, "/")
			port, _ = strconv.Atoi(list[len(list)-1])
			return false
		default:
			return true
		}
	})
	return uint16(port), nil
}
