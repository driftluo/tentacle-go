package discovery

import (
	"math/rand"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

const defaultMaxKnown = 5000
const version = 0
const maxAddrToSend = 1000
const checkIntervalToken = 0
const announceThershold = 10

// The maximum number addresses in on Nodes item
const maxAddrs = 3

const (
	duplicateGetNodes uint8 = iota
	duplicateFirstNodes
	tooManyItems
	tooManyAddresses
	invaildData
)

// Misbehavior to report to underlying peer storage
type Misbehavior struct {
	tag uint8
}

func (m *Misbehavior) String() string {
	var name string
	switch m.tag {
	case duplicateGetNodes:
		name = "DuplicateGetNodes"
	case duplicateFirstNodes:
		name = "DuplicateFirstNodes"
	case tooManyItems:
		name = "TooManyItems"
	case tooManyAddresses:
		name = "TooManyAddresses"
	case invaildData:
		name = "InvaildData"
	}
	return name
}

// MisbehaveResult report result
type MisbehaveResult struct {
	tag uint8
}

func (m *MisbehaveResult) isContinue() bool {
	return m.tag == 0
}

func (m *MisbehaveResult) isDisconnect() bool {
	return m.tag == 1
}

// Continue to run
func Continue() *MisbehaveResult {
	return &MisbehaveResult{tag: 0}
}

// Disconnect this peer
func Disconnect() *MisbehaveResult {
	return &MisbehaveResult{tag: 1}
}

// AddressManager ..
type AddressManager interface {
	AddNewAddr(tentacle.SessionID, multiaddr.Multiaddr)
	AddNewAddrs(tentacle.SessionID, []multiaddr.Multiaddr)
	Misbehave(tentacle.SessionID, Misbehavior) *MisbehaveResult
	GetRandom(int) []multiaddr.Multiaddr
}

// Protocol discovery protocol stuct
type Protocol struct {
	codec         *codec
	sessions      map[tentacle.SessionID]*discoveryState
	queryCycle    time.Duration
	checkInterval time.Duration
	globalIPOnly  bool
	addrMgr       AddressManager
}

// NewProtocol create a discovery protocol
func NewProtocol(addrMgr AddressManager, queryCycle time.Duration, checkInterval time.Duration, globalIPOnly bool) *Protocol {
	return &Protocol{codec: newCodec(), addrMgr: addrMgr, sessions: make(map[tentacle.SessionID]*discoveryState), queryCycle: queryCycle, checkInterval: checkInterval, globalIPOnly: globalIPOnly}
}

/*impl tentacle service protocol*/

// Init ..
func (p *Protocol) Init(ctx *tentacle.ProtocolContext) {
	ctx.SetServiceNotify(ctx.Pid, p.checkInterval, checkIntervalToken)
}

// Connected ..
func (p *Protocol) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	state := newState(ctx, p.codec)
	p.sessions[ctx.Sid] = state
}

// Disconnected ..
func (p *Protocol) Disconnected(ctx *tentacle.ProtocolContextRef) {
	removeState := p.sessions[ctx.Sid]
	delete(p.sessions, ctx.Sid)
	if removeState.remoteAddr.tag == listen {
		for _, state := range p.sessions {
			state.addrKnown.remove(removeState.remoteAddr.addr)
		}
	}
}

// Received ..
func (p *Protocol) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	msg, err := p.codec.decode(data)
	if err != nil {
		if p.addrMgr.Misbehave(ctx.Sid, Misbehavior{tag: invaildData}).isDisconnect() {
			ctx.Disconnect(ctx.Sid)
		}
		return
	}

	state := p.sessions[ctx.Sid]

	check := func(behavior Misbehavior) bool {
		if p.addrMgr.Misbehave(ctx.Sid, behavior).isDisconnect() {
			ctx.Disconnect(ctx.Sid)
			return true
		}
		return false
	}

	switch msg.tag {
	case getNode:
		if state.receivedGetNodes && check(Misbehavior{tag: duplicateGetNodes}) {
			return
		}
		state.receivedGetNodes = true

		inner := msg.inner.(getNodes)

		// must get the item first, otherwise it is possible to load
		// the address of peer listen.
		items := p.addrMgr.GetRandom(2500)

		// if listen port is 0, this field value is useless
		if inner.listenPort != 0 {
			state.remoteAddr.updatePort(inner.listenPort)
			state.addrKnown.insert(state.remoteAddr.addr)
			p.addrMgr.AddNewAddr(ctx.Sid, state.remoteAddr.addr)
		}

		var max int

		if maxAddrToSend > inner.count {
			max = int(inner.count)
		} else {
			max = int(maxAddrToSend)
		}

		for len(items) > max {
			lastItem := items[len(items)-1]
			items = deleteSlice(items, lastItem)
			idx := rand.Int() % max
			items[idx] = lastItem
		}
		addrses := make([]node, len(items))
		for idx, addr := range items {
			addrses[idx] = node{addresses: []multiaddr.Multiaddr{addr}}
			state.addrKnown.insert(addr)
		}
		msg := discoveryMessage{tag: sendNodes, inner: nodes{announce: false, items: addrses}}
		ctx.SendMessage(p.codec.encode(msg))

	case sendNodes:
		inner := msg.inner.(nodes)

		behavior := verifyNodesMsg(inner)

		if behavior != nil {
			if check(*behavior) {
				return
			}
		}

		state := p.sessions[ctx.Sid]

		insertFn := func(n nodes) {
			for _, node := range n.items {
				for _, addr := range node.addresses {
					state.addrKnown.insert(addr)
				}
				p.addrMgr.AddNewAddrs(ctx.Sid, node.addresses)
			}
		}

		if !inner.announce && state.receivedGetNodes {
			if check(*behavior) {
				return
			}
		} else {
			insertFn(inner)
			state.receivedNodes = true
		}
	}
}

// Notify ..
func (p *Protocol) Notify(ctx *tentacle.ProtocolContext, token uint64) {
	now := time.Now()

	announceList := []multiaddr.Multiaddr{}
	ids := []tentacle.SessionID{}

	// get announce list
	for id, state := range p.sessions {
		// send all announce addr to remote
		state.sendMessage(ctx, id, p.codec)
		// check timer
		addr := state.checkTimer(now, p.queryCycle)
		ids = append(ids, id)

		if addr != nil && (!p.globalIPOnly || manet.IsPublicAddr(addr)) {
			announceList = append(announceList, addr)
		}
	}

	// insert announce list to some session pending list
	for _, addr := range announceList {
		rand.Shuffle(len(ids), func(i, j int) {
			ids[i], ids[j] = ids[j], ids[i]
		})

		for i := 0; i < 2; i++ {
			if i > len(ids)-1 {
				break
			}
			key := ids[i]
			state := p.sessions[key]
			if len(state.announceMultiaddrs) < announceThershold && !state.addrKnown.contain(addr) {
				state.announceMultiaddrs = append(state.announceMultiaddrs, addr)
				state.addrKnown.insert(addr)
			}
		}
	}
}

func verifyNodesMsg(d nodes) *Misbehavior {
	var misbehavior *Misbehavior
	if d.announce {
		if len(d.items) > announceThershold {
			misbehavior = &Misbehavior{tag: tooManyItems}
		}
	} else {
		if len(d.items) > maxAddrToSend {
			misbehavior = &Misbehavior{tag: tooManyItems}
		}
	}

	if misbehavior == nil {
		for _, item := range d.items {
			if len(item.addresses) > maxAddrs {
				misbehavior = &Misbehavior{tag: tooManyAddresses}
			}
		}
	}

	return misbehavior
}
