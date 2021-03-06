package identify

import (
	"fmt"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

const maxReturnListenAddrs = 10
const checkTimeoutToken = 100

// Check timeout interval (seconds)
const checkTimeoutInterval = 1
const defaultTimeout = 8
const maxAddrs = 10

const (
	duplicateReceived uint8 = iota
	timeout
	invalidData
	tooManyAddresses
)

// Misbehavior to report to underlying peer storage
type Misbehavior struct {
	tag uint8
}

func (m *Misbehavior) String() string {
	var name string
	switch m.tag {
	case duplicateReceived:
		name = "DuplicateReceived"
	case timeout:
		name = "Timeut"
	case invalidData:
		name = "InvalidData"
	case tooManyAddresses:
		name = "TooManyAddresses"
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

// CallBack to communicate with underlying peer storage
type CallBack interface {
	// Received custom message
	ReceivedIdentify(*tentacle.ProtocolContextRef, []byte) *MisbehaveResult
	// Get custom identify message
	Identify() []byte
	// Get local listen addresses
	LocalListenAddrs() []multiaddr.Multiaddr
	// Add remote peer's listen addresses
	AddRemoteListenAddrs(secio.PeerID, []multiaddr.Multiaddr)
	// Add our address observed by remote peer
	AddObservedAddr(secio.PeerID, multiaddr.Multiaddr, tentacle.SessionType) *MisbehaveResult
	// Report misbehavior
	Misbehave(secio.PeerID, Misbehavior) *MisbehaveResult
}

type remoteInfo struct {
	pid         secio.PeerID
	session     *tentacle.SessionContext
	connectedAt time.Time
	timeout     time.Duration
	received    bool
}

func newInfo(session *tentacle.SessionContext, timeout time.Duration) remoteInfo {
	return remoteInfo{
		pid:         session.RemotePub.PeerID(),
		session:     session,
		connectedAt: time.Now(),
		timeout:     timeout,
		received:    false,
	}
}

// Protocol identify protocol stuct
type Protocol struct {
	callback     CallBack
	remoteInfos  map[tentacle.SessionID]*remoteInfo
	secioEnabled bool
	globalIPOnly bool
}

// NewProtocol create a identify protocol
func NewProtocol(callback CallBack) *Protocol {
	return &Protocol{callback: callback, remoteInfos: make(map[tentacle.SessionID]*remoteInfo), globalIPOnly: true, secioEnabled: true}
}

// GlobalIPOnly turning off global ip only mode will allow any ip to be broadcast, default is true
func (p *Protocol) GlobalIPOnly(globalIPOnly bool) *Protocol {
	p.globalIPOnly = globalIPOnly
	return p
}

func (p *Protocol) processListens(context *tentacle.ProtocolContextRef, listens []multiaddr.Multiaddr) *MisbehaveResult {
	info := p.remoteInfos[context.Sid]

	if len(listens) > maxAddrs {
		return p.callback.Misbehave(info.pid, Misbehavior{tag: tooManyAddresses})
	}

	listensNew := make([]multiaddr.Multiaddr, len(listens))

	for i := 0; i < len(listens); i++ {
		if !p.globalIPOnly || manet.IsPublicAddr(listens[i]) {
			listensNew[i] = listens[i]
		}
	}
	p.callback.AddRemoteListenAddrs(info.pid, listensNew)
	return Continue()

}

func (p *Protocol) processObserved(context *tentacle.ProtocolContextRef, observed multiaddr.Multiaddr) *MisbehaveResult {
	info := p.remoteInfos[context.Sid]

	if !p.globalIPOnly || manet.IsPublicAddr(observed) {
		res := p.callback.AddObservedAddr(info.pid, observed, info.session.Ty)
		if res.isDisconnect() {
			return Disconnect()
		}
	}
	return Continue()
}

func (p *Protocol) checkDuplicate(context *tentacle.ProtocolContextRef) *MisbehaveResult {
	info := p.remoteInfos[context.Sid]

	if info.received {
		return p.callback.Misbehave(info.pid, Misbehavior{tag: duplicateReceived})
	}
	info.received = true
	return Continue()
}

/*impl tentacle service protocol*/

// Init ..
func (p *Protocol) Init(ctx *tentacle.ProtocolContext) {
	ctx.SetServiceNotify(ctx.Pid, checkTimeoutInterval*time.Second, checkTimeoutToken)
}

// Connected ..
func (p *Protocol) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.RemotePub == nil {
		ctx.Disconnect(ctx.Sid)
		p.secioEnabled = false
		return
	}

	remotei := newInfo(ctx.SessionContext, defaultTimeout*time.Second)
	p.remoteInfos[ctx.Sid] = &remotei

	raw := p.callback.LocalListenAddrs()
	listenAddrs := make([]multiaddr.Multiaddr, len(raw))
	for i := 0; i < len(raw) && i <= maxAddrs-1; i++ {
		if !p.globalIPOnly || manet.IsPublicAddr(raw[i]) {
			listenAddrs[i] = raw[i]
		}
	}

	p2p, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s", ctx.RemotePub.PeerID().Bese58String()))
	observedAddr := ctx.RemoteAddr.Decapsulate(p2p)
	msg := identifyMessage{listenAddrs: listenAddrs, observedAddr: observedAddr, identify: p.callback.Identify()}
	ctx.QuickSendMessage(msg.encode())
}

// Disconnected ..
func (p *Protocol) Disconnected(ctx *tentacle.ProtocolContextRef) {
	if p.secioEnabled {
		delete(p.remoteInfos, ctx.Sid)
	}
}

// Received ..
func (p *Protocol) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	if !p.secioEnabled {
		return
	}
	msg, err := decodeToIdentifyMessage(data)
	if err != nil {
		info := p.remoteInfos[ctx.Sid]

		res := p.callback.Misbehave(info.pid, Misbehavior{tag: invalidData})
		if res.isDisconnect() {
			ctx.Disconnect(ctx.Sid)
		}
	} else {
		if p.checkDuplicate(ctx).isDisconnect() || p.callback.ReceivedIdentify(ctx, msg.identify).isDisconnect() || p.processListens(ctx, msg.listenAddrs).isDisconnect() || p.processObserved(ctx, msg.observedAddr).isDisconnect() {
			ctx.Disconnect(ctx.Sid)
		}
	}
}

// Notify ..
func (p *Protocol) Notify(ctx *tentacle.ProtocolContext, token uint64) {
	if !p.secioEnabled {
		return
	}

	now := time.Now()

	for k, v := range p.remoteInfos {
		if !v.received && v.connectedAt.Add(v.timeout).After(now) {
			ctx.Disconnect(k)
		}
	}
}
