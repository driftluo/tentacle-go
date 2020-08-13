package ping

import (
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
)

const sendPingToken = 0
const checkTimeoutToken = 1

// CallBack to communicate with underlying peer storage
type CallBack interface {
	ReceivedPing(*tentacle.ProtocolContextRef, secio.PeerID)
	ReceivedPong(*tentacle.ProtocolContextRef, secio.PeerID, time.Duration)
	Timeout(*tentacle.ProtocolContext, secio.PeerID)
	UnexpectedError(*tentacle.ProtocolContextRef, secio.PeerID)
}

type pingStatus struct {
	processing bool
	lastPing   time.Time
	peerid     secio.PeerID
}

// A meaningless value, peer must send a pong has same nonce to respond a ping.
func (p *pingStatus) nonce() uint32 {
	return nonce(p.lastPing)
}

// Time duration since we last send ping.
func (p *pingStatus) elapsed() time.Duration {
	return time.Now().Sub(p.lastPing)
}

func nonce(t time.Time) uint32 {
	return uint32(t.Unix())
}

// Protocol ping protocol stuct
type Protocol struct {
	interval         time.Duration
	timeout          time.Duration
	connectedSession map[tentacle.SessionID]*pingStatus
	callback         CallBack
}

// NewProtocol create a ping protocol
func NewProtocol(callback CallBack, interval time.Duration, timeout time.Duration) *Protocol {
	return &Protocol{callback: callback, connectedSession: make(map[tentacle.SessionID]*pingStatus), interval: interval, timeout: timeout}
}

/*impl tentacle service protocol*/

// Init ..
func (p *Protocol) Init(ctx *tentacle.ProtocolContext) {
	ctx.SetServiceNotify(ctx.Pid, p.interval, sendPingToken)
	ctx.SetServiceNotify(ctx.Pid, p.timeout, checkTimeoutToken)
}

// Connected ..
func (p *Protocol) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Key == nil {
		ctx.Disconnect(ctx.Sid)
		return
	}

	peerid := ctx.Key.PeerID()

	p.connectedSession[ctx.Sid] = &pingStatus{processing: false, peerid: peerid, lastPing: time.Now()}
}

// Disconnected ..
func (p *Protocol) Disconnected(ctx *tentacle.ProtocolContextRef) {
	delete(p.connectedSession, ctx.Sid)
}

// Received ..
func (p *Protocol) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	status := p.connectedSession[ctx.Sid]

	pingPayload, err := decodeToPingPayLoad(data)

	if err != nil {
		p.callback.UnexpectedError(ctx, status.peerid)
		return
	}

	switch pingPayload.tag {
	case ping:
		ctx.SendMessage(buildPong(pingPayload.nonce))
		p.callback.ReceivedPing(ctx, status.peerid)
	case pong:
		if status.processing && status.nonce() == pingPayload.nonce {
			status.processing = false
			p.callback.ReceivedPong(ctx, status.peerid, status.elapsed())
		} else {
			p.callback.UnexpectedError(ctx, status.peerid)
		}
	}
}

// Notify ..
func (p *Protocol) Notify(ctx *tentacle.ProtocolContext, token uint64) {
	switch token {
	case sendPingToken:
		now := time.Now()
		peers := []tentacle.SessionID{}
		for id, status := range p.connectedSession {
			if !status.processing {
				status.processing = true
				status.lastPing = now
				peers = append(peers, id)
			}
		}

		if len(peers) != 0 {
			pingMsg := buildPing(nonce(now))
			ctx.FilterBroadcast(tentacle.TargetSession{Tag: tentacle.Multi, Target: peers}, ctx.Pid, pingMsg)
		}

	case checkTimeoutToken:
		for _, status := range p.connectedSession {
			if status.processing && status.elapsed() >= p.timeout {
				p.callback.Timeout(ctx, status.peerid)
			}
		}
	}
}
