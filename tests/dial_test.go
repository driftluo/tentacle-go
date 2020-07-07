package tests

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

type dailPHandle struct {
	connCount uint
	sender    chan<- uint
	dialCount uint
	dailAddr  *ma.Multiaddr
}

func (p *dailPHandle) Init(ctx *tentacle.ProtocolContext) {
	ctx.SetServiceNotify(ctx.Pid, 100*time.Millisecond, 3)
}

func (p *dailPHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Ty.Name() == "Inbound" {
		p.dailAddr = &ctx.Listens[0]
	} else {
		p.dailAddr = &ctx.RemoteAddr
	}
	p.connCount++
}

func (p *dailPHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	p.connCount--
}

func (p *dailPHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *dailPHandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {
	if p.dailAddr != nil {
		ctx.Dial(*p.dailAddr, tentacle.TargetProtocol{Tag: tentacle.All})
		p.dialCount++
		if p.dialCount == 10 {
			p.sender <- p.connCount
		}
	}
}

type repeatSHandle struct {
	sender chan uint
	sid    tentacle.SessionID
	ty     tentacle.SessionType
}

func (s *repeatSHandle) HandleError(ctx *tentacle.ServiceContext, event tentacle.ServiceError) {
	switch event.Name() {
	case "DialerError":
		inner := event.Event.(tentacle.DialerErrorInner)
		switch inner.Name() {
		case "HandshakeError":
		case "RepeatedConnection":
			id := inner.Inner.(tentacle.SessionID)
			if id != s.sid {
				panic("session id must eq")
			}
		default:
			panic(fmt.Sprintf("test fail, expected RepeatedConnection, got %s", inner.Name()))
		}
	case "ListenError":
		inner := event.Event.(tentacle.ListenErrorInner)
		switch inner.Name() {
		case "RepeatedConnection":
			id := inner.Inner.(tentacle.SessionID)
			if id != s.sid {
				panic("session id must eq")
			}
		default:
			panic(fmt.Sprintf("test fail, expected RepeatedConnection, got %s", inner.Name()))
		}
	default:
		fmt.Println(event.String())
		panic("test fail on dail test")
	}
	s.sender <- 0
}

func (s *repeatSHandle) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	if event.Name() == "SessionOpen" {
		inner := event.Event.(*tentacle.SessionContext)
		s.sid = inner.Sid
		s.ty = inner.Ty
	}
}

type emptyRepeatShandle struct {
	sender chan uint
}

func (s *emptyRepeatShandle) HandleError(ctx *tentacle.ServiceContext, event tentacle.ServiceError) {
	switch event.Name() {
	case "DialerError":
		inner := event.Event.(tentacle.DialerErrorInner)
		switch inner.Name() {
		case "TransportError":
		default:
			panic(fmt.Sprintf("test fail, expected RepeatedConnection, got %s", inner.Name()))
		}
	default:
		fmt.Println(event.String())
		panic("test fail on dail test")
	}
	s.sender <- 0
}

func (s *emptyRepeatShandle) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {}

func createRepeatMeta(id tentacle.ProtocolID) (tentacle.ProtocolMeta, <-chan uint) {
	channel := make(chan uint, 512)
	meta := tentacle.DefaultMeta().ID(id).ServiceHandle(&dailPHandle{
		connCount: 0,
		sender:    channel,
		dialCount: 0,
		dailAddr:  nil,
	}).Build()
	return meta, channel
}

func createRepeatSHandle() (tentacle.ServiceHandle, <-chan uint) {
	channel := make(chan uint, 512)
	s := repeatSHandle{
		sender: channel,
	}

	return &s, channel
}

func createEmptyRepeatSHandle() (tentacle.ServiceHandle, <-chan uint) {
	channel := make(chan uint, 512)
	s := emptyRepeatShandle{
		sender: channel,
	}

	return &s, channel
}

func checkDialErrors(recv <-chan uint, timeout time.Duration, expected int) int {
	startTime := time.Now().UnixNano()
	for i := 0; i < expected; i++ {
		select {
		case <-recv:
		case <-time.Tick(100 * time.Millisecond):
			if float64((time.Now().UnixNano()-startTime)/1e9) > float64(timeout) {
				return i
			}
		}
	}
	return expected
}

func repeatDialTest(secioC bool) error {
	meta1, recv1 := createRepeatMeta(tentacle.ProtocolID(1))
	meta2, recv2 := createRepeatMeta(tentacle.ProtocolID(1))
	shandle1, errRecv1 := createRepeatSHandle()
	shandle2, errRecv2 := createRepeatSHandle()

	var server1, server2 *tentacle.Service
	if secioC {
		server1 = tentacle.DefaultServiceBuilder().InsertProtocol(meta1).KeyPair(secio.GenerateSecp256k1()).Build(shandle1)
		server2 = tentacle.DefaultServiceBuilder().InsertProtocol(meta2).KeyPair(secio.GenerateSecp256k1()).Build(shandle2)
	} else {
		server1 = tentacle.DefaultServiceBuilder().InsertProtocol(meta1).Build(shandle1)
		server2 = tentacle.DefaultServiceBuilder().InsertProtocol(meta2).Build(shandle2)
	}

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	listenAddr, _ := server1.Listen(addr)
	server2.Dial(listenAddr, tentacle.TargetProtocol{Tag: tentacle.All})

	if secioC {
		a := <-recv1
		b := <-recv2

		if a != 1 || b != 1 {
			return errors.New("a,b fail")
		}

		c := checkDialErrors(errRecv1, 30*time.Second, 10)
		d := checkDialErrors(errRecv2, 30*time.Second, 10)

		if c != 10 || d != 10 {
			return errors.New("c,d fail")
		}
	} else {
		a := <-recv1
		b := <-recv2

		if a == 1 || b == 1 {
			return errors.New("a,b fail")
		}
	}

	return nil
}

func emptyRepeatDialTest(secioC bool) error {
	meta1, _ := createRepeatMeta(tentacle.ProtocolID(1))
	shandle1, errRecv1 := createEmptyRepeatSHandle()

	var server1 *tentacle.Service
	if secioC {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).KeyPair(secio.GenerateSecp256k1()).Build(shandle1)
	} else {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).Build(shandle1)
	}

	for i := 0; i < 2; i++ {
		for j := 1; j < 8; j++ {
			addr, _ := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", j))
			server1.Dial(addr, tentacle.TargetProtocol{Tag: tentacle.All})
		}
	}

	time.Sleep(1 * time.Second)
	c := checkDialErrors(errRecv1, 15*time.Second, 10)
	if c != 10 {
		return errors.New("c,d fail")
	}
	return nil
}

func TestRepeatDialWithSecio(t *testing.T) {
	err := repeatDialTest(true)
	if err != nil {
		t.Fatal("repeat dial with secio fail")
	}
}

func TestRepeatDial(t *testing.T) {
	err := repeatDialTest(false)
	if err != nil {
		t.Fatal("repeat dial fail")
	}
}

func TestDialNoNotifyWithSecio(t *testing.T) {
	emptyRepeatDialTest(true)
}

func TestDialNoNotify(t *testing.T) {
	emptyRepeatDialTest(false)
}
