package tests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

type peeridPhandle struct{}

func (p *peeridPhandle) Init(ctx *tentacle.ProtocolContext) {}

func (p *peeridPhandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {}

func (p *peeridPhandle) Disconnected(ctx *tentacle.ProtocolContextRef) {}

func (p *peeridPhandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *peeridPhandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {}

type peeridSHandle struct {
	sender     chan<- uint
	errorCount uint
}

func (s *peeridSHandle) HandleError(ctx *tentacle.ServiceContext, event tentacle.ServiceError) {
	s.errorCount++

	switch event.Name() {
	case "DialerError":
		inner := event.Event.(tentacle.DialerErrorInner)
		switch inner.Name() {
		case "PeerIDNotMatch":
		default:
			panic(fmt.Sprintf("test fail, expected PeerIDNotMatch, got %s", inner.Name()))
		}
	default:
		fmt.Println(event.String())
		panic("test fail on dail test")
	}

	if s.errorCount > 8 {
		s.sender <- s.errorCount
	}

}

func (s *peeridSHandle) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	switch event.Name() {
	case "SessionOpen":
		s.sender <- s.errorCount
	}
}

func createPeeridSHandle() (tentacle.ServiceHandle, <-chan uint) {
	channel := make(chan uint, 512)
	s := peeridSHandle{
		sender: channel,
	}

	return &s, channel
}

func peerIDTest(fail bool) error {
	meta1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ServiceHandle(&peeridPhandle{}).Build()
	meta2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ServiceHandle(&peeridPhandle{}).Build()

	shandle2, recv2 := createPeeridSHandle()

	var key = secio.GenerateSecp256k1()

	server1 := tentacle.DefaultServiceBuilder().InsertProtocol(meta1).Forever(true).KeyPair(key).Build(nil)
	server2 := tentacle.DefaultServiceBuilder().InsertProtocol(meta2).Forever(true).KeyPair(secio.GenerateSecp256k1()).Build(shandle2)

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	listenAddr, _ := server1.Listen(addr)

	if fail {
		for i := 1; i < 11; i++ {
			paddr, _ := ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", secio.GenerateSecp256k1().PeerID().Bese58String()))
			remoteAddr := listenAddr.Encapsulate(paddr)
			server2.Dial(remoteAddr, tentacle.TargetProtocol{Tag: tentacle.All})
		}
		count := <-recv2
		if count != 9 {
			return errors.New("test fail")
		}
	} else {
		paddr, _ := ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", key.PeerID().Bese58String()))
		remoteAddr := listenAddr.Encapsulate(paddr)
		server2.Dial(remoteAddr, tentacle.TargetProtocol{Tag: tentacle.All})
		count := <-recv2
		if count != 0 {
			return errors.New("test fail")
		}
	}

	return nil
}

func TestPeerIDSuccessed(t *testing.T) {
	err := peerIDTest(false)
	if err != nil {
		t.Fatal("test peerid false fail")
	}
}

func TestPeerIDFail(t *testing.T) {
	err := peerIDTest(true)
	if err != nil {
		t.Fatal("test peerid true fail")
	}
}
