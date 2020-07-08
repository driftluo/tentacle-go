package tests

import (
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

/// test case:
/// 1. open with dummy protocol
/// 2. open test session protocol
/// 3. test protocol disconnect current session
/// 4. service handle dial with dummy protocol,
///   4.1. goto 1
///   4.2. count >= 10, test done

type testSessionPHandle struct{}

func (p *testSessionPHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Ty.Name() == "Inbound" {
		// Close the session after opening the protocol correctly
		ctx.Disconnect(ctx.Sid)
	}
}

func (p *testSessionPHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {}

func (p *testSessionPHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *testSessionPHandle) Notify(ctx *tentacle.ProtocolContextRef, token uint64) {}

type testSessionDummyPHandle struct{}

func (p *testSessionDummyPHandle) Init(ctx *tentacle.ProtocolContext) {}

func (p *testSessionDummyPHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {}

func (p *testSessionDummyPHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {}

func (p *testSessionDummyPHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *testSessionDummyPHandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {}

type testSessionSHandle struct {
	count uint
	addr  *ma.Multiaddr
}

func (s *testSessionSHandle) HandleError(ctx *tentacle.ServiceContext, event tentacle.ServiceError) {}

func (s *testSessionSHandle) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	switch event.Name() {
	case "SessionOpen":
		inner := event.Event.(*tentacle.SessionContext)
		s.addr = &inner.RemoteAddr
		if inner.Ty.Name() == "Outbound" {
			ctx.OpenProtocol(inner.Sid, tentacle.ProtocolID(1))
		}
	case "SessionClose":
		inner := event.Event.(*tentacle.SessionContext)
		if inner.Ty.Name() == "Outbound" {
			s.count++
			if s.count > 10 {
				ctx.Shutdown()
			} else {
				ctx.Dial(*s.addr, tentacle.TargetProtocol{Tag: tentacle.Single, Target: tentacle.ProtocolID(0)})
			}
		}
	}
}

func sessionHandleOpenTest(secioC bool) {
	metaDummy1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).ServiceHandle(&testSessionDummyPHandle{}).Build()
	metaDummy2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).ServiceHandle(&testSessionDummyPHandle{}).Build()

	meta1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).SessionHandle(func() tentacle.SessionProtocol {
		return &testSessionPHandle{}
	}).Build()
	meta2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).SessionHandle(func() tentacle.SessionProtocol {
		return &testSessionPHandle{}
	}).Build()

	var server1, server2 *tentacle.Service
	if secioC {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).InsertProtocol(metaDummy1).KeyPair(secio.GenerateSecp256k1()).Build(&testSessionSHandle{})
		server2 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta2).InsertProtocol(metaDummy2).KeyPair(secio.GenerateSecp256k1()).Build(&testSessionSHandle{})
	} else {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).InsertProtocol(metaDummy1).Build(&testSessionSHandle{})
		server2 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta2).InsertProtocol(metaDummy2).Build(&testSessionSHandle{})
	}

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	listenAddr, _ := server1.Listen(addr)
	server2.Dial(listenAddr, tentacle.TargetProtocol{Tag: tentacle.Single, Target: tentacle.ProtocolID(0)})

	for {
		if server2.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSessionHandleOpenWithSecio(t *testing.T) {
	sessionHandleOpenTest(true)
}

func TestSessionHandleOpen(t *testing.T) {
	sessionHandleOpenTest(false)
}
