package tests

import (
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

/// test case:
/// 1. open with dummy session protocol
/// 2. dummy protocol open test protocol
/// 3. test protocol open/close self 10 times, each closed count + 1
/// 4. when count >= 10, test done

type testSessionOpenClosePHandle struct {
	count uint
}

func (p *testSessionOpenClosePHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Ty.Name() == "Outbound" {
		// close self protocol
		ctx.CloseProtocol(ctx.Sid, ctx.Pid)
		// set a timer to open self protocol
		// because service state may not clean
		ctx.SetSessionNotify(ctx.Sid, ctx.Pid, 100*time.Millisecond, 1)
	}
}

func (p *testSessionOpenClosePHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	if ctx.Ty.Name() == "Outbound" {
		// each close add one
		p.count++
		if p.count > 10 {
			ctx.Shutdown()
		}
	}
}

func (p *testSessionOpenClosePHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *testSessionOpenClosePHandle) Notify(ctx *tentacle.ProtocolContextRef, token uint64) {
	ctx.OpenProtocol(ctx.Sid, ctx.Pid)
}

type testDummyPHandle struct{}

func (p *testDummyPHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	// dummy open the test protocol
	ctx.OpenProtocol(ctx.Sid, tentacle.ProtocolID(1))
}

func (p *testDummyPHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {}

func (p *testDummyPHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *testDummyPHandle) Notify(ctx *tentacle.ProtocolContextRef, token uint64) {}

func SessionProtoOpenCloseTest(secioC bool) {
	meta1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).SessionHandle(func() tentacle.SessionProtocol {
		return &testSessionOpenClosePHandle{}
	}).Build()
	meta2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).SessionHandle(func() tentacle.SessionProtocol {
		return &testSessionOpenClosePHandle{}
	}).Build()

	metaDummy1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).SessionHandle(func() tentacle.SessionProtocol {
		return &testDummyPHandle{}
	}).Build()
	metaDummy2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).SessionHandle(func() tentacle.SessionProtocol {
		return &testDummyPHandle{}
	}).Build()

	var server1, server2 *tentacle.Service
	if secioC {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).InsertProtocol(metaDummy1).KeyPair(secio.GenerateSecp256k1()).Build(nil)
		server2 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta2).InsertProtocol(metaDummy2).KeyPair(secio.GenerateSecp256k1()).Build(nil)
	} else {
		server1 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta1).InsertProtocol(metaDummy1).Build(nil)
		server2 = tentacle.DefaultServiceBuilder().Forever(true).InsertProtocol(meta2).InsertProtocol(metaDummy2).Build(nil)
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

func TestSessionProtocolOpenCloseWithSecio(t *testing.T) {
	SessionProtoOpenCloseTest(true)
}

func TestSessionProtocolOpenClose(t *testing.T) {
	SessionProtoOpenCloseTest(false)
}
