package tests

import (
	"sync/atomic"
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

type testSpawnOpenClosePHandle struct {
	count uint32
	once  bool
}

func (p *testSpawnOpenClosePHandle) Spawn(ctx *tentacle.SessionContext, control *tentacle.Service, read tentacle.SubstreamReadPart) {
	sid := ctx.Sid
	pid := read.ProtocolID()
	isOutbound := ctx.Ty.Name() == "Outbound"

	if isOutbound && p.once {
		p.once = false

		go func() {
			interval := time.NewTicker(100 * time.Millisecond)

			for {
				select {
				case <-interval.C:
					control.OpenProtocol(sid, pid)
				}
			}
		}()
	}

	if isOutbound {
		go func() {
			control.CloseProtocol(sid, pid)
		}()
	}

	go func() {
		for {
			_, err := read.NextMsg()
			if err != nil {
				break
			}
		}

		if isOutbound {
			atomic.AddUint32(&p.count, 1)
			if atomic.LoadUint32(&p.count) >= 10 {
				control.Shutdown()
			}
		}
	}()
}

type testDummySpawn struct{}

func (p *testDummySpawn) Spawn(ctx *tentacle.SessionContext, control *tentacle.Service, read tentacle.SubstreamReadPart) {
	// dummy open the test protocol
	control.OpenProtocol(ctx.Sid, tentacle.ProtocolID(1))
	// protocol close here
}

func SpawnProtoOpenCloseTest(secioC bool) {
	meta1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ProtoSpawn(&testSpawnOpenClosePHandle{count: 0, once: true}).Build()
	meta2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ProtoSpawn(&testSpawnOpenClosePHandle{count: 0, once: true}).Build()

	metaDummy1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).ProtoSpawn(&testDummySpawn{}).Build()
	metaDummy2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(0)).ProtoSpawn(&testDummySpawn{}).Build()

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

func TestProtocolOpenCloseSpawnWithSecio(t *testing.T) {
	SpawnProtoOpenCloseTest(true)
}

func TestProtocolOpenCloseSpawn(t *testing.T) {
	SpawnProtoOpenCloseTest(false)
}
