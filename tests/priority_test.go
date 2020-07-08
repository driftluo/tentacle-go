package tests

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

type priorityPHandle struct {
	count      uint
	testResult *atomic.Value
}

func (p *priorityPHandle) Init(ctx *tentacle.ProtocolContext) {}

func (p *priorityPHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Ty.Name() == "Inbound" {
		for i := 0; i < 1024; i++ {
			if i == 254 {
				ctx.QuickSendMessage([]byte("high"))
			}
			ctx.SendMessage([]byte("normal"))
		}
	}
}

func (p *priorityPHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {}

func (p *priorityPHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	p.count++
	if string(data) == "high" {
		if p.count <= 254 {
			p.testResult.Store(true)
		}
		ctx.Shutdown()
	}
}

func (p *priorityPHandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {}

func createPriorityMeta(pid tentacle.ProtocolID) (tentacle.ProtocolMeta, *atomic.Value) {
	res := atomic.Value{}
	res.Store(false)

	meta := tentacle.DefaultMeta().ID(pid).ServiceHandle(&priorityPHandle{testResult: &res}).Build()
	return meta, &res
}

func priorityTest(secioC bool) error {
	meta1, _ := createPriorityMeta(tentacle.ProtocolID(1))
	meta2, res := createPriorityMeta(tentacle.ProtocolID(1))

	var server1, server2 *tentacle.Service
	if secioC {
		server1 = tentacle.DefaultServiceBuilder().InsertProtocol(meta1).KeyPair(secio.GenerateSecp256k1()).Build(nil)
		server2 = tentacle.DefaultServiceBuilder().InsertProtocol(meta2).KeyPair(secio.GenerateSecp256k1()).Build(nil)
	} else {
		server1 = tentacle.DefaultServiceBuilder().InsertProtocol(meta1).Build(nil)
		server2 = tentacle.DefaultServiceBuilder().InsertProtocol(meta2).Build(nil)
	}

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	listenAddr, _ := server1.Listen(addr)
	server2.Dial(listenAddr, tentacle.TargetProtocol{Tag: tentacle.All})

	for {
		if server2.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var x bool
	x = res.Load().(bool)
	if !x {
		return errors.New("test fail")
	}
	return nil
}

func TestPriorityWithSecio(t *testing.T) {
	err := priorityTest(true)
	if err != nil {
		t.Fatal("test priority with secio fail")
	}
}

func TestPriority(t *testing.T) {
	err := priorityTest(false)
	if err != nil {
		t.Fatal("test priority fail")
	}
}
