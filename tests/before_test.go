package tests

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

type beforePHandle struct{}

func (p *beforePHandle) Init(ctx *tentacle.ProtocolContext) {}

func (p *beforePHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	if ctx.Ty.Name() == "Inbound" {
		ctx.SendMessage([]byte(strings.Repeat("x", 10)))
	}
}

func (p *beforePHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	ctx.Shutdown()
}

func (p *beforePHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	if ctx.Ty.Name() == "Outbound" {
		ctx.Shutdown()
	}
}

func (p *beforePHandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {}

func createBeforeMeta(pid tentacle.ProtocolID) (tentacle.ProtocolMeta, *int32) {
	var count int32 = 0
	meta := tentacle.DefaultMeta().ID(pid).BeforeSend(func(src []byte) []byte {
		atomic.AddInt32(&count, 1)
		return src
	}).BeforeReceive(func(src []byte) []byte {
		atomic.AddInt32(&count, 1)
		return src
	}).ServiceHandle(&beforePHandle{}).Build()
	return meta, &count
}

func beforeTest(secioC bool) error {
	meta1, count1 := createBeforeMeta(tentacle.ProtocolID(1))
	meta2, count2 := createBeforeMeta(tentacle.ProtocolID(1))

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

	res1 := atomic.LoadInt32(count1)
	res2 := atomic.LoadInt32(count2)

	if res1 != 1 || res2 != 1 {
		return errors.New("test fail")
	}
	return nil
}

func TestBeforeWithSecio(t *testing.T) {
	err := beforeTest(true)
	if err != nil {
		t.Fatal("before with secio fail")
	}
}

func TestBefore(t *testing.T) {
	err := beforeTest(false)
	if err != nil {
		t.Fatal("before fail")
	}
}
