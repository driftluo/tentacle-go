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

type aUint32 struct {
	inner uint32
}

func (a *aUint32) add() {
	atomic.AddUint32(&a.inner, 1)
}

func (a *aUint32) load() uint32 {
	return atomic.LoadUint32(&a.inner)
}

type pOpenPhandle struct {
	countClose uint
	count      *aUint32
}

func (p *pOpenPhandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	ctx.SetSessionNotify(ctx.Sid, ctx.Pid, 300*time.Millisecond, 1)
}

func (p *pOpenPhandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	ctx.Shutdown()
}

func (p *pOpenPhandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *pOpenPhandle) Notify(ctx *tentacle.ProtocolContextRef, token uint64) {
	switch token {
	case 1:
		p.countClose++
		if p.countClose > 10 {
			ctx.Shutdown()
		} else if p.countClose > 3 {
			// 1. open protocol
			// 2. set another notify
			// 3. must notify same session protocol handle
			ctx.OpenProtocol(ctx.Sid, ctx.Pid)
			ctx.SetSessionNotify(ctx.Sid, ctx.Pid, 300*time.Millisecond, 2)
		}
	case 2:
		// if protocol handle is same, `count close` must be greater than zero
		// Otherwise it is a bug
		if p.countClose > 0 {
			p.count.add()
		}
	}
}

func createPOpenMeta(pid tentacle.ProtocolID) (tentacle.ProtocolMeta, *aUint32) {
	var count aUint32 = aUint32{}

	meta := tentacle.DefaultMeta().ID(pid).SessionHandle(func() tentacle.SessionProtocol {
		return &pOpenPhandle{count: &count}
	}).Build()
	return meta, &count
}

func pOpenTest(secioC bool) error {
	meta1, _ := createPOpenMeta(tentacle.ProtocolID(1))
	meta2, res := createPOpenMeta(tentacle.ProtocolID(1))

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

	res2 := res.load()
	if res2 > 0 {
		return nil
	}

	return errors.New("test fail")
}

func TestPOpenWithSecio(t *testing.T) {
	err := pOpenTest(true)
	if err != nil {
		t.Fatal("test protocol open with secio fail")
	}
}

func TestPOpen(t *testing.T) {
	err := pOpenTest(false)
	if err != nil {
		t.Fatal("test protocol open fail")
	}
}
