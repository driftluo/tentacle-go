package tests

import (
	"testing"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

type disconnectPhandle struct {
	count uint
}

func (p *disconnectPhandle) Init(ctx *tentacle.ProtocolContext) {}

func (p *disconnectPhandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	p.count++
}

func (p *disconnectPhandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	p.count--
}

func (p *disconnectPhandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {}

func (p *disconnectPhandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {}

func disconnectedTest(secioC bool) {
	meta1 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ServiceHandle(&disconnectPhandle{}).Build()
	meta2 := tentacle.DefaultMeta().ID(tentacle.ProtocolID(1)).ServiceHandle(&disconnectPhandle{}).Build()

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

	time.Sleep(5 * time.Second)
	server2.Disconnect(tentacle.SessionID(1))

	for {
		if server2.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDisconnectedWithSecio(t *testing.T) {
	disconnectedTest(true)
}

func TestDisconnected(t *testing.T) {
	disconnectedTest(false)
}
