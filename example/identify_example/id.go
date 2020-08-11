package main

import (
	"log"
	"os"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/protocols/identify"
	"github.com/driftluo/tentacle-go/secio"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	args := os.Args
	if len(args) == 2 {
		if args[1] == "server" {
			log.Println("Starting server ...")
			server()
			return
		}
	}
	log.Println("Starting client ...")
	client()
}

type identifyCallback struct {
	localListenAddrs []multiaddr.Multiaddr
}

func (i *identifyCallback) ReceivedIdentify(ctx *tentacle.ProtocolContextRef, data []byte) *identify.MisbehaveResult {
	log.Println(secio.Bytes2str(data))
	return identify.Continue()
}

func (i *identifyCallback) Identify() []byte {
	return secio.Str2bytes("Identify message")
}

func (i *identifyCallback) LocalListenAddrs() []multiaddr.Multiaddr {
	return i.localListenAddrs
}

func (i *identifyCallback) AddRemoteListenAddrs(secio.PeerID, []multiaddr.Multiaddr) {}

func (i *identifyCallback) AddObservedAddr(secio.PeerID, multiaddr.Multiaddr, tentacle.SessionType) *identify.MisbehaveResult {
	return identify.Continue()
}

func (i *identifyCallback) Misbehave(secio.PeerID, identify.Misbehavior) *identify.MisbehaveResult {
	return identify.Disconnect()
}

type simpleHandler struct{}

func (s *simpleHandler) HandleError(ctx *tentacle.ServiceContext, err tentacle.ServiceError) {
	log.Println("service error: ", err.String())
}

func (s *simpleHandler) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	log.Println("service event: ", event.String())
}

func createMeta(pid tentacle.ProtocolID) tentacle.ProtocolMeta {
	return tentacle.DefaultMeta().ID(pid).ServiceHandle(identify.NewProtocol(&identifyCallback{localListenAddrs: []multiaddr.Multiaddr{}})).Build()
}

func client() {
	client := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(1))).KeyPair(secio.GenerateSecp256k1()).Build(&simpleHandler{})

	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	client.Dial(addr, tentacle.TargetProtocol{Tag: tentacle.All})
	for {
		if client.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}

func server() {
	server := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(1))).KeyPair(secio.GenerateSecp256k1()).Build(&simpleHandler{})

	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	server.Listen(addr)
	for {
		if server.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}
