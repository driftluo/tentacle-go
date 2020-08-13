package main

import (
	"log"
	"os"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/protocols/ping"
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

type pingCallback struct{}

func (p *pingCallback) ReceivedPing(ctx *tentacle.ProtocolContextRef, id secio.PeerID) {
	log.Println("received ping from: ", id.Bese58String())
}

func (p *pingCallback) ReceivedPong(ctx *tentacle.ProtocolContextRef, id secio.PeerID, t time.Duration) {
	log.Println("received pong from: ", id.Bese58String(), t)
}

func (p *pingCallback) Timeout(ctx *tentacle.ProtocolContext, id secio.PeerID) {
	log.Println("peer timeout: ", id.Bese58String())
}

func (p *pingCallback) UnexpectedError(ctx *tentacle.ProtocolContextRef, id secio.PeerID) {
	log.Println("unexpected error: ", id.Bese58String())
}

type simpleHandler struct{}

func (s *simpleHandler) HandleError(ctx *tentacle.ServiceContext, err tentacle.ServiceError) {
	log.Println("service error: ", err.String())
}

func (s *simpleHandler) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	log.Println("service event: ", event.String())
}

func createMeta(pid tentacle.ProtocolID) tentacle.ProtocolMeta {
	return tentacle.DefaultMeta().ID(pid).ServiceHandle(ping.NewProtocol(&pingCallback{}, 5*time.Second, 15*time.Second)).Build()
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
