package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

func deleteSlice(source []tentacle.SessionID, item tentacle.SessionID) []tentacle.SessionID {
	j := 0
	for _, val := range source {
		if val != item {
			source[j] = val
			j++
		}
	}
	return source[:j]
}

type pHandle struct {
	count       uint
	connections []tentacle.SessionID
	clearSender map[tentacle.SessionID]chan<- int
}

func (p *pHandle) Init(ctx *tentacle.ProtocolContext) {
	if ctx.Pid == tentacle.ProtocolID(0) {
		ctx.SetServiceNotify(tentacle.ProtocolID(0), 5*time.Second, 3)
	}
}

func (p *pHandle) Connected(ctx *tentacle.ProtocolContextRef, version string) {
	p.connections = append(p.connections, ctx.Sid)

	log.Println(fmt.Sprintf("pid: %d, sid: %d, remote addr: %s type: %s, version: %s", ctx.Pid, ctx.Sid, ctx.RemoteAddr, ctx.Ty.Name(), version))
	log.Println("connected sessions", p.connections)

	if ctx.Pid != tentacle.ProtocolID(1) {
		return
	}

	clear := make(chan int)
	p.clearSender[ctx.Sid] = clear

	go func() {
		interval := time.NewTicker(3 * time.Second)
		for {
			select {
			case <-interval.C:
				ctx.SendMessageTo(ctx.Sid, tentacle.ProtocolID(1), []byte("I am a interval message"))
			case <-clear:
				break
			}
		}
	}()
}

func (p *pHandle) Disconnected(ctx *tentacle.ProtocolContextRef) {
	deleteSlice(p.connections, ctx.Sid)

	sender, ok := p.clearSender[ctx.Sid]
	if ok {
		sender <- 0
	}
	delete(p.clearSender, ctx.Sid)

	log.Println(fmt.Sprintf("pid: %d close on session sid: %d", ctx.Pid, ctx.Sid))
}

func (p *pHandle) Received(ctx *tentacle.ProtocolContextRef, data []byte) {
	p.count++
	log.Println(fmt.Sprintf("received from sid: %d, pid: %d, data: %s, count: %d", ctx.Sid, ctx.Pid, string(data), p.count))

}

func (p *pHandle) Notify(ctx *tentacle.ProtocolContext, token uint64) {
	log.Println(fmt.Sprintf("proto %d received notify token: %d", ctx.Pid, token))
}

type shandle struct{}

func (s *shandle) HandleError(ctx *tentacle.ServiceContext, err tentacle.ServiceError) {
	log.Println("service error: ", err.String())
}

func (s *shandle) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	log.Println("service event: ", event.String())

	if event.Name() == "SessionOpen" {
		go func() {
			<-time.After(3 * time.Second)

			ctx.FilterBroadcast(tentacle.TargetSession{Tag: tentacle.All}, tentacle.ProtocolID(0), []byte("I am a delayed message"))
		}()
	}
}

func createMeta(pid tentacle.ProtocolID) tentacle.ProtocolMeta {
	return tentacle.DefaultMeta().ID(pid).ServiceHandle(&pHandle{
		count:       0,
		connections: []tentacle.SessionID{},
		clearSender: make(map[tentacle.SessionID]chan<- int),
	}).Build()
}

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

func client() {
	client := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(0))).InsertProtocol(createMeta(tentacle.ProtocolID(1))).InsertProtocol(createMeta(tentacle.ProtocolID(2))).KeyPair(secio.GenerateSecp256k1()).Build(&shandle{})

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	client.Dial(addr, tentacle.TargetProtocol{Tag: tentacle.All})
	for {
		if client.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}

func server() {
	server := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(0))).InsertProtocol(createMeta(tentacle.ProtocolID(1))).KeyPair(secio.GenerateSecp256k1()).Build(&shandle{})

	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	server.Listen(addr)
	for {
		if server.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}
