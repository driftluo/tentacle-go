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

type ProtocolStream struct{}

func (p *ProtocolStream) Spawn(ctx *tentacle.SessionContext, control *tentacle.Service, read tentacle.SubstreamReadPart) {
	log.Println(fmt.Sprintf("pid: %d, sid: %d, remote addr: %s type: %s, version: %s", read.ProtocolID(), ctx.Sid, ctx.RemoteAddr, ctx.Ty.Name(), read.Version()))

	go func() {
		if read.ProtocolID() == tentacle.ProtocolID(1) {
			pid := read.ProtocolID()
			go func() {
				interval := time.NewTicker(5 * time.Second)

				for {
					select {
					case <-interval.C:
						control.FilterBroadcast(tentacle.TargetSession{Tag: tentacle.All}, pid, []byte("I am a interval message"))
					}
				}
			}()
		}

		for {
			msg, err := read.NextMsg()
			if err != nil {
				break
			}

			log.Println(fmt.Sprintf("received from sid: [%d], proto: [%d], data: %s", ctx.Sid, read.ProtocolID(), string(msg)))
		}

		log.Println(fmt.Sprintf("sid: %d, type: %s, pid: %d, closed", ctx.Sid, ctx.Ty.Name(), read.ProtocolID()))
	}()
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
	return tentacle.DefaultMeta().ID(pid).ProtoSpawn(&ProtocolStream{}).Build()
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
	wsaddr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1338/ws")
	server.Listen(wsaddr)
	for {
		if server.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}
