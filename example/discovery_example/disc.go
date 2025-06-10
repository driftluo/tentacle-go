package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/driftluo/tentacle-go"
	"github.com/driftluo/tentacle-go/protocols/discovery"
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

type nodeState struct {
	score uint
	addrs map[string]bool
}

type simpleAddressManager struct {
	peers map[tentacle.SessionID]*nodeState
}

func (s *simpleAddressManager) AddNewAddr(id tentacle.SessionID, addr multiaddr.Multiaddr) {
	var state *nodeState
	var ok bool
	state, ok = s.peers[id]
	if !ok {
		state = &nodeState{score: 100, addrs: make(map[string]bool)}
		s.peers[id] = state
	}
	log.Printf("%s", addr)

	state.addrs[addr.String()] = true
}
func (s *simpleAddressManager) AddNewAddrs(id tentacle.SessionID, addrs []multiaddr.Multiaddr) {
	for _, addr := range addrs {
		s.AddNewAddr(id, addr)
	}
}
func (s *simpleAddressManager) Misbehave(id tentacle.SessionID, b discovery.Misbehavior) *discovery.MisbehaveResult {
	if b.String() == "InvaildData" {
		return discovery.Disconnect()
	}

	var state *nodeState
	var ok bool
	state, ok = s.peers[id]
	if !ok {
		state = &nodeState{score: 100, addrs: make(map[string]bool)}
		s.peers[id] = state
	}

	state.score -= 20

	if state.score < 0 {
		return discovery.Disconnect()
	}
	return discovery.Continue()
}

func (s *simpleAddressManager) GetRandom(n int) []multiaddr.Multiaddr {
	res := []multiaddr.Multiaddr{}

	i := 0
	for _, state := range s.peers {
		if i > n-1 {
			break
		}
		for addr := range state.addrs {
			res = append(res, multiaddr.StringCast(addr))
			i++
			if i > n-1 {
				break
			}
		}
	}
	return res
}

type simpleHandler struct{}

func (s *simpleHandler) HandleError(ctx *tentacle.ServiceContext, err tentacle.ServiceError) {
	log.Println("service error: ", err.String())
}

func (s *simpleHandler) HandleEvent(ctx *tentacle.ServiceContext, event tentacle.ServiceEvent) {
	log.Println("service event: ", event.String())
}

func createMeta(pid tentacle.ProtocolID, start uint16) tentacle.ProtocolMeta {
	addrs := make(map[string]bool, 3333)

	for i := 0; i < 3333; i++ {
		addr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", start+uint16(i)))
		addrs[addr.String()] = true
	}

	peers := make(map[tentacle.SessionID]*nodeState)
	peers[tentacle.SessionID(0)] = &nodeState{score: 100, addrs: addrs}

	addrMgr := simpleAddressManager{peers: peers}

	return tentacle.DefaultMeta().ID(pid).ServiceHandle(discovery.NewProtocol(&addrMgr, 7*time.Second, 3*time.Second, false)).Build()
}

func client() {
	port := os.Args[1]
	client := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(1), 1400)).KeyPair(secio.GenerateSecp256k1()).Build(&simpleHandler{})

	laddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%s", port))
	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	client.Dial(addr, tentacle.TargetProtocol{Tag: tentacle.All})
	client.Listen(laddr)
	for {
		if client.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}

func server() {
	server := tentacle.DefaultServiceBuilder().InsertProtocol(createMeta(tentacle.ProtocolID(1), 1400)).KeyPair(secio.GenerateSecp256k1()).Build(&simpleHandler{})

	addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337")
	server.Listen(addr)
	for {
		if server.IsShutdown() {
			break
		}
		time.Sleep(20 * time.Second)
	}
}
