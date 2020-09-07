package tentacle

import (
	"fmt"
	"testing"

	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

func TestExtractPeerID(t *testing.T) {
	pid := secio.RandomPeerID()

	ip1 := fmt.Sprintf("/ip4/127.0.0.1/tcp/1337/p2p/%s", pid.Bese58String())
	ip2 := fmt.Sprintf("/p2p/%s", pid.Bese58String())

	addr1, _ := ma.NewMultiaddr(ip1)
	pid1, _ := ExtractPeerID(addr1)

	addr2, _ := ma.NewMultiaddr(ip2)
	pid2, _ := ExtractPeerID(addr2)

	if pid.Bese58String() != pid1.Bese58String() {
		t.Fatal("ip1 fail")
	}

	if pid.Bese58String() != pid2.Bese58String() {
		t.Fatal("ip2 fail")
	}
}

func TestDeleteSlice(t *testing.T) {
	m1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1332/")
	m3, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/133/")
	m4, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1337/")
	m5, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/135/")
	m6, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1347/")
	m7, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1317/")
	m8, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1237/")
	m9, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/137/")

	a := []ma.Multiaddr{
		m1, m2, m3, m4, m5, m1, m6, m7, m8, m9, m1,
	}

	b := deleteSlice(a, m1)

	for _, v := range b {
		if v == m1 {
			t.Fatal("not delete")
		}
	}
}

func TestSupport(t *testing.T) {
	m1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := ma.NewMultiaddr("/ip4/127.0.0.1/udp/1336/")
	m3, _ := ma.NewMultiaddr("/dns/www.baidu.com/tcp/1336/")
	m4, _ := ma.NewMultiaddr("/dns/www.baidu.com/tcp/1336/ws")

	if !isSupport(m1) {
		t.Fatal("m1 fail")
	}
	if isSupport(m2) {
		t.Fatal("m2 fail")
	}
	if !isSupport(m3) {
		t.Fatal("m3 fail")
	}
	if !isSupport(m4) {
		t.Fatal("m3 fail")
	}
}
