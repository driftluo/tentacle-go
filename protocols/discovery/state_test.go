package discovery

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func TestUpdatePort(t *testing.T) {
	m1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337/")
	expectM1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/16/")
	expectM2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/7/")

	u1 := updateTCPPort(m1, 16)
	u2 := updateTCPPort(m2, 7)

	if !u1.Equal(expectM1) {
		t.Fatal("replace port fail")
	}
	if !u2.Equal(expectM2) {
		t.Fatal("replace port fail")
	}
}

func TestGetPort(t *testing.T) {
	m1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1337/")

	p1, err := getTCPPort(m1)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := getTCPPort(m2)
	if err != nil {
		t.Fatal(err)
	}

	if p1 != 1336 {
		t.Fatal("get m1 port fail")
	}

	if p2 != 1337 {
		t.Fatal("get m1 port fail")
	}
}
