package discovery

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func TestDiscoveryMessageDecodeEncodeOnGetNodes(t *testing.T) {
	g1inner := getNodes{version: 0, count: 1000, listenPort: 0}
	ginfo1 := discoveryMessage{tag: getNode, inner: g1inner}
	g2inner := getNodes{version: 0, count: 1000, listenPort: 1024}
	ginfo2 := discoveryMessage{tag: getNode, inner: g2inner}

	b1 := ginfo1.encode()
	b2 := ginfo2.encode()

	decode1, err := decodeToDiscoveryMessage(b1)
	if err != nil {
		t.Fatal(err)
	}

	decode2, err := decodeToDiscoveryMessage(b2)
	if err != nil {
		t.Fatal(err)
	}

	d1, ok := decode1.inner.(getNodes)
	if !ok {
		t.Fatal("ginfo1 decode fail on type assert")
	}

	d2, ok := decode2.inner.(getNodes)
	if !ok {
		t.Fatal("ginfo2 decode fail on type assert")
	}

	if d1.version != g1inner.version {
		t.Fatal("d1 version != g1 version")
	}
	if d1.count != g1inner.count {
		t.Fatal("d1 count != g1 count")
	}
	if d1.listenPort != g1inner.listenPort {
		t.Fatal("d1 listenPort != g1 listenPort")
	}

	if d2.version != g2inner.version {
		t.Fatal("d2 version != g2 version")
	}
	if d2.count != g2inner.count {
		t.Fatal("d2 count != g2 count")
	}
	if d2.listenPort != g2inner.listenPort {
		t.Fatal("d2 listenPort != g2 listenPort")
	}
}

func TestDiscoveryMessageDecodeEncodeOnNodes(t *testing.T) {
	m1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")

	n1inner := nodes{announce: true, items: []node{{addresses: []multiaddr.Multiaddr{m1}}}}
	ninfo1 := discoveryMessage{tag: sendNodes, inner: n1inner}
	n2inner := nodes{announce: true, items: []node{{addresses: []multiaddr.Multiaddr{m1}}}}
	ninfo2 := discoveryMessage{tag: sendNodes, inner: n2inner}

	b1 := ninfo1.encode()
	b2 := ninfo2.encode()

	decode1, err := decodeToDiscoveryMessage(b1)
	if err != nil {
		t.Fatal(err)
	}

	decode2, err := decodeToDiscoveryMessage(b2)
	if err != nil {
		t.Fatal(err)
	}

	d1, ok := decode1.inner.(nodes)
	if !ok {
		t.Fatal("ninfo1 decode fail on type assert")
	}

	d2, ok := decode2.inner.(nodes)
	if !ok {
		t.Fatal("ninfo2 decode fail on type assert")
	}

	if d1.announce != n1inner.announce {
		t.Fatal("d1 announce != n1 announce")
	}

	if len(d1.items) != len(n1inner.items) {
		t.Fatal("d1 items len != n1 items len")
	}

	if !d1.items[0].addresses[0].Equal(n1inner.items[0].addresses[0]) {
		t.Fatal("d1 addresses must eq")
	}

	if d2.announce != n2inner.announce {
		t.Fatal("d2 announce != n2 announce")
	}

	if len(d2.items) != len(n2inner.items) {
		t.Fatal("d2 items len != n2 items len")
	}

	if !d2.items[0].addresses[0].Equal(n2inner.items[0].addresses[0]) {
		t.Fatal("d2 addresses must eq")
	}
}
