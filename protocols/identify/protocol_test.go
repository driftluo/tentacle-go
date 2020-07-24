package identify

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func TestProtocolInfoDecodeEncode(t *testing.T) {
	m1, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/1332/")
	info := new(identifyMessage)
	info.identify = []byte("test")
	info.observedAddr = m1
	info.listenAddrs = []multiaddr.Multiaddr{m1, m2}

	b := info.encode()

	decode, err := decodeToIdentifyMessage(b)
	if err != nil {
		t.Fatal(err)
	}

	if string(info.identify) != string(decode.identify) {
		t.Fatal("identify must eq")
	}

	if !info.observedAddr.Equal(decode.observedAddr) {
		t.Fatal("observedAddr must eq")
	}

	if len(info.listenAddrs) != len(decode.listenAddrs) {
		t.Fatal("listenAddrs len must eq")
	}

	for i, v := range info.listenAddrs {
		if !decode.listenAddrs[i].Equal(v) {
			t.Fatal("listenAddrs must eq")
		}
	}
}
