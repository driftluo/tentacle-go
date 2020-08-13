package ping

import "testing"

func TestProtocolInfoDecodeEncode(t *testing.T) {
	pingRaw := buildPing(2)
	pongRaw := buildPong(2)

	decodePing, err := decodeToPingPayLoad(pingRaw)
	if err != nil {
		t.Fatal(err)
	}

	decodePong, err := decodeToPingPayLoad(pongRaw)
	if err != nil {
		t.Fatal(err)
	}

	if decodePing.tag != ping {
		t.Fatal("decode ping type fail")
	}

	if decodePing.nonce != 2 {
		t.Fatal("decode ping nonce fail")
	}

	if decodePong.tag != pong {
		t.Fatal("decode pong type fail")
	}

	if decodePong.nonce != 2 {
		t.Fatal("decode pong nonce fail")
	}
}
