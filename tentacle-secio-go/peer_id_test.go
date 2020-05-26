package secio

import (
	"bytes"
	"testing"
)

func TestPeerIDBasic(t *testing.T) {
	// from ckb mannet config
	ids := []string{
		"QmXS4Kbc9HEeykHUTJCm2tNmqghbvWyYpUp6BtE5b6VrAU",
		"QmUaSuEdXNGJEKvkE4rCn3cwBrpRFUm5TsouF4M3Sjursv",
		"QmbT7QimcrcD5k2znoJiWpxoESxang6z1Gy9wof1rT1LKR",
		"QmShw2vtVt49wJagc1zGQXGS6LkQTcHxnEV3xs6y8MAmQN",
		"QmRHqhSGMGm5FtnkW8D6T83X7YwaiMAZXCXJJaKzQEo3rb",
		"QmeQwD2GGuZyFzDPbQEKFJUjmNaY9FG3X7WHPL823zFD3a",
		"QmWVt9kNFv8XM1CMqeJj2nmG4tJ4ViqgwzJMr7yYynp6qd",
		"QmaJP1sDiWZuwAEMghNHt7TrTgaMCyYaEMMYLc4YvoUGSV",
		"QmTjLAewCM6SivjpW7BJfSj1ABuPA7x6FsFu5ga7Xy2xig",
		"QmQBLw9TqkS8yu2Kg8UtiYzvxEQ7DfKiXLx8iD7bF8XRyj",
		"QmcEK1wUR287qSYdw8eHNWeQrFitQsCaZHHTM9wgvakxnS",
		"QmVi7reKhqVnoBYzW2nJYnrujVeckrZXhwuYbX7P2whPJg",
		"QmNRAvtC6L85hwp6vWnqaKonJw3dz1q39B4nXVQErzC4Hx",
		"QmagxSv7GNwKXQE7mi1iDjFHghjUpbqjBgqSot7PmMJqHA",
		"QmQidJaxciY3NT2PjsaCR4Gz8vB8kFn3Avwz96u6b3jGc1",
		"QmVeeCh81GTLGRwB7vRHXeTRdUHRYcfn6qKEfewhtiRJZC"}

	for _, value := range ids {
		_, err := PeerIDFromBese58(value)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPeerIDRandomPeerID(t *testing.T) {
	p1 := RandomPeerID()
	p2 := RandomPeerID()

	if bytes.Compare(p1, p2) == 0 {
		panic("first time")
	}

	var err error
	_, err = PeerIDFromBytes(p1)
	_, err = PeerIDFromBytes(p2)

	if err != nil {
		t.Fatal(err)
	}
}

func TestPeerIDTOBS58ThenBack(t *testing.T) {
	p := RandomPeerID()
	q, _ := PeerIDFromBese58(p.Bese58String())

	if bytes.Compare(p, q) != 0 {
		t.Fatal("fail to test peer id to bs58 then back")
	}
}

func TestIsKey(t *testing.T) {
	key := GenerateSecp256k1().GenPublic()
	peerID := key.PeerID()

	if !peerID.IsKey(key) {
		t.Fatal("fail to test is key function")
	}
}

func TestPeerIDTOBytesThenBack(t *testing.T) {
	p := RandomPeerID()
	q, _ := PeerIDFromBytes(p.Bytes())

	if bytes.Compare(p, q) != 0 {
		t.Fatal("fail to test peer id to bytes then back")
	}
}
