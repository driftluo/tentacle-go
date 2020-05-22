package secio

import "testing"

func TestSecp256k1BasicSignAndVerify(t *testing.T) {
	priv := GenerateSecp256k1()
	pubkey := priv.GenPublic()

	data := []byte("test secp256k1")

	message := hashSha256(data)

	sig, err := priv.Sign(message[:])

	if err != nil {
		t.Fatal(err)
	}

	err = pubkey.Verify(message[:], sig)

	if err != nil {
		t.Fatal(err)
	}

	message[0] = ^message[0]

	err = pubkey.Verify(message[:], sig)

	if err == nil {
		t.Fatal("signature matched and shouldn't")
	}
}
