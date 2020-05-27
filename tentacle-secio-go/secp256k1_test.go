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

func TestSecp256k1MoleculeEncodeDecode(t *testing.T) {
	priv := GenerateSecp256k1()
	pubkey := priv.GenPublic()

	mol := pubkey.Encode()

	pub, err := DecodeToSecpPub(mol)

	if err != nil {
		t.Fatal("decode from molecule should success")
	}

	if !pubkey.Equals(pub) {
		t.Fatal("pubkey should equal")
	}
}
