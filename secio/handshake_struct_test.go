package secio

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDecodeEncodePropose(t *testing.T) {
	nonce := make([]byte, 16)
	pubkey := make([]byte, 256)
	rand.Read(nonce)
	rand.Read(pubkey)

	pr := new(propose)

	pr.rand = nonce
	pr.pubkey = pubkey
	pr.ciphers = "123"
	pr.exchange = "321"
	pr.hashes = "012"

	encodeByte := pr.encode()

	decode, err := decodeToPropose(encodeByte)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decode.rand, pr.rand) {
		t.Fatal("rand must eq")
	}

	if !bytes.Equal(decode.pubkey, pr.pubkey) {
		t.Fatal("pubkey must eq")
	}

	if pr.ciphers != decode.ciphers {
		t.Fatal("ciphers must eq")
	}

	if pr.exchange != decode.exchange {
		t.Fatal("exchange must eq")
	}

	if pr.hashes != decode.hashes {
		t.Fatal("exchange must eq")
	}
}

func TestDecodeEncodeExchange(t *testing.T) {
	epub := make([]byte, 256)
	sig := make([]byte, 256)

	rand.Read(epub)
	rand.Read(sig)

	ex := new(exchange)
	ex.epubkey = epub
	ex.signature = sig

	encodeByte := ex.encode()
	decode, err := decodeToExchange(encodeByte)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decode.epubkey, ex.epubkey) {
		t.Fatal("epubkey must eq")
	}

	if !bytes.Equal(decode.signature, ex.signature) {
		t.Fatal("signature must eq")
	}
}
