package secio

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	msgio "github.com/libp2p/go-msgio"
)

func getRWStream(ty string) (msgio.Reader, msgio.WriteCloser) {
	buf := new(bytes.Buffer)
	switch ty {
	case "AES-128-GCM":
		key := make([]byte, 16)
		rand.Read(key)

		encodeCipher, _ := AESGCM(key)
		decodeCipher, _ := AESGCM(key)
		w := newWriteSide(msgio.NewWriter(buf), encodeCipher)
		r := newReadSide(msgio.NewReader(buf), decodeCipher)
		return r, w
	case "AES-256-GCM", "CHACHA20_POLY1305":
		key := make([]byte, 32)
		rand.Read(key)

		encodeCipher, _ := AESGCM(key)
		decodeCipher, _ := AESGCM(key)
		w := newWriteSide(msgio.NewWriter(buf), encodeCipher)
		r := newReadSide(msgio.NewReader(buf), decodeCipher)
		return r, w
	}
	return nil, nil
}

func testEncodeDecode(ty string) error {
	r, w := getRWStream(ty)
	data := []byte("hello")

	err := w.WriteMsg(data)
	if err != nil {
		return err
	}

	msg, err := r.ReadMsg()
	if err != nil {
		return err
	}

	if !bytes.Equal(msg, data) {
		return fmt.Errorf("wr side fail, %s", ty)
	}
	return nil
}

func TestStream(t *testing.T) {
	var err error
	err = testEncodeDecode("AES-128-GCM")
	if err != nil {
		t.Fatal(err)
	}
	err = testEncodeDecode("AES-256-GCM")
	if err != nil {
		t.Fatal(err)
	}
	err = testEncodeDecode("CHACHA20_POLY1305")
	if err != nil {
		t.Fatal(err)
	}
}
