package secio

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecodePanic(t *testing.T) {
	var encodeData, decodeData []byte
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")
	encryptCripher, _ := AESGCM(key)
	decryptCripher, _ := AESGCM(key)

	encodeData, _ = encryptCripher.Encrypt(plaintext)
	decodeData, _ = decryptCripher.Decrypt(encodeData)
	if bytes.Compare(plaintext, decodeData) != 0 {
		panic("first time")
	}

	plantext2 := []byte("exampleplaintext2")
	encodeData, _ = encryptCripher.Encrypt(plantext2)
	decodeData, _ = decryptCripher.Decrypt(encodeData)

	if bytes.Compare(plantext2, decodeData) != 0 {
		panic("second time")
	}
}
