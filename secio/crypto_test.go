package secio

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDecodePanic(t *testing.T) {
	var encodeData, decodeData []byte
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")
	encryptCripher, _ := AESGCM(key)
	decryptCripher, _ := AESGCM(key)

	encodeData = encryptCripher.Encrypt(plaintext)
	decodeData, _ = decryptCripher.Decrypt(encodeData)
	if bytes.Compare(plaintext, decodeData) != 0 {
		panic("first time")
	}

	plantext2 := []byte("exampleplaintext2")
	encodeData = encryptCripher.Encrypt(plantext2)
	decodeData, _ = decryptCripher.Decrypt(encodeData)

	if bytes.Compare(plantext2, decodeData) != 0 {
		panic("second time")
	}
}

func TestStretch(t *testing.T) {
	output := make([]byte, 32)

	secret1 := []byte("")

	key1 := hmac.New(sha256.New, secret1)

	stretchKey(key1, output)

	if bytes.Compare(output, []byte{103, 144, 60, 199, 85, 145, 239, 71, 79, 198, 85, 164, 32, 53, 143, 205, 50, 48,
		153, 10, 37, 32, 85, 1, 226, 61, 193, 1, 154, 120, 207, 80}) != 0 {
		panic("stretch key1")
	}

	secret2 := []byte{157, 166, 80, 144, 77, 193, 198, 6, 23, 220, 87, 220, 191, 72, 168, 197, 54, 33,
		219, 225, 84, 156, 165, 37, 149, 224, 244, 32, 170, 79, 125, 35, 171, 26, 178, 176,
		92, 168, 22, 27, 205, 44, 229, 61, 152, 21, 222, 81, 241, 81, 116, 236, 74, 166,
		89, 145, 5, 162, 108, 230, 55, 54, 9, 17}

	key2 := hmac.New(sha256.New, secret2)

	stretchKey(key2, output)

	if bytes.Compare(output, []byte{39, 151, 182, 63, 180, 175, 224, 139, 42, 131, 130, 116, 55, 146, 62, 31, 157, 95,
		217, 15, 73, 81, 10, 83, 243, 141, 64, 227, 103, 144, 99, 121}) != 0 {
		panic("stretch key2")
	}

	secret3 := []byte{98, 219, 94, 104, 97, 70, 139, 13, 185, 110, 56, 36, 66, 3, 80, 224, 32, 205, 102,
		170, 59, 32, 140, 245, 86, 102, 231, 68, 85, 249, 227, 243, 57, 53, 171, 36, 62,
		225, 178, 74, 89, 142, 151, 94, 183, 231, 208, 166, 244, 130, 130, 209, 248, 65,
		19, 48, 127, 127, 55, 82, 117, 154, 124, 108}

	key3 := hmac.New(sha256.New, secret3)

	stretchKey(key3, output)

	if bytes.Compare(output, []byte{28, 39, 158, 206, 164, 16, 211, 194, 99, 43, 208, 36, 24, 141, 90, 93, 157, 236,
		238, 111, 170, 0, 60, 11, 49, 174, 177, 121, 30, 12, 182, 25}) != 0 {
		panic("stretch key3")
	}
}
