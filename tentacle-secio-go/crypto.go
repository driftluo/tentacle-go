package secio

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// StreamCipher a cipher of aead stream
type StreamCipher interface {
	Encrypt(input []byte) ([]byte, error)
	Decrypt(input []byte) ([]byte, error)
}

type metaCipher struct {
	nonce []byte
	aead  cipher.AEAD
}

func (c *metaCipher) Encrypt(input []byte) ([]byte, error) {
	nonceAdvance(c.nonce)
	output := c.aead.Seal(nil, c.nonce, input, nil)
	return output, nil
}

func (c *metaCipher) Decrypt(input []byte) ([]byte, error) {
	// input length must greater than aead tag len
	if len(input) < c.aead.Overhead() {
		return nil, errors.New("short packet")
	}
	nonceAdvance(c.nonce)
	output, err := c.aead.Open(nil, c.nonce, input, nil)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16 or 32 to select AES-128/256-GCM.
func AESGCM(psk []byte) (StreamCipher, error) {
	switch l := len(psk); l {
	case 16, 32: // AES 128/256
	default:
		return nil, aes.KeySizeError(l)
	}
	aead, err := aesGCM(psk)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())

	return &metaCipher{nonce: nonce, aead: aead}, nil
}

// Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func Chacha20Poly1305(psk []byte) (StreamCipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, errors.New("chacha20poly1305 keySize not match")
	}

	aead, err := chacha20poly1305.New(psk)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())

	return &metaCipher{nonce: nonce, aead: aead}, nil
}

func nonceAdvance(b []byte) {
	for i := range b {
		if 255 == b[i] {
			b[i] = 0
		} else {
			b[i]++
			return
		}
	}
}
