package secio

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"math"

	sha256 "github.com/minio/sha256-simd"
	"golang.org/x/crypto/chacha20poly1305"
)

// StreamCipher a cipher of aead stream
type StreamCipher interface {
	Encrypt(input []byte) []byte
	Decrypt(input []byte) ([]byte, error)
}

type metaCipher struct {
	nonce []byte
	aead  cipher.AEAD
}

func (c *metaCipher) Encrypt(input []byte) []byte {
	nonceAdvance(c.nonce)
	output := c.aead.Seal(nil, c.nonce, input, nil)
	return output
}

func (c *metaCipher) Decrypt(input []byte) ([]byte, error) {
	// input length must greater than aead tag len
	if len(input) < c.aead.Overhead() {
		return nil, ErrFrameTooShort
	}
	nonceAdvance(c.nonce)
	output, err := c.aead.Open(nil, c.nonce, input, nil)
	if err != nil {
		return nil, ErrDecipherFail
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

// [0, 0, 0, 0]
// [1, 0, 0, 0]
// ...
// [255, 0, 0, 0]
// [0, 1, 0, 0]
// [1, 1, 0, 0]
// ...
func nonceAdvance(b []byte) {
	for i := range b {
		if math.MaxUint8 == b[i] {
			b[i] = 0
		} else {
			b[i]++
			return
		}
	}
}

// Custom algorithm translated from reference implementations. Needs to be the same algorithm
// amongst all implementations.
func stretchKey(hash hash.Hash, result []byte) {
	seed := []byte("key expansion")

	// never error here
	hash.Write(seed)
	a := hash.Sum(nil)

	j := 0
	for j < len(result) {
		hash.Reset()

		hash.Write(a)
		hash.Write(seed)

		b := hash.Sum(nil)

		todo := len(b)

		if j+todo > len(result) {
			todo = len(result) - j
		}

		copy(result[j:j+todo], b)

		j += todo

		hash.Reset()

		hash.Write(a)

		a = hash.Sum(nil)
	}
}

// GenSharedKey generates the shared key from a given private key
type GenSharedKey func([]byte) ([]byte, error)

// GenerateEphemeralKeyPair returns an ephemeral public key and returns a function that will compute
// the shared secret key.
func GenerateEphemeralKeyPair(curveName string) ([]byte, GenSharedKey, error) {
	switch curveName {
	case "P-256":
		return generateP256KeyPair()
	case "P-384":
		return generateP384KeyPair()
	case "X25519":
		return generateX25519KeyPair()
	default:
		return nil, nil, fmt.Errorf("unknown curve name")
	}
}

func generateP256KeyPair() ([]byte, GenSharedKey, error) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes := privKey.PublicKey().Bytes()

	done := func(theirPub []byte) ([]byte, error) {
		theirPubKey, err := ecdh.P256().NewPublicKey(theirPub)
		if err != nil {
			return nil, err
		}

		secret, err := privKey.ECDH(theirPubKey)
		if err != nil {
			return nil, err
		}

		return secret, nil
	}

	return pubKeyBytes, done, nil
}

func generateP384KeyPair() ([]byte, GenSharedKey, error) {
	privKey, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes := privKey.PublicKey().Bytes()

	done := func(theirPub []byte) ([]byte, error) {
		theirPubKey, err := ecdh.P384().NewPublicKey(theirPub)
		if err != nil {
			return nil, err
		}

		secret, err := privKey.ECDH(theirPubKey)
		if err != nil {
			return nil, err
		}

		return secret, nil
	}

	return pubKeyBytes, done, nil
}

func generateX25519KeyPair() ([]byte, GenSharedKey, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes := privKey.PublicKey().Bytes()

	done := func(theirPub []byte) ([]byte, error) {
		theirPubKey, err := ecdh.X25519().NewPublicKey(theirPub)
		if err != nil {
			return nil, err
		}

		secret, err := privKey.ECDH(theirPubKey)
		if err != nil {
			return nil, err
		}

		return secret, nil
	}

	return pubKeyBytes, done, nil
}

func hashSha256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func pubkeyToBytes(pubkey any, ty string) []byte {
	switch ty {
	case "P-256":
		if key, ok := pubkey.(*ecdh.PublicKey); ok {
			return key.Bytes()
		}

	case "P-384":
		if key, ok := pubkey.(*ecdh.PublicKey); ok {
			return key.Bytes()
		}

	case "X25519":
		if key, ok := pubkey.(*ecdh.PublicKey); ok {
			return key.Bytes()
		}
	}
	return []byte{}
}

func bytesToPubkey(pubkey []byte, ty string) (crypto.PublicKey, error) {
	switch ty {
	case "P-256":
		return ecdh.P256().NewPublicKey(pubkey)
	case "P-384":
		return ecdh.P384().NewPublicKey(pubkey)
	case "X25519":
		return ecdh.X25519().NewPublicKey(pubkey)
	default:
		return nil, fmt.Errorf("unsupported curve type: %s", ty)
	}
}
