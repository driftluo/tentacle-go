package secio

import (
	"crypto/subtle"
	"errors"
	"fmt"

	// may replace by std/crypto in future
	btcec "github.com/btcsuite/btcd/btcec"
)

type secp256k1PrivateKey btcec.PrivateKey

type secp256k1PublicKey btcec.PublicKey

// from molecule generate code
const typeID = Number(0)

// Key represents a crypto key that can be compared to another key
type Key interface {
	// Bytes returns raw bytes
	Bytes() []byte

	// Equals checks whether two PubKeys are the same
	Equals(Key) bool

	// TypeID return molecule union ID
	TypeID() Number

	// PeerID generate a peer id from key
	PeerID() PeerID
}

// PrivKey represents a private key that can be used to generate a public key and sign data
type PrivKey interface {
	Key

	// Cryptographically sign the given bytes
	Sign([]byte) ([]byte, error)

	// Return a public key paired with this private key
	GenPublic() PubKey
}

// PubKey is a public key that can be used to verifiy data signed with the corresponding private key
type PubKey interface {
	Key

	// Verify that 'sig' is the signed hash
	Verify(message []byte, sig []byte) error

	// Encode return molecule-encodes bytes
	Encode() []byte
}

// GenerateSecp256k1 return a random Secp256k1 private key
func GenerateSecp256k1() PrivKey {
	var priv *btcec.PrivateKey
	var err error
	for {
		priv, err = btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			continue
		} else {
			break
		}
	}

	return (*secp256k1PrivateKey)(priv)
}

// Secp256k1FromBytes return private key from bytes
func Secp256k1FromBytes(key []byte) (PrivKey, error) {
	if len(key) != btcec.PrivKeyBytesLen {
		return nil, fmt.Errorf("expected secp256k1 data size to be %d", btcec.PrivKeyBytesLen)
	}

	private, _ := btcec.PrivKeyFromBytes(btcec.S256(), key)
	return (*secp256k1PrivateKey)(private), nil
}

// Sign returns a signature from input message
func (p *secp256k1PrivateKey) Sign(msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("expected secp256k1 msg size to be 32")
	}

	sig, err := (*btcec.PrivateKey)(p).Sign(msg[:])

	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

// GenPublic returns a public key
func (p *secp256k1PrivateKey) GenPublic() PubKey {
	return (*secp256k1PublicKey)((*btcec.PrivateKey)(p).PubKey())
}

// Bytes returns the bytes of the key
func (p *secp256k1PrivateKey) Bytes() []byte {
	return (*btcec.PrivateKey)(p).Serialize()
}

// Equals compares two private keys
func (p *secp256k1PrivateKey) Equals(other Key) bool {
	sk, ok := other.(*secp256k1PrivateKey)
	if !ok {
		return basicEquals(p, other)
	}

	return p.GenPublic().Equals(sk.GenPublic())
}

// TypeId return molecule union ID
func (p *secp256k1PrivateKey) TypeID() Number {
	return Number(0)
}

// PeerID generate a peer id from key
func (p *secp256k1PrivateKey) PeerID() PeerID {
	return p.GenPublic().PeerID()
}

// Verify compares a signature against the input message
func (k *secp256k1PublicKey) Verify(msg []byte, sigRaw []byte) error {
	if len(msg) != 32 {
		return fmt.Errorf("expected secp256k1 msg size to be 32")
	}

	sig, err := btcec.ParseDERSignature(sigRaw, btcec.S256())
	if err != nil {
		return err
	}

	if sig.Verify(msg[:], (*btcec.PublicKey)(k)) {
		return nil
	}

	return fmt.Errorf("verify fail")
}

// Encode return molecule-encodes bytes
func (k *secp256k1PublicKey) Encode() []byte {
	b := IntoByteslice(k.Bytes())
	secp := PublicKeyUnionFromSecp256k1(NewSecp256k1Builder().Set(b).Build())
	pub := NewPublicKeyBuilder().Set(secp).Build()
	return pub.AsSlice()
}

// DecodeToSecpPub try parse bytes from molecule-encodes byte
func DecodeToSecpPub(data []byte) (PubKey, error) {
	k, err := PublicKeyFromSlice(data, true)
	if err != nil {
		return nil, err
	}

	if k.ItemID() != typeID {
		return nil, errors.New("not secp256k1 pubkey")
	}

	s, err := btcec.ParsePubKey(k.ToUnion().IntoSecp256k1().RawData(), btcec.S256())
	if err != nil {
		return nil, err
	}

	return (*secp256k1PublicKey)(s), nil
}

// Bytes returns the bytes of the key
func (k *secp256k1PublicKey) Bytes() []byte {
	return (*btcec.PublicKey)(k).SerializeCompressed()
}

// Equals compares two public keys
func (k *secp256k1PublicKey) Equals(other Key) bool {
	sk, ok := other.(*secp256k1PublicKey)
	if !ok {
		return basicEquals(k, other)
	}

	return (*btcec.PublicKey)(k).IsEqual((*btcec.PublicKey)(sk))
}

// TypeId return molecule union ID
func (k *secp256k1PublicKey) TypeID() Number {
	return typeID
}

// PeerID generate a peer id from key
func (k *secp256k1PublicKey) PeerID() PeerID {
	return fromSeed(k.Bytes())
}

func basicEquals(k1, k2 Key) bool {
	if k1.TypeID() != k2.TypeID() {
		return false
	}
	a := k1.Bytes()
	b := k2.Bytes()

	return subtle.ConstantTimeCompare(a, b) == 1
}
