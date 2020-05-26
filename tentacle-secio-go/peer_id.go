package secio

import (
	"bytes"
	"errors"
	"math/rand"

	bs58 "github.com/mr-tron/base58/base58"
	"github.com/multiformats/go-varint"
)

// PeerID is a byte slice
type PeerID []byte

// SHA256CODE code
const SHA256CODE = 0x12

// SHA256SIZE 32
const SHA256SIZE = 32

// errors
var (
	ErrUnknownCode   = errors.New("unknown multihash code")
	ErrTooShort      = errors.New("peer id too short. must be >= 2 bytes")
	ErrInvalidPeerID = errors.New("input isn't valid peer id")

	ErrVarintBufferShort = errors.New("uvarint: buffer too small")
	ErrVarintTooLong     = errors.New("uvarint: varint too big (max 64bit)")
)

func uvarint(buf []byte) (uint64, []byte, error) {
	varint, readSize, err := varint.FromUvarint(buf)
	if err != nil {
		return varint, buf, err
	}

	if readSize == 0 {
		return varint, buf, ErrVarintBufferShort
	} else if readSize < 0 {
		return varint, buf[-readSize:], ErrVarintTooLong
	} else {
		return varint, buf[readSize:], nil
	}
}

// Bese58String return bs58 format string
func (p PeerID) Bese58String() string {
	return bs58.Encode([]byte(p))
}

// IsKey compare peer id with key
func (p *PeerID) IsKey(k Key) bool {
	kp := k.PeerID()
	return bytes.Compare(*p, kp) == 0
}

// Bytes return bytes
func (p *PeerID) Bytes() []byte {
	return []byte(*p)
}

// PeerIDFromBese58 parses a Bese58-encoded string.
func PeerIDFromBese58(s string) (p PeerID, e error) {
	var err error
	var b []byte

	b, err = bs58.Decode(s)
	if err != nil {
		return nil, ErrInvalidPeerID
	}

	p, err = PeerIDFromBytes(b)

	if err != nil {
		return nil, err
	}

	return p, nil
}

// PeerIDFromBytes parses a slice
func PeerIDFromBytes(data []byte) (PeerID, error) {
	lend := len(data)
	if lend < 2 {
		return nil, ErrTooShort
	}

	code, tmp, err := uvarint(data)

	if err != nil {
		return nil, err
	}

	if code != SHA256CODE {
		return nil, ErrUnknownCode
	}

	if len(tmp) != SHA256SIZE+1 {
		return nil, ErrInvalidPeerID
	}

	if tmp[0] != SHA256SIZE {
		return nil, ErrInvalidPeerID
	}

	return PeerID(data), nil
}

func fromSeed(seed []byte) PeerID {
	headerLen := varint.UvarintSize(SHA256CODE)
	buf := make([]byte, headerLen+1+SHA256SIZE)
	n := varint.PutUvarint(buf, SHA256CODE)
	buf[headerLen] = SHA256SIZE
	hash := hashSha256(seed)
	copy(buf[n+1:], hash[:])

	return PeerID(buf)
}

// RandomPeerID return a random PeerID
func RandomPeerID() PeerID {
	a := make([]byte, 20)
	rand.Read(a)

	return fromSeed(a)
}

// PeerIDFromKey return a PeerID from the key
func PeerIDFromKey(k Key) PeerID {
	return k.PeerID()
}
