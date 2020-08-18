package ping

import (
	"encoding/binary"
	"errors"

	mol "github.com/driftluo/tentacle-go/protocols/ping/mol"
)

const (
	ping uint8 = iota
	pong
)

type pingPayload struct {
	tag   uint8
	nonce uint32
}

func buildPing(nonce uint32) []byte {
	nonceLe := uint32ToBytes(nonce)
	nonceMol := mol.NewUint32Builder().Nth0(mol.NewByte(nonceLe[0])).Nth1(mol.NewByte(nonceLe[1])).Nth2(mol.NewByte(nonceLe[2])).Nth3(mol.NewByte(nonceLe[3])).Build()

	ping := mol.NewPingBuilder().Nonce(nonceMol).Build()
	payload := mol.NewPingPayloadBuilder().Set(mol.PingPayloadUnionFromPing(ping)).Build()
	msg := mol.NewPingMessageBuilder().Payload(payload).Build()
	return msg.AsSlice()
}

func buildPong(nonce uint32) []byte {
	nonceLe := uint32ToBytes(nonce)
	nonceMol := mol.NewUint32Builder().Nth0(mol.NewByte(nonceLe[0])).Nth1(mol.NewByte(nonceLe[1])).Nth2(mol.NewByte(nonceLe[2])).Nth3(mol.NewByte(nonceLe[3])).Build()

	pong := mol.NewPongBuilder().Nonce(nonceMol).Build()
	payload := mol.NewPingPayloadBuilder().Set(mol.PingPayloadUnionFromPong(pong)).Build()
	msg := mol.NewPingMessageBuilder().Payload(payload).Build()
	return msg.AsSlice()
}

func decodeToPingPayLoad(data []byte) (*pingPayload, error) {
	ptr, err := mol.PingMessageFromSlice(data, true)
	if err != nil {
		return nil, err
	}

	union := ptr.Payload().ToUnion()

	switch union.ItemName() {
	case "Ping":
		return &pingPayload{tag: ping, nonce: bytesToUint32(union.IntoPing().Nonce().RawData())}, nil
	case "Pong":
		return &pingPayload{tag: pong, nonce: bytesToUint32(union.IntoPong().Nonce().RawData())}, nil
	}

	// never reach
	return nil, errors.New("not found")
}

func uint32ToBytes(i uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, i)
	return buf
}

func bytesToUint32(buf []byte) uint32 {
	return binary.LittleEndian.Uint32(buf)
}
