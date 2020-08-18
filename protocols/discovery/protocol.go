package discovery

import (
	"encoding/binary"
	"errors"

	mol "github.com/driftluo/tentacle-go/protocols/discovery/mol"
	"github.com/multiformats/go-multiaddr"
)

const (
	getNode uint8 = iota
	sendNodes
)

type discoveryMessage struct {
	tag   uint8
	inner interface{}
}

func (d *discoveryMessage) encode() []byte {
	var payload mol.DiscoveryPayload
	switch d.tag {
	case getNode:
		inner := d.inner.(getNodes)

		versionLe := uint32ToBytes(inner.version)
		versionMol := mol.NewUint32Builder().Nth0(mol.NewByte(versionLe[0])).Nth1(mol.NewByte(versionLe[1])).Nth2(mol.NewByte(versionLe[2])).Nth3(mol.NewByte(versionLe[3])).Build()

		countLe := uint32ToBytes(inner.count)
		countMol := mol.NewUint32Builder().Nth0(mol.NewByte(countLe[0])).Nth1(mol.NewByte(countLe[1])).Nth2(mol.NewByte(countLe[2])).Nth3(mol.NewByte(countLe[3])).Build()

		var portOpt mol.PortOpt

		if inner.listenPort == 0 {
			portOpt = mol.NewPortOptBuilder().Build()
		} else {
			portLe := uint16ToBytes(inner.listenPort)
			portMol := mol.NewUint16Builder().Nth0(mol.NewByte(portLe[0])).Nth1(mol.NewByte(portLe[1])).Build()
			portOpt = mol.NewPortOptBuilder().Set(portMol).Build()
		}
		gnode := mol.NewGetNodesBuilder().Version(versionMol).Count(countMol).ListenPort(portOpt).Build()

		payload = mol.NewDiscoveryPayloadBuilder().Set(mol.DiscoveryPayloadUnionFromGetNodes(gnode)).Build()

	case sendNodes:
		inner := d.inner.(nodes)
		var announce mol.Bool
		if inner.announce {
			announce = mol.NewBoolBuilder().Set([1]mol.Byte{mol.NewByte(1)}).Build()
		} else {
			announce = mol.NewBoolBuilder().Set([1]mol.Byte{mol.NewByte(0)}).Build()
		}

		itemVecs := make([]mol.Node, len(inner.items))
		for idx, item := range inner.items {
			itemVecs[idx] = mol.NewNodeBuilder().Addresses(intoBytesVec(item.addresses)).Build()
		}
		items := mol.NewNodeVecBuilder().Set(itemVecs).Build()
		nd := mol.NewNodesBuilder().Announce(announce).Items(items).Build()
		payload = mol.NewDiscoveryPayloadBuilder().Set(mol.DiscoveryPayloadUnionFromNodes(nd)).Build()
	}

	msg := mol.NewDiscoveryMessageBuilder().Payload(payload).Build()
	return msg.AsSlice()
}

func decodeToDiscoveryMessage(data []byte) (*discoveryMessage, error) {
	ptr, err := mol.DiscoveryMessageFromSlice(data, true)
	if err != nil {
		return nil, err
	}

	union := ptr.Payload().ToUnion()

	switch union.ItemName() {
	case "GetNodes":
		rawGet := union.IntoGetNodes()

		var port uint16
		portMol, err := rawGet.ListenPort().IntoUint16()

		if err != nil {
			port = 0
		} else {
			port = bytesToUint16(portMol.RawData())
		}
		get := getNodes{version: bytesToUint32(rawGet.Version().RawData()), count: bytesToUint32(rawGet.Count().RawData()), listenPort: port}
		return &discoveryMessage{tag: getNode, inner: get}, nil

	case "Nodes":
		rawNodes := union.IntoNodes()

		var announce bool
		switch rawNodes.Announce().RawData()[0] {
		case 0:
			announce = false
		case 1:
			announce = true
		default:
			return nil, errors.New("Invalid data")
		}

		raw := rawNodes.Items()
		rawLen := raw.Len()
		items := make([]node, rawLen)

		for i := 0; uint(i) < rawLen; i++ {
			rawAddresses := raw.Get(uint(i)).Addresses()
			rawInnerLen := rawAddresses.Len()
			addresses := make([]multiaddr.Multiaddr, rawInnerLen)

			for j := 0; uint(j) < rawInnerLen; j++ {
				addr, err := multiaddr.NewMultiaddrBytes(rawAddresses.Get(uint(j)).RawData())
				if err != nil {
					return nil, err
				}
				addresses[j] = addr
			}
			items[i] = node{addresses: addresses}
		}

		return &discoveryMessage{tag: sendNodes, inner: nodes{announce: announce, items: items}}, nil
	}

	// never reach
	return nil, errors.New("not found")
}

type getNodes struct {
	version    uint32
	count      uint32
	listenPort uint16
}

type nodes struct {
	announce bool
	items    []node
}

type node struct {
	addresses []multiaddr.Multiaddr
}

func uint32ToBytes(i uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, i)
	return buf
}

func bytesToUint32(buf []byte) uint32 {
	return binary.LittleEndian.Uint32(buf)
}

func uint16ToBytes(i uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, i)
	return buf
}

func bytesToUint16(buf []byte) uint16 {
	return binary.LittleEndian.Uint16(buf)
}

func intoBytesVec(b []multiaddr.Multiaddr) mol.BytesVec {
	tmp := make([]mol.Bytes, len(b))
	for i, v := range b {
		tmp[i] = intoBytes(v.Bytes())
	}

	return mol.NewBytesVecBuilder().Set(tmp).Build()
}

func intoBytes(b []byte) mol.Bytes {
	tmp := intoByteslice(b)
	return mol.NewBytesBuilder().Set(tmp).Build()
}

func intoByteslice(b []byte) []mol.Byte {
	tmp := make([]mol.Byte, len(b))
	for i, v := range b {
		tmp[i] = mol.NewByte(v)
	}
	return tmp
}
