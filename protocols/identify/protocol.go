package identify

import (
	mol "github.com/driftluo/tentacle-go/protocols/identify/mol"
	"github.com/multiformats/go-multiaddr"
)

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

func intoBytesVec(b []multiaddr.Multiaddr) mol.AddressVec {
	tmp := make([]mol.Address, len(b))
	for i, v := range b {
		tmp[i] = mol.NewAddressBuilder().Bytes(intoBytes(v.Bytes())).Build()
	}

	return mol.NewAddressVecBuilder().Set(tmp).Build()
}

type identifyMessage struct {
	listenAddrs  []multiaddr.Multiaddr
	observedAddr multiaddr.Multiaddr
	identify     []byte
}

func (i *identifyMessage) encode() []byte {
	identify := intoBytes(i.identify)
	observedAddr := mol.NewAddressBuilder().Bytes(intoBytes(i.observedAddr.Bytes())).Build()
	listenAddrs := intoBytesVec(i.listenAddrs)

	ptr := mol.NewIdentifyMessageBuilder().Identify(identify).ObservedAddr(observedAddr).ListenAddrs(listenAddrs).Build()

	return ptr.AsSlice()
}

func decodeToIdentifyMessage(data []byte) (*identifyMessage, error) {
	ptr, err := mol.IdentifyMessageFromSlice(data, true)
	if err != nil {
		return nil, err
	}

	observedAddr, err := multiaddr.NewMultiaddrBytes(ptr.ObservedAddr().Bytes().RawData())
	if err != nil {
		return nil, err
	}

	raw := ptr.ListenAddrs()
	rawLen := raw.Len()
	listenAddrs := make([]multiaddr.Multiaddr, rawLen)

	for i := 0; uint(i) < rawLen; i++ {
		addr, err := multiaddr.NewMultiaddrBytes(raw.Get(uint(i)).Bytes().RawData())
		if err != nil {
			return nil, err
		}

		listenAddrs[i] = addr
	}

	identifyMessage := new(identifyMessage)
	identifyMessage.identify = ptr.Identify().RawData()
	identifyMessage.observedAddr = observedAddr
	identifyMessage.listenAddrs = listenAddrs

	return identifyMessage, nil
}
