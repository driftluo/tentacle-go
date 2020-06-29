package secio

import (
	"unsafe"

	mol "github.com/driftluo/tentacle-go/secio/mol"
)

// intoBytes convert to molecule bytes
func intoBytes(b []byte) mol.Bytes {
	tmp := intoByteslice(b)
	return mol.NewBytesBuilder().Set(tmp).Build()
}

// intoString convert to molecule string
func intoString(s string) mol.String {
	b := Str2bytes(s)
	tmp := intoByteslice(b)
	return mol.NewStringBuilder().Set(tmp).Build()
}

// intoByteslice convert to molecule byte slice
func intoByteslice(b []byte) []mol.Byte {
	tmp := make([]mol.Byte, len(b))
	for i, v := range b {
		tmp[i] = mol.NewByte(v)
	}
	return tmp
}

// Str2bytes convert to bytes in place
// https://www.cnblogs.com/shuiyuejiangnan/p/9707066.html
func Str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

// Bytes2str convert to string in place
func Bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// propose is handshake propose context
type propose struct {
	rand     []byte
	pubkey   []byte
	exchange string
	ciphers  string
	hashes   string
}

func (p propose) encode() []byte {
	rand := intoBytes(p.rand)

	pubkey := intoBytes(p.pubkey)

	exchange := intoString(p.exchange)

	ciphers := intoString(p.ciphers)

	hashes := intoString(p.hashes)

	pr := mol.NewProposeBuilder().Rand(rand).Pubkey(pubkey).Exchanges(exchange).Ciphers(ciphers).Hashes(hashes).Build()

	return pr.AsSlice()
}

func decodeToPropose(b []byte) (*propose, error) {
	pr, err := mol.ProposeFromSlice(b, true)
	if err != nil {
		return nil, err
	}

	propose := new(propose)
	propose.rand = pr.Rand().RawData()
	propose.pubkey = pr.Pubkey().RawData()
	propose.exchange = Bytes2str(pr.Exchanges().RawData())
	propose.ciphers = Bytes2str(pr.Ciphers().RawData())
	propose.hashes = Bytes2str(pr.Hashes().RawData())

	return propose, nil
}

type exchange struct {
	epubkey   []byte
	signature []byte
}

func (e exchange) encode() []byte {
	epub := intoBytes(e.epubkey)
	sig := intoBytes(e.signature)

	ex := mol.NewExchangeBuilder().Epubkey(epub).Signature(sig).Build()

	return ex.AsSlice()
}

func decodeToExchange(b []byte) (*exchange, error) {
	ex, err := mol.ExchangeFromSlice(b, true)
	if err != nil {
		return nil, err
	}

	exchange := new(exchange)
	exchange.epubkey = ex.Epubkey().RawData()
	exchange.signature = ex.Signature().RawData()

	return exchange, nil
}
