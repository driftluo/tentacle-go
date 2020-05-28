package secio

import "unsafe"

// IntoBytes convert to molecule bytes
func IntoBytes(b []byte) Bytes {
	tmp := IntoByteslice(b)
	return NewBytesBuilder().Set(tmp).Build()
}

// IntoString convert to molecule string
func IntoString(s string) String {
	b := str2bytes(s)
	tmp := IntoByteslice(b)
	return NewStringBuilder().Set(tmp).Build()
}

// IntoByteslice convert to molecule byte slice
func IntoByteslice(b []byte) []Byte {
	tmp := make([]Byte, len(b))
	for i, v := range b {
		tmp[i] = NewByte(v)
	}
	return tmp
}

// https://www.cnblogs.com/shuiyuejiangnan/p/9707066.html
func str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func bytes2str(b []byte) string {
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
	rand := IntoBytes(p.rand)

	pubkey := IntoBytes(p.pubkey)

	exchange := IntoString(p.exchange)

	ciphers := IntoString(p.ciphers)

	hashes := IntoString(p.hashes)

	pr := NewProposeBuilder().Rand(rand).Pubkey(pubkey).Exchanges(exchange).Ciphers(ciphers).Hashes(hashes).Build()

	return pr.AsSlice()
}

func decodeToPropose(b []byte) (*propose, error) {
	pr, err := ProposeFromSlice(b, true)
	if err != nil {
		return nil, err
	}

	propose := new(propose)
	propose.rand = pr.Rand().RawData()
	propose.pubkey = pr.Pubkey().RawData()
	propose.exchange = bytes2str(pr.Exchanges().RawData())
	propose.ciphers = bytes2str(pr.Ciphers().RawData())
	propose.hashes = bytes2str(pr.Hashes().RawData())

	return propose, nil
}

type exchange struct {
	epubkey   []byte
	signature []byte
}

func (e exchange) encode() []byte {
	epub := IntoBytes(e.epubkey)
	sig := IntoBytes(e.signature)

	ex := NewExchangeBuilder().Epubkey(epub).Signature(sig).Build()

	return ex.AsSlice()
}

func decodeToExchange(b []byte) (*exchange, error) {
	ex, err := ExchangeFromSlice(b, true)
	if err != nil {
		return nil, err
	}

	exchange := new(exchange)
	exchange.epubkey = ex.Epubkey().RawData()
	exchange.signature = ex.Signature().RawData()

	return exchange, nil
}
