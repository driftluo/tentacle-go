package tentacle

import (
	"io"
	"net"

	"github.com/libp2p/go-msgio"
)

// Codec use on protocol stream to en/decode message
type Codec interface {
	// ReadMsg reads the next message from the Reader
	ReadMsg() ([]byte, error)
	// WriteMsg writes the msg in the passed
	WriteMsg([]byte) error
	io.Closer
}

// CodecFn generate a codec
type CodecFn func(net.Conn) Codec

// BeforeSend unified processing of messages before they are sent
type BeforeSend func([]byte) []byte

// BeforeReceive unified processing of messages before user received
type BeforeReceive func([]byte) []byte

// DefaultCodec use by default, is a LengthDelimitedCodec
var DefaultCodec = func(conn net.Conn) Codec {
	return msgio.Combine(msgio.NewWriter(conn), msgio.NewReader(conn))
}

// DefaultBeforeSend use by default, do nothing
var DefaultBeforeSend = func(b []byte) []byte {
	return b
}

// DefaultBeforeReceive use by default, do nothing
var DefaultBeforeReceive = func(b []byte) []byte {
	return b
}
