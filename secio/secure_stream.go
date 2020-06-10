package secio

import (
	"net"
	"sync"
	"time"

	msgio "github.com/libp2p/go-msgio"
)

var _ net.Conn = &SecureConn{}

// SecureConn is a stream for secio
type SecureConn struct {
	secioConn msgio.ReadWriteCloser

	remotePub PubKey

	conn net.Conn
}

// RemotePub return remote pubkey
func (sec *SecureConn) RemotePub() PubKey {
	return sec.remotePub
}

func (sec *SecureConn) Read(b []byte) (n int, err error) {
	return sec.secioConn.Read(b)
}

func (sec *SecureConn) Write(b []byte) (n int, err error) {
	return sec.secioConn.Write(b)
}

// Close closes the connection.
func (sec *SecureConn) Close() error {
	return sec.secioConn.Close()
}

// LocalAddr returns the local network address.
func (sec *SecureConn) LocalAddr() net.Addr {
	return sec.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (sec *SecureConn) RemoteAddr() net.Addr {
	return sec.conn.RemoteAddr()
}

// SetDeadline call inner conn set deadline
func (sec *SecureConn) SetDeadline(t time.Time) error {
	return sec.conn.SetDeadline(t)
}

// SetReadDeadline call inner conn set read deadline
func (sec *SecureConn) SetReadDeadline(t time.Time) error {
	return sec.conn.SetReadDeadline(t)
}

// SetWriteDeadline call inner conn set write deadline
func (sec *SecureConn) SetWriteDeadline(t time.Time) error {
	return sec.conn.SetWriteDeadline(t)
}

type writeSide struct {
	socket       msgio.WriteCloser
	encodeCipher StreamCipher

	sync.Mutex
}

func newWriteSide(socket msgio.WriteCloser, encodeCipher StreamCipher) msgio.WriteCloser {
	return &writeSide{socket: socket, encodeCipher: encodeCipher}
}

// Write writes passed in buffer as a single message.
func (w *writeSide) Write(b []byte) (int, error) {
	if err := w.WriteMsg(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteMsg writes the msg into inner io writer
func (w *writeSide) WriteMsg(b []byte) error {
	w.Lock()
	defer w.Unlock()

	buf := w.encodeCipher.Encrypt(b)

	err := w.socket.WriteMsg(buf)
	return err
}

func (w *writeSide) Close() error {
	return w.Close()
}

type readSide struct {
	socket       msgio.Reader
	decodeCipher StreamCipher
	buf          []byte

	sync.Mutex
}

func newReadSide(socket msgio.Reader, decodeCipher StreamCipher) msgio.Reader {
	return &readSide{socket: socket, decodeCipher: decodeCipher}
}

func (r *readSide) NextMsgLen() (int, error) {
	return r.socket.NextMsgLen()
}

func (r *readSide) ReleaseMsg(b []byte) {
	r.socket.ReleaseMsg(b)
}

func (r *readSide) fillBuf() error {
	buf, err := r.ReadMsg()
	if err != nil {
		return err
	}

	r.buf = append(r.buf, buf...)

	return nil
}

func (r *readSide) Read(buf []byte) (int, error) {
	if len(r.buf) == 0 {
		if err := r.fillBuf(); err != nil {
			return 0, err
		}
	}

	r.Lock()
	defer r.Unlock()

	var readLen int

	bufLen := len(r.buf)
	outputLen := len(buf)

	if bufLen < outputLen {
		readLen = bufLen
	} else {
		readLen = outputLen
	}

	if readLen == 0 {
		return 0, nil
	}

	copy(buf[:readLen], r.buf[:readLen])
	r.buf = r.buf[readLen:]

	return readLen, nil
}

func (r *readSide) ReadMsg() ([]byte, error) {
	r.Lock()
	defer r.Unlock()

	msg, err := r.socket.ReadMsg()
	if err != nil {
		return nil, err
	}

	buf, err := r.decodeCipher.Decrypt(msg)
	if err != nil {
		r.socket.ReleaseMsg(msg)
		return nil, err
	}
	return buf, nil
}
