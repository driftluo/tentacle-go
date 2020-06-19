package secio

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"net"

	msgio "github.com/libp2p/go-msgio"
)

// Config of handshake
type Config struct {
	key                PrivKey
	agreementsProposal string
	ciphersProposal    string
	digestsProposal    string
	maxFrameLength     int
}

// NewConfig return a default config
func NewConfig(k PrivKey) *Config {
	return &Config{
		key:                k,
		agreementsProposal: DefaultAgreementsProposition,
		ciphersProposal:    DefaultCiphersProposition,
		digestsProposal:    DefaultDigestsProposition,
		maxFrameLength:     1024 * 1024 * 8,
	}
}

// MaxFrameLength replace default frame size, default is 8M
func (c *Config) MaxFrameLength(size int) *Config {
	c.maxFrameLength = size
	return c
}

// KeyAgreements try replace default agreements function
// but if new one can't supported by this library, it will do nothing
func (c *Config) KeyAgreements(agreement string) *Config {
	if checkAgreements(agreement) {
		c.agreementsProposal = agreement
	}
	return c
}

// Ciphers try replace default ciphers function
// but if new one can't supported by this library, it will do nothing
func (c *Config) Ciphers(ci string) *Config {
	if checkCiphers(ci) {
		c.ciphersProposal = ci
	}
	return c
}

// Digests try replace default digests function
// but if new one can't supported by this library, it will do nothing
func (c *Config) Digests(d string) *Config {
	if checkDigests(d) {
		c.digestsProposal = d
	}
	return c
}

// Handshake attempts to perform a handshake on the given socket.
func (c *Config) Handshake(conn net.Conn) (*SecureConn, error) {
	secConn, err := c.handshake(conn)

	if err != nil {
		defer conn.Close()
		return nil, err
	}
	return secConn, nil
}

// Handshake attempts to perform a handshake on the given socket.
func (c *Config) handshake(conn net.Conn) (*SecureConn, error) {
	socket := msgio.Combine(msgio.NewWriter(conn), msgio.NewReaderSize(conn, c.maxFrameLength))

	localNonce := make([]byte, 16)
	_, err := rand.Read(localNonce)
	if err != nil {
		return nil, err
	}

	localPubkey := c.key.GenPublic()
	localPropose := new(propose)
	localPropose.rand = localNonce
	localPropose.pubkey = localPubkey.Encode()
	localPropose.exchange = c.agreementsProposal
	localPropose.ciphers = c.ciphersProposal
	localPropose.hashes = c.digestsProposal

	localProposeBytes := localPropose.encode()

	// sending proposition to remote and receive the remote's proposition.
	remoteProposeBytes, err := readWriteMsg(socket, localProposeBytes)

	if err != nil {
		return nil, err
	}

	defer socket.ReleaseMsg(remoteProposeBytes)

	remotePropose, err := decodeToPropose(remoteProposeBytes)

	if err != nil {
		return nil, ErrInvalidData
	}

	remotePubkey, err := DecodeToSecpPub(remotePropose.pubkey)

	if err != nil {
		return nil, ErrInvalidData
	}

	if localPubkey.Equals(remotePubkey) {
		return nil, ErrConnectSelf
	}

	// use raw pubkey bytes and nonce to decide order
	oh1 := hashSha256(append(remotePubkey.Bytes(), localNonce...))
	oh2 := hashSha256(append(localPubkey.Bytes(), remotePropose.rand...))
	order := bytes.Compare(oh1[:], oh2[:])

	chosenExchange, err := selectPropose(order, localPropose.exchange, remotePropose.exchange)
	if err != nil {
		return nil, err
	}

	chosenCipher, err := selectPropose(order, localPropose.ciphers, remotePropose.ciphers)
	if err != nil {
		return nil, err
	}

	chosenHash, err := selectPropose(order, localPropose.hashes, remotePropose.hashes)
	if err != nil {
		return nil, err
	}

	epubkey, genSecret, err := GenerateEphemeralKeyPair(chosenExchange)
	if err != nil {
		return nil, ErrEphemeralKeyGenerationFailed
	}

	dataToSign := new(bytes.Buffer)
	dataToSign.Write(localProposeBytes)
	dataToSign.Write(remoteProposeBytes)
	dataToSign.Write(epubkey)

	localMsg := hashSha256(dataToSign.Bytes())

	localExchange := new(exchange)
	localExchange.epubkey = epubkey
	signBytes, err := c.key.Sign(localMsg[:])
	if err != nil {
		return nil, err
	}
	localExchange.signature = signBytes

	localExchangeBytes := localExchange.encode()

	// sending exchange to remote and received the remote's exchange
	remoteExchangeBytes, err := readWriteMsg(socket, localExchangeBytes)
	if err != nil {
		return nil, err
	}

	defer socket.ReleaseMsg(remoteExchangeBytes)

	remoteExchange, err := decodeToExchange(remoteExchangeBytes)
	if err != nil {
		return nil, ErrInvalidData
	}

	dataToVerify := new(bytes.Buffer)
	dataToVerify.Write(remoteProposeBytes)
	dataToVerify.Write(localProposeBytes)
	dataToVerify.Write(remoteExchange.epubkey)

	remoteMsg := hashSha256(dataToVerify.Bytes())

	if err = remotePubkey.Verify(remoteMsg[:], remoteExchange.signature); err != nil {
		return nil, ErrVerificationFail
	}

	keyMaterial, err := genSecret(remoteExchange.epubkey)
	if err != nil {
		return nil, ErrSecretGenerationFailed
	}

	localKey, remoteKey, err := genDoubleKey(chosenCipher, chosenHash, order, keyMaterial)
	if err != nil {
		return nil, err
	}

	encodeCipher, decodeCipher, err := genStreamCipher(chosenCipher, localKey, remoteKey)
	if err != nil {
		return nil, err
	}

	r := newReadSide(socket, decodeCipher)
	w := newWriteSide(socket, encodeCipher)

	secio := msgio.Combine(w, r)

	sourceNonce, err := readWriteMsg(secio, remotePropose.rand)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(localNonce, sourceNonce) {
		return nil, fmt.Errorf("Nonce expact %s, but read %s", localNonce, sourceNonce)
	}

	return &SecureConn{secioConn: secio, remotePub: remotePubkey, conn: conn}, nil
}

// read and write a message at the same time.
func readWriteMsg(c msgio.ReadWriter, out []byte) ([]byte, error) {
	wresult := make(chan error)
	go func() {
		wresult <- c.WriteMsg(out)
	}()

	msg, err1 := c.ReadMsg()

	err2 := <-wresult

	if err1 != nil {
		return nil, err1
	}
	if err2 != nil {
		c.ReleaseMsg(msg)
		return nil, err2
	}
	return msg, nil
}

func genDoubleKey(chosenCipher, chosenHash string, order int, keyMaterial []byte) ([]byte, []byte, error) {
	var cipherKeySize int
	var ivSize int
	switch chosenCipher {
	case "AES-128-GCM":
		ivSize = 12
		cipherKeySize = 16
	case "AES-256-GCM":
		ivSize = 12
		cipherKeySize = 32
	case "CHACHA20_POLY1305":
		ivSize = 12
		cipherKeySize = 32
	default:
		panic("Unrecognized cipher")
	}

	var h func() hash.Hash

	switch chosenHash {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		panic("Unrecognized hash function")
	}

	longKey := make([]byte, (ivSize+cipherKeySize+20)*2)

	hkey := hmac.New(h, keyMaterial)

	stretchKey(hkey, longKey)

	var localKey, remoteKey []byte

	half := len(longKey) / 2
	localKey = longKey[:half][ivSize : ivSize+cipherKeySize]
	remoteKey = longKey[half:][ivSize : ivSize+cipherKeySize]
	switch {
	case order < 0:
		localKey, remoteKey = remoteKey, localKey
	case order > 0:
	default:
		return nil, nil, errors.New("equal digest of public key and nonce for local and remote")
	}

	return localKey, remoteKey, nil
}

func genStreamCipher(chosenCipher string, localKey, remoteKey []byte) (StreamCipher, StreamCipher, error) {
	var encodeCipher, decodeCipher StreamCipher
	var err error
	switch chosenCipher {
	case "AES-128-GCM", "AES-256-GCM":
		encodeCipher, err = AESGCM(localKey)
		if err != nil {
			return nil, nil, err
		}
		decodeCipher, err = AESGCM(remoteKey)
		if err != nil {
			return nil, nil, err
		}
	case "CHACHA20_POLY1305":
		encodeCipher, err = Chacha20Poly1305(localKey)
		if err != nil {
			return nil, nil, err
		}
		decodeCipher, err = Chacha20Poly1305(remoteKey)
		if err != nil {
			return nil, nil, err
		}
	default:
		panic("Unrecognized cipher")
	}
	return encodeCipher, decodeCipher, nil
}
