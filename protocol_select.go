package tentacle

import (
	"errors"
	"io"

	mol "github.com/driftluo/tentacle-go/mol"
	"github.com/driftluo/tentacle-go/secio"
	"github.com/libp2p/go-msgio"
)

// ErrProtocolNotMatch is server don't support this protocol
var ErrProtocolNotMatch = errors.New("Don't support this protocol")

// ErrVersionNotMatch is node can't support this version
var ErrVersionNotMatch = errors.New("Can't find the same version")

// SelectFn is the function for protocol version select
type SelectFn func([]string, []string) (string, error)

// intoStringVec convert to molecule stringVec
func intoStringVec(sv []string) mol.StringVec {
	tmp := make([]mol.String, len(sv))

	for i, v := range sv {
		tmp[i] = intoString(v)
	}

	return mol.NewStringVecBuilder().Set(tmp).Build()
}

// intoString convert to molecule string
func intoString(s string) mol.String {
	b := secio.Str2bytes(s)
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

// ProtocolInfo is the handshake message of open protocol
type ProtocolInfo struct {
	name           string
	supportVersion []string
}

func (p ProtocolInfo) encode() []byte {
	name := intoString(p.name)
	supportVersion := intoStringVec(p.supportVersion)

	pi := mol.NewProtocolInfoMolBuilder().Name(name).SupportVersions(supportVersion).Build()
	return pi.AsSlice()
}

func decodeToProtocolInfo(b []byte) (*ProtocolInfo, error) {
	pi, err := mol.ProtocolInfoMolFromSlice(b, true)
	if err != nil {
		return nil, err
	}

	sp := pi.SupportVersions()
	spLen := sp.Len()
	versions := make([]string, spLen)

	for i := 0; uint(i) < spLen; i++ {
		versions[i] = secio.Bytes2str(sp.Get(uint(i)).RawData())
	}

	protocolInfo := new(ProtocolInfo)
	protocolInfo.name = secio.Bytes2str(pi.Name().RawData())
	protocolInfo.supportVersion = versions

	return protocolInfo, nil
}

// SelectVersion choose the highest version of the two sides, assume that slices are sorted
func SelectVersion(local, remote []string) (string, error) {
	localLen := len(local)
	remoteLen := len(remote)

	if localLen == 0 || remoteLen == 0 {
		return "", ErrVersionNotMatch
	}

	localLen--
	remoteLen--

	for {
		if local[localLen] == remote[remoteLen] {
			return local[localLen], nil
		} else if local[localLen] > remote[remoteLen] {
			if localLen == 0 {
				return "", ErrVersionNotMatch
			}
			localLen--
		} else {
			if remoteLen == 0 {
				return "", ErrVersionNotMatch
			}
			remoteLen--
		}
	}
}

// Performs a handshake on the given socket.
//
// Select the protocol version, return the protocol name, plus the version.
func clientSelect(conn io.ReadWriter, protoInfo ProtocolInfo) (string, string, error) {
	socket := msgio.Combine(msgio.NewWriter(conn), msgio.NewReader(conn))

	socket.WriteMsg(protoInfo.encode())
	msg, err := socket.ReadMsg()

	if err != nil {
		return "", "", err
	}

	remote, err := decodeToProtocolInfo(msg)

	if err != nil {
		return "", "", err
	}

	if len(remote.supportVersion) == 0 {
		return remote.name, "", ErrVersionNotMatch
	}
	return remote.name, remote.supportVersion[0], nil
}

type info struct {
	inner ProtocolInfo
	fn    SelectFn
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return the protocol name, plus the version.
func serverSelect(conn io.ReadWriter, protoInfos map[string]info) (string, string, error) {
	socket := msgio.Combine(msgio.NewWriter(conn), msgio.NewReader(conn))

	msg, err := socket.ReadMsg()

	if err != nil {
		return "", "", err
	}

	remote, err := decodeToProtocolInfo(msg)

	if err != nil {
		return "", "", err
	}

	local, ok := protoInfos[remote.name]

	errResponse := func() {
		res := new(ProtocolInfo)
		res.name = remote.name
		socket.WriteMsg(res.encode())
	}

	if !ok {
		errResponse()
		return remote.name, "", ErrProtocolNotMatch
	}

	version, err := local.fn(local.inner.supportVersion, remote.supportVersion)

	if err != nil {
		errResponse()
		return remote.name, "", ErrVersionNotMatch
	}

	res := new(ProtocolInfo)
	res.name = remote.name
	res.supportVersion = []string{version}
	socket.WriteMsg(res.encode())

	return remote.name, version, nil
}
