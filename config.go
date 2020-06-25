package tentacle

import (
	"fmt"
	"strconv"
)

// NameFn define protocol name, default is "/p2p/protocol_id"
//
// Used to interact with the remote service to determine whether the protocol is supported.
//
// If not found, the protocol connection(not session just sub stream) will be closed,
// and return a `ProtocolSelectError` event.
type NameFn = func(ProtocolID) string

var defaultNameFn = func(id ProtocolID) string {
	return fmt.Sprintf("/p2p/%s", strconv.Itoa(int(id)))
}

type meta struct {
	id              ProtocolID
	name            NameFn
	supportVersions []string
	codec           CodecFn
	selectVersion   SelectFn
	beforeReceive   BeforeReceive
}
