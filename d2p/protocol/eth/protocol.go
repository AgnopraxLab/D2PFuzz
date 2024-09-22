package eth

import (
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// Unexported devp2p message codes from p2p/peer.go.
const (
	handshakeMsg = 0x00
	discMsg      = 0x01
	pingMsg      = 0x02
	pongMsg      = 0x03
)

// Unexported devp2p protocol lengths from p2p package.
const (
	baseProtoLen = 16
	ethProtoLen  = 17
	snapProtoLen = 8
)

const (
	baseProto Proto = iota
	ethProto
	snapProto
)

const (
	BaseProto Proto = iota
	EthProto
	SnapProto
)

type Proto int

func protoOffset(proto Proto) uint64 {
	switch proto {
	case baseProto:
		return 0
	case ethProto:
		return baseProtoLen
	case snapProto:
		return baseProtoLen + ethProtoLen
	default:
		panic("unhandled protocol")
	}
}

// Unexported handshake structure from p2p/peer.go.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []p2p.Cap
	ListenPort uint64
	ID         []byte
	Rest       []rlp.RawValue `rlp:"tail"`
}

// getProto returns the protocol a certain message code is associated with
// (assuming the negotiated capabilities are exactly {eth,snap})
func getProto(code uint64) Proto {
	switch {
	case code < baseProtoLen:
		return baseProto
	case code < baseProtoLen+ethProtoLen:
		return EthProto
	case code < baseProtoLen+ethProtoLen+snapProtoLen:
		return snapProto
	default:
		panic("unhandled msg code beyond last protocol")
	}
}
