package eth

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
