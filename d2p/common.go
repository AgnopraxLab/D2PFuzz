package d2p

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"net"
)

type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

type ConnClient interface {
	Self() *enode.Node
}

type Packet interface {
	// Name is the name of the package, for logging purposes.
	Name() string
	// Kind is the packet type, for logging purposes.
	Kind() byte
	// String is the print of packet
	String() string
}

type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	Unhandled chan<- ReadPacket // unhandled packets are sent on this channel
	// The options below are useful in very specific cases, like in unit tests.
	V5ProtocolID *[6]byte
	Log          log.Logger         // if set, log messages go here
	ValidSchemes enr.IdentityScheme // allowed identity schemes
	Clock        mclock.Clock
}

func GenKey() *ecdsa.PrivateKey {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Error("failed to generate private key: %v", err)
	}
	return privateKey
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

func (cfg Config) WithDefaults() Config {

	// Debug/test settings:
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}
