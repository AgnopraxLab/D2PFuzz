package d2p

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"net"
)

type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	// The options below are useful in very specific cases, like in unit tests.
	V5ProtocolID *[6]byte
	Log          log.Logger // if set, log messages go here
	Clock        mclock.Clock
}

func GenKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}
