package connection

import (
	"crypto/ecdsa"
	"net"

	"D2PFuzz/p2p/connection/rlpx"
)

func CreateConnection(conn net.Conn, dialDest *ecdsa.PublicKey) *rlpx.Conn {
	return rlpx.NewConn(conn, dialDest)
}
