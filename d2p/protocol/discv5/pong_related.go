package discv5

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

func (t *UDPv5) makePong(reqID []byte, toAddr *net.UDPAddr) *Pong {
	remoteIP := toAddr.IP
	// Handle IPv4 mapped IPv6 addresses in the
	// event the local node is bound to an
	// ipv6 interface.
	if remoteIP.To4() != nil {
		remoteIP = remoteIP.To4()
	}

	return &Pong{
		ReqID:  reqID,
		ToIP:   remoteIP,
		ToPort: uint16(toAddr.Port),
		ENRSeq: t.localNode.Node().Seq(),
	}
}

func (t *UDPv5) sendPong(reqID []byte, toID enode.ID, toAddr *net.UDPAddr) error {
	pong := t.makePong(reqID, toAddr)
	return t.sendResponse(toID, toAddr, pong)
}
