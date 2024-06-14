package discv4

import (
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
)

func (t *UDPv4) sendENRResponse(to *net.UDPAddr, toID enode.ID, mac []byte) {
	response := t.makeENRResponse(mac)
	_, err := t.send(to, toID, response)
	if err != nil {
		log.Error("Failed to send ENR response", "err", err)
	}
}

func (t *UDPv4) makeENRResponse(mac []byte) *ENRResponse {
	return &ENRResponse{
		ReplyTok: mac,
		Record:   *t.localNode.Node().Record(),
	}
}