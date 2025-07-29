package discv5

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// makeTalkResponse creates a TalkResponse packet.
func (t *UDPv5) makeTalkResponse(reqID []byte, message []byte) *TalkResponse {
	return &TalkResponse{
		ReqID:   reqID,
		Message: message,
	}
}

// sendTalkResponse sends a talk response to a node.
func (t *UDPv5) sendTalkResponse(reqID []byte, toID enode.ID, toAddr *net.UDPAddr, message []byte) error {
	resp := t.makeTalkResponse(reqID, message)
	return t.sendResponse(toID, toAddr, resp)
}
