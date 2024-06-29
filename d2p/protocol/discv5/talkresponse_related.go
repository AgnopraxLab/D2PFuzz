package discv5

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
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


// handleCallResponse dispatches a response packet to the call waiting for it.
func (t *UDPv5) handleCallResponse(fromID enode.ID, fromAddr *net.UDPAddr, p Packet) bool {
	ac := t.activeCallByNode[fromID]
	if ac == nil || !bytes.Equal(p.RequestID(), ac.reqid) {
		t.log.Debug(fmt.Sprintf("Unsolicited/late %s response", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if !fromAddr.IP.Equal(ac.addr.IP) || fromAddr.Port != ac.addr.Port {
		t.log.Debug(fmt.Sprintf("%s from wrong endpoint", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if p.Kind() != ac.responseType {
		t.log.Debug(fmt.Sprintf("Wrong discv5 response type %s", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	t.startResponseTimeout(ac)
	ac.ch <- p
	return true
}