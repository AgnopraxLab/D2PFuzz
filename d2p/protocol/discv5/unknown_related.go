package discv5

import (
	crand "crypto/rand"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
)


// makeUnknown creates an Unknown packet with a random nonce.
func (t *UDPv5) makeUnknown() *Unknown {
	unknownPacket := &Unknown{
		Nonce: Nonce{}, // 创建一个空的 Nonce
	}
	crand.Read(unknownPacket.Nonce[:])
	return unknownPacket
}

// sendUnknown sends an Unknown packet to a node and waits for a Whoareyou response.
func (t *UDPv5) sendUnknown(n *enode.Node, callback func(*Whoareyou)) error {
	req := t.makeUnknown()

	resp := t.callToNode(n, WhoareyouPacket, req)
	defer t.callDone(resp)

	select {
	case whoareyou := <-resp.ch:
		if callback != nil {
			callback(whoareyou.(*Whoareyou))
		}
		return nil
	case err := <-resp.err:
		return err
	}
}

// handleUnknown initiates a handshake by responding with WHOAREYOU.
func (t *UDPv5) handleUnknown(p *Unknown, fromID enode.ID, fromAddr *net.UDPAddr) {
	challenge := &Whoareyou{Nonce: p.Nonce}
	crand.Read(challenge.IDNonce[:])
	if n := t.getNode(fromID); n != nil {
		challenge.Node = n
		challenge.RecordSeq = n.Seq()
	}
	t.sendResponse(fromID, fromAddr, challenge)
}

// getNode looks for a node record in table and database.
func (t *UDPv5) getNode(id enode.ID) *enode.Node {
	if n := t.localNode.Database().Node(id); n != nil {
		return n
	}
	return nil
}