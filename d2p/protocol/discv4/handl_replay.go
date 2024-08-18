package discv4

import (
	"net"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

// handleReply dispatches a reply packet, invoking reply matchers. It returns
// whether any matcher considered the packet acceptable.
func (t *UDPv4) handleReply(from enode.ID, fromIP net.IP, req Packet) bool {
	matched := make(chan bool, 1)

	//print testing
	//fmt.Println(req.String())

	select {
	case t.gotreply <- reply{from, fromIP, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closeCtx.Done():
		return false
	}
}

func (t *UDPv4) write(toaddr *net.UDPAddr, toid enode.ID, what string, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	t.log.Trace(">> "+what, "id", toid, "addr", toaddr, "err", err)
	return err
}

func (t *UDPv4) send(toaddr *net.UDPAddr, toid enode.ID, req Packet) ([]byte, error) {
	packet, hash, err := Encode(t.priv, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, toid, req.Name(), packet)
}

// checkBond checks if the given node has a recent enough endpoint proof.
func (t *UDPv4) checkBond(id enode.ID, ip net.IP) bool {
	// return time.Since(t.db.LastPongReceived(id, ip)) < bondExpiration
	return true
}

// ensureBond solicits a ping from a node if we haven't seen a ping from it for a while.
// This ensures there is a valid endpoint proof on the remote end.
func (t *UDPv4) ensureBond(toid enode.ID, toaddr *net.UDPAddr) {
	/*t
	ooOld := time.Since(t.db.LastPingReceived(toid, toaddr.IP)) > bondExpiration
	if tooOld || t.db.FindFails(toid, toaddr.IP) > maxFindnodeFailures {
		rm := t.sendPing(toid, toaddr, nil)
		<-rm.errc
		// Wait for them to ping back and process our pong.
		time.Sleep(respTimeout)
	}
	*/
	return
}

// PING/v4

func (t *UDPv4) verifyPing(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	req := h.Packet.(*Ping)

	if Expired(req.Expiration) {
		return errExpired
	}
	senderKey, err := DecodePubkey(secp256k1.S256(), fromKey)
	if err != nil {
		return err
	}
	h.senderKey = senderKey
	return nil
}

func (t *UDPv4) handlePing(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*Ping)

	// Reply with Pong.
	if err := t.sendPong(fromID, from, req, mac); err != nil {
		// handle error if needed
	}

	// Ping back if our last pong on file is too far in the past.
	/*
		n := wrapNode(enode.NewV4(h.senderKey, from.IP, int(req.From.TCP), from.Port))
		if time.Since(t.db.LastPongReceived(n.ID(), from.IP)) > bondExpiration {
			t.sendPing(fromID, from, func() {
				t.tab.addVerifiedNode(n)
			})
		} else {
			t.tab.addVerifiedNode(n)
		}
	*/

	// Update node database and endpoint predictor.
	// t.localNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
}

// PONG/v4

func (t *UDPv4) verifyPong(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	req := h.Packet.(*Pong)

	if Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.IP, req) {
		return errUnsolicitedReply
	}
	// t.localNode.UDPEndpointStatement(from, &net.UDPAddr{IP: req.To.IP, Port: int(req.To.UDP)})
	return nil
}

// FINDNODE/v4

func (t *UDPv4) verifyFindnode(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	req := h.Packet.(*Findnode)

	if Expired(req.Expiration) {
		return errExpired
	}
	if !t.checkBond(fromID, from.IP) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors' packet (which is a much bigger packet than
		// findnode) to the victim.
		return errUnknownNode
	}
	return nil
}

func (t *UDPv4) handleFindnode(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	req := h.Packet.(*Findnode)

	// 创建一个自定义的节点记录
	key, _ := crypto.GenerateKey()
	var r enr.Record
	r.Set(enr.IP(net.IP{127, 0, 0, 1}))
	r.Set(enr.UDP(30303))
	r.Set(enr.TCP(30303)) //16个一组
	r.Set(Secp256k1(key.PublicKey))
	r.Set(enr.WithEntry("target", req.Target))

	// 使用节点记录创建一个新的 enode.Node 对象
	customNode, _ := enode.New(enode.ValidSchemes, &r)

	// 将自定义节点作为最接近的节点
	closest := []*node{wrapNode(customNode)}

	// 发送 neighbors
	t.sendNeighbors(from, fromID, closest)
}

// NEIGHBORS/v4

func (t *UDPv4) verifyNeighbors(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	req := h.Packet.(*Neighbors)

	if Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.IP, h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}

// ENRREQUEST/v4

func (t *UDPv4) verifyENRRequest(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	req := h.Packet.(*ENRRequest)

	if Expired(req.Expiration) {
		return errExpired
	}
	if !t.checkBond(fromID, from.IP) {
		return errUnknownNode
	}
	return nil
}

func (t *UDPv4) handleENRRequest(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte) {
	t.sendENRResponse(from, fromID, mac)
}

// ENRRESPONSE/v4

func (t *UDPv4) verifyENRResponse(h *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error {
	if !t.handleReply(fromID, from.IP, h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}
