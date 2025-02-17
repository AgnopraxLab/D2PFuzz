package discv5

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

var (
	errChallengeNoCall = errors.New("no matching call")
	errChallengeTwice  = errors.New("second handshake")
)

// makeWhoareyou creates a Whoareyou packet.
func (t *UDPv5) makeWhoareyou() *Whoareyou {
	whoareyou := &Whoareyou{
		ChallengeData: make([]byte, 32),
		RecordSeq:     t.localNode.Seq(),
		Node:          t.localNode.Node(),
		IDNonce:       [16]byte{},
		Nonce:         [12]byte{},
	}
	crand.Read(whoareyou.IDNonce[:])
	crand.Read(whoareyou.Nonce[:])
	whoareyou.sent = t.clock.Now()
	crand.Read(whoareyou.ChallengeData)

	return whoareyou
}

func (t *UDPv5) sendWhoareyou(n *enode.Node, callback func()) error {
	req := t.makeWhoareyou()

	resp := t.CallToNode(n, UnknownPacket, req)
	defer t.CallDone(resp)

	select {
	case _ = <-resp.ch:
		// Handle the auth response
		// You might want to process the response here
		if callback != nil {
			callback()
		}
		return nil
	case err := <-resp.err:
		return err
	}
}

// handleWhoareyou resends the active call as a handshake packet.
func (t *UDPv5) handleWhoareyou(p *Whoareyou, fromID enode.ID, fromAddr *net.UDPAddr) {
	c, err := t.matchWithCall(fromID, p.Nonce)
	if err != nil {
		fmt.Printf("Failed to match call - Error: %v\n", err)
		t.log.Debug("Invalid "+p.Name(), "addr", fromAddr, "err", err)
		return
	}

	fmt.Printf("Successfully matched call with nonce: %x\n", p.Nonce)

	if c.node == nil {
		// Can't perform handshake because we don't have the ENR.
		t.log.Debug("Can't handle "+p.Name(), "addr", fromAddr, "err", "call has no ENR")
		c.err <- errors.New("remote wants handshake, but call has no ENR")
		return
	}

	// Resend the call that was answered by WHOAREYOU.
	t.log.Trace("<< "+p.Name(), "id", c.node.ID(), "addr", fromAddr)

	c.handshakeCount++
	c.challenge = p
	p.Node = c.node

	t.sendCall(c)
}

// matchWithCall checks whether a handshake attempt matches the active call.
func (t *UDPv5) matchWithCall(fromID enode.ID, nonce Nonce) (*callV5, error) {
	c := t.activeCallByAuth[nonce]
	if c == nil {
		return nil, errChallengeNoCall
	}
	if c.handshakeCount > 0 {
		return nil, errChallengeTwice
	}
	return c, nil
}
