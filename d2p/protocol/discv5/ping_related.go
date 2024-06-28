package discv5

import (
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Ping sends a ping message to the given node.
func (t *UDPv5) Ping(n *enode.Node) error {
	_, err := t.ping(n)
	return err
}

// ping calls PING on a node and waits for a PONG response.
func (t *UDPv5) ping(n *enode.Node) (uint64, error) {
	req := &Ping{ENRSeq: t.localNode.Node().Seq()}
	resp := t.callToNode(n, PongMsg, req)
	defer t.callDone(resp)

	select {
	case pong := <-resp.ch:
		return pong.(*v5wire.Pong).ENRSeq, nil
	case err := <-resp.err:
		return 0, err
	}
}