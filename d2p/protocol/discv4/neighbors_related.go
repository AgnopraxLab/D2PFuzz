package discv4

import (
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

func (t *UDPv4) sendNeighbors(from *net.UDPAddr, fromID enode.ID, closest []*node) {
	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the packet size limit.
	p := t.makeNeighbors(closest, from.IP)
	var sent bool
	for {
		if len(p.Nodes) == 0 {
			break
		}
		if len(p.Nodes) > MaxNeighbors {
			p.Nodes = p.Nodes[:MaxNeighbors]
		}
		if _, err := t.send(from, fromID, &p); err != nil {
			log.Error("Failed to send neighbors", "err", err)
		}
		p.Nodes = p.Nodes[len(p.Nodes):]
		sent = true
	}
	if !sent {
		if _, err := t.send(from, fromID, &p); err != nil {
			log.Error("Failed to send neighbors", "err", err)
		}
	}
}

func (t *UDPv4) makeNeighbors(closest []*node, fromIP net.IP) Neighbors {
	p := Neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	for _, n := range closest {
		if netutil.CheckRelayIP(fromIP, n.IP()) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
	}
	return p
}

func nodeToRPC(n *node) Node {
	var key ecdsa.PublicKey
	var ekey Pubkey
	if err := n.Load((*enode.Secp256k1)(&key)); err == nil {
		ekey = EncodePubkey(&key)
	}
	return Node{ID: ekey, IP: n.IP(), UDP: uint16(n.UDP()), TCP: uint16(n.TCP())}
}
