package discv4

import (
	"errors"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

func (t *UDPv4) sendFindnode(toid enode.ID, toaddr *net.UDPAddr, target Pubkey) ([]*node, error) {
	t.ensureBond(toid, toaddr)

	req := t.makeFindnode(target)

	// Add a matcher for 'neighbours' replies to the pending reply queue. The matcher is
	// active until enough nodes have been received.
	nodes := make([]*node, 0, 16)
	nreceived := 0
	rm := t.pending(toid, toaddr.IP, NeighborsPacket, func(r Packet) (matched bool, requestDone bool) {
		reply := r.(*Neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				t.log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		return true, nreceived >= 16
	})
	_, err := t.send(toaddr, toid, req)
	if err != nil {
		return nil, err
	}

	// Ensure that callers don't see a timeout if the node actually responded. Since
	// findnode can receive more than one neighbors response, the reply matcher will be
	// active until the remote node sends enough nodes. If the remote end doesn't have
	// enough nodes the reply matcher will time out waiting for the second reply, but
	// there's no need for an error in that case.
	err = <-rm.errc
	if errors.Is(err, errTimeout) && rm.reply != nil {
		err = nil
	}
	return nodes, err
}

func (t *UDPv4) makeFindnode(target Pubkey) *Findnode {
	return &Findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
}

func (t *UDPv4) nodeFromRPC(sender *net.UDPAddr, rn Node) (*node, error) {
	if rn.UDP <= 1024 {
		return nil, errLowPort
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	key, err := DecodePubkey(crypto.S256(), rn.ID)
	if err != nil {
		return nil, err
	}
	n := wrapNode(enode.NewV4(key, rn.IP, int(rn.TCP), int(rn.UDP)))
	err = n.Record().Load(enr.WithEntry("ip", new(enr.IPv4)))
	if err != nil {
		return nil, err
	}

	return n, nil
}

func wrapNode(n *enode.Node) *node {
	return &node{Node: *n}
}
