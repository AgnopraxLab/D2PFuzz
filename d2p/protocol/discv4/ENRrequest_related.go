package discv4

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

func (t *UDPv4) sendENRRequest(n *enode.Node) (*enode.Node, error) {
	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	t.ensureBond(n.ID(), addr)

	req := t.makeENRRequest()
	packet, hash, err := Encode(t.priv, req)
	if err != nil {
		return nil, err
	}

	// Add a matcher for the reply to the pending reply queue. Responses are matched if
	// they reference the request we're about to send.
	rm := t.pending(n.ID(), addr.IP, ENRResponsePacket, func(r Packet) (matched bool, requestDone bool, shouldComplete bool) {
		matched = bytes.Equal(r.(*ENRResponse).ReplyTok, hash)
		return matched, matched, matched
	})
	// Send the packet and wait for the reply.
	if err := t.write(addr, n.ID(), req.Name(), packet); err != nil {
		return nil, err
	}
	if err := <-rm.errc; err != nil {
		return nil, err
	}
	// Verify the response record.
	respN, err := enode.New(enode.ValidSchemes, &rm.reply.(*ENRResponse).Record)
	if err != nil {
		return nil, err
	}
	if respN.ID() != n.ID() {
		return nil, errors.New("invalid ID in response record")
	}
	if respN.Seq() < n.Seq() {
		return n, nil // response record is older
	}
	if err := netutil.CheckRelayIP(addr.IP, respN.IP()); err != nil {
		return nil, fmt.Errorf("invalid IP in response record: %v", err)
	}
	return respN, nil
}

func (t *UDPv4) makeENRRequest() *ENRRequest {
	return &ENRRequest{
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
}
