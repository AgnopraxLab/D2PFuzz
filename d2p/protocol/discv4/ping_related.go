package discv4

import (
	"bytes"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

func (t *UDPv4) sendPing(n *enode.Node, callback func()) (seq uint64, err error) {
	toid := n.ID()
	toaddr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}

	req := t.makePing(toaddr)
	packet, hash, err := Encode(t.priv, req)
	if err != nil {
		return 0, err
	}

	rm := t.pending(toid, toaddr.IP, PongPacket, func(p Packet) (matched bool, requestDone bool, shouldComplete bool) {
		matched = bytes.Equal(p.(*Pong).ReplyTok, hash)
		if matched && callback != nil {
			callback()
		}
		return matched, matched, matched
	})

	err = t.write(toaddr, toid, req.Name(), packet)
	if err != nil {
		return 0, err
	}

	if err = <-rm.errc; err == nil {
		seq = rm.reply.(*Pong).ENRSeq
	}
	return seq, err
}

func (t *UDPv4) makePing(toaddr *net.UDPAddr) *Ping {
	return &Ping{
		Version:    4,
		From:       t.ourEndpoint(),
		To:         NewEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	}
}
