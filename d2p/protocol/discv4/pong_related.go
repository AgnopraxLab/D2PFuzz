package discv4

import (
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
	"time"
)

func (t *UDPv4) sendPong(toid enode.ID, toaddr *net.UDPAddr, req *Ping, mac []byte) error {
	pong := t.makePong(toaddr, req, mac)
	_, err := t.send(toaddr, toid, pong)
	return err
}

func (t *UDPv4) makePong(toaddr *net.UDPAddr, req *Ping, mac []byte) *Pong {
	return &Pong{
		To:         NewEndpoint(toaddr, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	}
}

