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

	rm := t.pending(toid, toaddr.IP, PongPacket, func(p Packet) (matched bool, requestDone bool) {
		matched = bytes.Equal(p.(*Pong).ReplyTok, hash)
		if matched && callback != nil {
			callback()
		}
		return matched, matched
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

func (t *UDPv4) pending(id enode.ID, ip net.IP, ptype byte, callback replyMatchFunc) *replyMatcher {
	ch := make(chan error, 1)
	p := &replyMatcher{from: id, ip: ip, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addReplyMatcher <- p:
		// loop will handle it
	case <-t.closeCtx.Done():
		ch <- errClosed
	}
	return p
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