package discv5

import (
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
)

func (t *UDPv5) makePing(toaddr *net.UDPAddr) *Ping {
	return &Ping{
		ENRSeq:     t.localNode.Node().Seq(),
		// 添加其他必要的字段,如 Version, From, To 等
	}
}

func (t *UDPv5) sendPing(n *enode.Node, callback func()) (uint64, error) {
	toaddr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	req := t.makePing(toaddr)

	resp := t.callToNode(n, PongMsg, req)
	defer t.callDone(resp)

	var seq uint64
	select {
	case pong := <-resp.ch:
		seq = pong.(*Pong).ENRSeq
		if callback != nil {
			callback()
		}
	case err := <-resp.err:
		return 0, err
	}

	return seq, nil
}

// handlePing sends a PONG response.
func (t *UDPv5) handlePing(p *Ping, fromID enode.ID, fromAddr *net.UDPAddr) {
	remoteIP := fromAddr.IP
	// Handle IPv4 mapped IPv6 addresses in the
	// event the local node is bound to an
	// ipv6 interface.
	if remoteIP.To4() != nil {
		remoteIP = remoteIP.To4()
	}
	t.sendResponse(fromID, fromAddr, &Pong{
		ReqID:  p.ReqID,
		ToIP:   remoteIP,
		ToPort: uint16(fromAddr.Port),
		ENRSeq: t.localNode.Node().Seq(),
	})
}