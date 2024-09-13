package discv5

import (
	"crypto/ecdsa"
	"crypto/rand"
	"net"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

func (t *UDPv5) makeNodes(count int) *Nodes {
	var records []*enr.Record
	for i := 0; i < count; i++ {
		key, _ := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		var r enr.Record
		r.Set(enr.IP(net.IP{127, 0, 0, 1}))
		r.Set(enr.UDP(30303))
		r.Set(enr.TCP(30303))
		r.Set(enode.Secp256k1(key.PublicKey))
		r.SetSeq(1)
		enode.SignV4(&r, key)
		records = append(records, &r)
	}

	nodesPacket := &Nodes{
		RespCount: uint8(len(records)),
		Nodes:     records,
	}
	reqID := make([]byte, 8)
	rand.Read(reqID)
	nodesPacket.SetRequestID(reqID)
	return nodesPacket
}

func (t *UDPv5) sendNodes(toID enode.ID, toAddr *net.UDPAddr, count int) error {
	nodes := t.makeNodes(count)
	return t.sendResponse(toID, toAddr, nodes)
}
