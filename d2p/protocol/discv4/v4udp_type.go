package discv4

import (
	"D2PFuzz/d2p"
	"D2PFuzz/fuzzing"
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// UDPv4 implements the v4 wire protocol.
type UDPv4 struct {
	conn      d2p.UDPConn
	log       log.Logger
	priv      *ecdsa.PrivateKey
	localNode *enode.LocalNode
	closeOnce sync.Once
	wg        sync.WaitGroup

	addReplyMatcher chan *replyMatcher
	gotreply        chan reply
	closeCtx        context.Context
	cancelCloseCtx  context.CancelFunc
}

// replyMatcher represents a pending reply.
//
// Some implementations of the protocol wish to send more than one
// reply packet to findnode. In general, any neighbors' packet cannot
// be matched up with a specific findnode packet.
//
// Our implementation handles this by storing a callback function for
// each pending reply. Incoming packets from a node are dispatched
// to all callback functions for that node.
type replyMatcher struct {
	// these fields must match in the reply.
	from  enode.ID
	ip    net.IP
	ptype byte

	deadline time.Time

	callback replyMatchFunc

	errc chan error

	reply Packet
}

type replyMatchFunc func(Packet) (matched bool, requestDone bool)

// reply is a reply packet from a certain node.
type reply struct {
	from enode.ID
	ip   net.IP
	data Packet

	matched chan<- bool
}

func (t *UDPv4) Self() *enode.Node {
	return t.localNode.Node()
}

func (t *UDPv4) ourEndpoint() Endpoint {
	n := t.Self()
	a := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	return Endpoint{IP: a.IP, UDP: uint16(a.Port), TCP: uint16(n.TCP())}
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

type node struct {
	enode.Node
	addedAt        time.Time // time when the node was added to the table
	livenessChecks uint      // how often liveness was checked
}

// packetHandlerV4 wraps a packet with handler functions.
type packetHandlerV4 struct {
	Packet
	senderKey *ecdsa.PublicKey // used for ping

	// preverify checks whether the packet is valid and should be handled at all.
	preverify func(p *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, fromKey Pubkey) error
	// handle the packet.
	handle func(req *packetHandlerV4, from *net.UDPAddr, fromID enode.ID, mac []byte)
}

// Secp256k1 is the "secp256k1" key, which holds a public key.
type Secp256k1 ecdsa.PublicKey

func (v Secp256k1) ENRKey() string { return "secp256k1" }

// EncodeRLP implements rlp.Encoder.
func (v Secp256k1) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v)))
}

// DecodeRLP implements rlp.Decoder.
func (v *Secp256k1) DecodeRLP(s *rlp.Stream) error {
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	pk, err := crypto.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	*v = (Secp256k1)(*pk)
	return nil
}

func (t *UDPv4) GenPacket(packetType string, count int, n *enode.Node) Packet {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		target      = fuzzing.RandHex(64)
		pubkey      Pubkey
		packetTypes = []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
	)
	copy(pubkey[:], target)

	for i := 0; i < count; i++ {
		switch packetType {
		case "ping":
			return &Ping{
				Version:    4,
				From:       t.ourEndpoint(),
				To:         NewEndpoint(addr, 0),
				Expiration: uint64(time.Now().Add(expiration).Unix()),
				ENRSeq:     t.localNode.Node().Seq(),
			}
		//case "ping":
		//	return t.makePing(addr)
		case "pong":
			return &Pong{
				To:         NewEndpoint(addr, 0),
				ReplyTok:   []byte(fuzzing.RandHex(64)),
				Expiration: uint64(time.Now().Add(expiration).Unix()),
				ENRSeq:     t.localNode.Node().Seq(),
			}
		case "findnode":
			return &Findnode{
				Target:     pubkey,
				Expiration: uint64(time.Now().Add(expiration).Unix()),
			}
		case "neighbors":
			// 创建一个自定义的节点记录
			key, _ := crypto.GenerateKey()
			var r enr.Record
			r.Set(enr.IP(net.IP{127, 0, 0, 1}))
			r.Set(enr.UDP(30303))
			r.Set(enr.TCP(30303))
			r.Set(Secp256k1(key.PublicKey))

			// 使用节点记录创建一个新的 enode.Node 对象
			customNode, _ := enode.New(enode.ValidSchemes, &r)

			// 将自定义节点作为最接近的节点
			closest := []*node{wrapNode(customNode)}

			// 创建 Neighbors 结构
			neighbors := &Neighbors{
				Expiration: uint64(time.Now().Add(expiration).Unix()),
			}

			// 将 closest 中的节点转换为 Neighbors 结构中的格式
			for _, n := range closest {
				neighbors.Nodes = append(neighbors.Nodes, nodeToRPC(n))
			}

			return neighbors
		case "ENRRequest":
			return &ENRRequest{
				Expiration: uint64(time.Now().Add(expiration).Unix()),
			}
		case "ENRResponse":
			return &ENRResponse{
				ReplyTok: []byte(fuzzing.RandHex(64)),
				Record:   *t.localNode.Node().Record(),
			}
		case "random":
			randomType := packetTypes[rand.Intn(len(packetTypes))]
			switch randomType {
			case "ping":
				return &Ping{
					Version:    4,
					From:       t.ourEndpoint(),
					To:         NewEndpoint(addr, 0),
					Expiration: uint64(time.Now().Add(expiration).Unix()),
					ENRSeq:     t.localNode.Node().Seq(),
				}
			case "pong":
				return &Pong{
					To:         NewEndpoint(addr, 0),
					ReplyTok:   []byte(fuzzing.RandHex(64)),
					Expiration: uint64(time.Now().Add(expiration).Unix()),
					ENRSeq:     t.localNode.Node().Seq(),
				}
			case "findnode":
				return &Findnode{
					Target:     pubkey,
					Expiration: uint64(time.Now().Add(expiration).Unix()),
				}
			case "neighbors":
				// 创建一个自定义的节点记录
				key, _ := crypto.GenerateKey()
				var r enr.Record
				r.Set(enr.IP(net.IP{127, 0, 0, 1}))
				r.Set(enr.UDP(30303))
				r.Set(enr.TCP(30303))
				r.Set(Secp256k1(key.PublicKey))

				// 使用节点记录创建一个新的 enode.Node 对象
				customNode, _ := enode.New(enode.ValidSchemes, &r)

				// 将自定义节点作为最接近的节点
				closest := []*node{wrapNode(customNode)}

				// 创建 Neighbors 结构
				neighbors := &Neighbors{
					Expiration: uint64(time.Now().Add(expiration).Unix()),
				}

				// 将 closest 中的节点转换为 Neighbors 结构中的格式
				for _, n := range closest {
					neighbors.Nodes = append(neighbors.Nodes, nodeToRPC(n))
				}

				return neighbors
			case "ENRRequest":
				return &ENRRequest{
					Expiration: uint64(time.Now().Add(expiration).Unix()),
				}
			case "ENRResponse":
				return &ENRResponse{
					ReplyTok: []byte(fuzzing.RandHex(64)),
					Record:   *t.localNode.Node().Record(),
				}
			}
		default:
			return nil
		}
	}
	return nil
}
