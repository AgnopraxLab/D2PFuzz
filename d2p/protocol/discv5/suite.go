package discv5

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"log"
	"math/rand"
	"net"
	"os"
)

// Errors
var (
	errUnknowPacketType = errors.New("unknow packet type")
)

type Suite struct {
	DestList []*enode.Node
	conn     *Conn
}

type Conn struct {
	localNode *enode.LocalNode
	localKey  *ecdsa.PrivateKey
	listeners []net.PacketConn

	clock     mclock.Clock
	log       *log.Logger
	codec     *v5wire.Codec
	idCounter uint32
}

func NewSuite(dest []*enode.Node) (*Suite, error) {
	conn := newConn(nil)
	return &Suite{
		DestList: dest,
		conn:     conn,
	}, nil
}

func newConn(logger *log.Logger) *Conn {
	if logger == nil {
		logger = log.New(os.Stdout, "LOG: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	db, err := enode.OpenDB("")
	if err != nil {
		panic(err)
	}
	ln := enode.NewLocalNode(db, key)

	return &Conn{
		localKey:  key,
		localNode: ln,
		codec:     v5wire.NewCodec(ln, key, mclock.System{}, nil),
		log:       logger,
		clock:     mclock.System{},
	}
}

func (s *Suite) GenPacket(packetType string, n *enode.Node) (Packet, error) {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		packetTypes = []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	)

	switch packetType {
	case "ping":
		pingPacket := &Ping{
			ENRSeq: s.conn.localNode.Seq(),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		pingPacket.SetRequestID(reqID)
		return pingPacket, nil
	case "pong":
		pongPacket := &Pong{
			ENRSeq: s.conn.localNode.Seq(),
			ToIP:   addr.IP,
			ToPort: uint16(addr.Port),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		pongPacket.SetRequestID(reqID)
		return pongPacket, nil
	case "findnode":
		findnodePacket := &Findnode{
			Distances: []uint{256, 255, 254}, // 示例距离
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		findnodePacket.SetRequestID(reqID)
		return findnodePacket, nil
	case "nodes":
		key, _ := crypto.GenerateKey()
		var r enr.Record
		r.Set(enr.IP(net.IP{127, 0, 0, 1}))
		r.Set(enr.UDP(30303))
		r.Set(enr.TCP(30303))
		r.Set(enode.Secp256k1(key.PublicKey))
		r.SetSeq(1)
		enode.SignV4(&r, key)
		var records []*enr.Record
		for i := 0; i < 3; i++ {
			records = append(records, &r)
		}
		nodesPacket := &Nodes{
			RespCount: uint8(len(records)),
			Nodes:     records,
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		nodesPacket.SetRequestID(reqID)
		return nodesPacket, nil
	case "talkrequest":
		talkReqPacket := &TalkRequest{
			Protocol: "example-protocol",
			Message:  []byte("Hello, world!"),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		talkReqPacket.SetRequestID(reqID)
		return talkReqPacket, nil
	case "talkresponse":
		talkRespPacket := &TalkResponse{
			Message: []byte("Response received"),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		talkRespPacket.SetRequestID(reqID)
		return talkRespPacket, nil
	case "whoareyou":
		whoareyouPacket := &Whoareyou{
			ChallengeData: make([]byte, 32),
			RecordSeq:     s.conn.localNode.Seq(),
			Node:          s.conn.localNode.Node(),
		}
		crand.Read(whoareyouPacket.IDNonce[:])
		crand.Read(whoareyouPacket.Nonce[:])
		whoareyouPacket.sent = s.conn.clock.Now()
		return whoareyouPacket, nil
	case "unknown":
		unknownPacket := &Unknown{
			Nonce: Nonce{}, // 创建一个空的 Nonce
		}
		crand.Read(unknownPacket.Nonce[:])
		return unknownPacket, nil
	case "random":
		randomType := packetTypes[rand.Intn(len(packetTypes))]
		return s.GenPacket(randomType, n)
	default:
		return nil, errUnknowPacketType
	}
}

func (s *Suite) EncodePacket(id enode.ID, addr string, packet Packet, challenge *v5wire.Whoareyou) ([]byte, v5wire.Nonce, error) {
	return s.conn.codec.Encode(id, addr, packet, challenge)
}
