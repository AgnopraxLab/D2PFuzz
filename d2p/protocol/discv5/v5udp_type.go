package discv5

import (
	"D2PFuzz/d2p"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"net"
	"sync"
	"time"
)

const (
	findnodeResultLimit = 16 // applies in FINDNODE handler
	respTimeoutV5       = 700 * time.Millisecond
)

// codecV5 is implemented by wire.Codec (and testCodec).
//
// The UDPv5 transport is split into two objects: the codec object deals with
// encoding/decoding and with the handshake; the UDPv5 object handles higher-level concerns.
type codecV5 interface {
	// Encode encodes a packet.
	Encode(enode.ID, string, Packet, *Whoareyou) ([]byte, Nonce, error)

	// Decode decodes a packet. It returns a *wire.Unknown packet if decryption fails.
	// The *enode.Node return value is non-nil when the input contains a handshake response.
	Decode([]byte, string) (enode.ID, *enode.Node, Packet, error)
}

// UDPv5 is the implementation of protocol version 5.
type UDPv5 struct {
	// static fields
	conn         d2p.UDPConn
	priv         *ecdsa.PrivateKey
	localNode    *enode.LocalNode
	log          log.Logger
	clock        mclock.Clock
	validSchemes enr.IdentityScheme

	// misc buffers used during message handling
	logcontext []interface{}

	// talkreq handler registry
	talk *talkSystem

	// channels into dispatch
	packetInCh    chan d2p.ReadPacket
	readNextCh    chan struct{}
	callCh        chan *callV5
	callDoneCh    chan *callV5
	respTimeoutCh chan *callTimeout
	sendCh        chan sendRequest
	unhandled     chan<- d2p.ReadPacket

	// state of dispatch
	codec            codecV5
	activeCallByNode map[enode.ID]*callV5
	activeCallByAuth map[Nonce]*callV5
	callQueue        map[enode.ID][]*callV5

	// shutdown stuff
	closeOnce      sync.Once
	closeCtx       context.Context
	cancelCloseCtx context.CancelFunc
	wg             sync.WaitGroup
}

type sendRequest struct {
	destID   enode.ID
	destAddr *net.UDPAddr
	msg      Packet
}

// callV5 represents a remote procedure call against another node.
type callV5 struct {
	id   enode.ID
	addr *net.UDPAddr
	node *enode.Node // This is required to perform handshakes.

	packet       Packet
	responseType byte // expected packet type of response
	reqid        []byte
	ch           chan Packet // responses sent here
	err          chan error  // errors sent here

	// Valid for active calls only:
	nonce          Nonce      // nonce of request packet
	handshakeCount int        // # times we attempted handshake for this call
	challenge      *Whoareyou // last sent handshake challenge
	timeout        mclock.Timer
}

// callTimeout is the response timeout event of a call.
type callTimeout struct {
	c     *callV5
	timer mclock.Timer
}

// Self returns the local node record.
func (t *UDPv5) Self() *enode.Node {
	return t.localNode.Node()
}

// LocalNode returns the current local node running the
// protocol.
func (t *UDPv5) LocalNode() *enode.LocalNode {
	return t.localNode
}

func (t *UDPv5) GenPacket(packetType string, n *enode.Node) Packet {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		packetTypes = []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	)

	switch packetType {
	case "ping":
		pingPacket := &Ping{
			ENRSeq: t.localNode.Seq(),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		pingPacket.SetRequestID(reqID)
		return pingPacket

	case "pong":
		pongPacket := &Pong{
			ENRSeq: t.localNode.Seq(),
			ToIP:   addr.IP,
			ToPort: uint16(addr.Port),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		pongPacket.SetRequestID(reqID)
		return pongPacket

	case "findnode":
		findnodePacket := &Findnode{
			Distances: []uint{256, 255, 254}, // 示例距离
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		findnodePacket.SetRequestID(reqID)
		return findnodePacket

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
		return nodesPacket

	case "talkrequest":
		talkReqPacket := &TalkRequest{
			Protocol: "example-protocol",
			Message:  []byte("Hello, world!"),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		talkReqPacket.SetRequestID(reqID)
		return talkReqPacket

	case "talkresponse":
		talkRespPacket := &TalkResponse{
			Message: []byte("Response received"),
		}
		reqID := make([]byte, 8)
		crand.Read(reqID)
		talkRespPacket.SetRequestID(reqID)
		return talkRespPacket
	/*case "whoareyou":
	whoareyouPacket := &Whoareyou{
		ChallengeData: make([]byte, 32),
		RecordSeq:     1721275104493,
		Node:          t.localNode.Node(),
	}
	crand.Read(whoareyouPacket.IDNonce[:])
	crand.Read(whoareyouPacket.Nonce[:])
	whoareyouPacket.sent = t.clock.Now()
	return whoareyouPacket*/
	case "whoareyou":
		// 创建一个新的 enr.Record
		r := enr.Record{}
		r.Set(enr.UDP(30303))   // 设置 UDP 端口
		r.SetSeq(1721275398453) // 设置序列号

		// 创建一个新的 enode.Node
		id := enode.HexID("6516a94edcc63ec65b32ab7ea215e45fdce8ded08dccc8878c9d1642fd3eba85")
		remoteNode := enode.SignNull(&r, id)

		whoareyouPacket := &Whoareyou{
			ChallengeData: make([]byte, 32),
			RecordSeq:     1721275398453, // 使用打印出的 RecordSeq
			Node:          remoteNode,    // 使用新创建的 Node
		}
		crand.Read(whoareyouPacket.IDNonce[:])
		crand.Read(whoareyouPacket.Nonce[:])
		whoareyouPacket.sent = t.clock.Now()
		return whoareyouPacket
	case "unknown":
		unknownPacket := &Unknown{
			Nonce: Nonce{}, // 创建一个空的 Nonce
		}
		crand.Read(unknownPacket.Nonce[:])
		return unknownPacket
	case "random":
		randomIndex := cryptoRandIntn(len(packetTypes))
		randomType := packetTypes[randomIndex]
		return t.GenPacket(randomType, n)
	default:
		return nil
	}
	return nil
}

func cryptoRandIntn(n int) int {
	b := make([]byte, 4)
	crand.Read(b)
	return int(binary.BigEndian.Uint32(b) % uint32(n))
}

func (t *UDPv5) EncodePacket(id enode.ID, addr string, packet Packet, challenge *Whoareyou) ([]byte, Nonce, error) {
	return t.codec.Encode(id, addr, packet, challenge)
}

func (t *UDPv5) DecodePacket(input []byte, fromAddr string) (enode.ID, *enode.Node, v5wire.Packet, error) {
	return t.codec.Decode(input, fromAddr)
}
