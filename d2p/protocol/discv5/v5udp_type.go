package discv5

import (
	"D2PFuzz/d2p"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
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

func (t *UDPv5) Send(n *enode.Node, p Packet, challenge *Whoareyou) (Nonce, error) {
	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	t.logcontext = append(t.logcontext[:0], "id", n.ID(), "addr", addr)
	t.logcontext = p.AppendLogInfo(t.logcontext)

	enc, nonce, err := t.codec.Encode(n.ID(), addr.String(), p, challenge)
	if err != nil {
		t.logcontext = append(t.logcontext, "err", err)
		t.log.Warn(">> "+p.Name(), t.logcontext...)
		return nonce, err
	}
	// print test
	fmt.Printf("EncodePacket Output:\n")
	fmt.Printf("packet: %x\n", enc)
	fmt.Printf("nonce: %x\n", nonce)

	_, err = t.conn.WriteToUDP(enc, addr)
	t.log.Trace(">> "+p.Name(), t.logcontext...)
	return nonce, err
}

func (t *UDPv5) GenPacket(packetType string, n *enode.Node) Packet {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		packetTypes = []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	)

	switch packetType {
	case "ping":
		pingPacket := &Ping{
			//ENRSeq: t.localNode.Node().Seq(),
			ReqID:  []byte("reqid"), // 使用固定的 ReqID 用于测试
			ENRSeq: 5,
		}
		return pingPacket
	/*case "ping":
	pingPacket := &Ping{
		ENRSeq: t.localNode.Seq(),
	}
	reqID := make([]byte, 8)
	crand.Read(reqID)
	pingPacket.SetRequestID(reqID)
	return pingPacket*/

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
	case "whoareyou":
		whoareyouPacket := &Whoareyou{
			ChallengeData: make([]byte, 32),
			RecordSeq:     t.localNode.Seq(),
			Node:          t.localNode.Node(),
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
}

func cryptoRandIntn(n int) int {
	b := make([]byte, 4)
	crand.Read(b)
	return int(binary.BigEndian.Uint32(b) % uint32(n))
}

func (t *UDPv5) CreateSeed(node *enode.Node) (*V5Seed, error) {
	var packets []Packet

	// 生成各种类型的Packet并添加到packets切片中
	packetTypes := []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}

	for _, pType := range packetTypes {
		packet := t.GenPacket(pType, node)
		if packet != nil {
			packets = append(packets, packet)
		}
	}
	seedID := fmt.Sprintf("%d", time.Now().Unix())
	seed := &V5Seed{
		ID:        seedID,
		Packets:   packets,
		Priority:  1,
		Mutations: 0,
		Series:    make([]*StateSeries, 0),
	}

	return seed, nil
}

func (t *UDPv5) RunPacketTest(seed *V5Seed, node *enode.Node) (*V5Seed, error) {
	for {
		// 初始化一个 series
		var series []*StateSeries
		for _, req := range seed.Packets {
			nonce, _ := t.Send(node, req, nil)
			// 将结果 req.Name():res 保存到 series
			series = append(series, &StateSeries{
				Type:  req.Name(),
				Nonce: nonce,
			})
		}
		// 比较 seed.Series 与 series 中的每一项，如果有任何地方不同 则将 seed.Series 更新为 series 并返回 seed
		if !compareSeries(seed.Series, series) {
			seed.Series = series // 如果不同，则更新 seed.Series
			seed.ID = fmt.Sprintf("%d", time.Now().Unix())
			return seed, nil
		}
		// 对 seed 的 packet 进行变异操作
		t.seedMutate(seed)
	}
}

func (t *UDPv5) SelectSeed(seedQueue []*V5Seed) *V5Seed {
	var selectedSeed *V5Seed
	maxPriority := 0

	// 遍历种子队列，找到优先级最低的种子
	for _, seed := range seedQueue {
		if seed.Priority > maxPriority {
			maxPriority = seed.Priority
			selectedSeed = seed
		}
	}
	selectedSeed.Priority -= 1
	for _, seed := range seedQueue {
		if seed != selectedSeed {
			seed.Priority++
		}
	}
	return selectedSeed
}

func (t *UDPv5) seedMutate(seed *V5Seed) {
	seed.Mutations++
	//需要补充
	if seed.Mutations < 100 {
		seed.PacketMutate(seed.Packets)
	} else if seed.Mutations < 200 {
		seed.SeriesMutate(seed.Packets)
	} else {
		seed.HavocMutate(seed.Packets)
	}
}

func compareSeries(s1, s2 []*StateSeries) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i, item1 := range s1 {
		item2 := s2[i]
		if item1.Type != item2.Type {
			return false
		}
	}
	return true
}

type V5Seed struct {
	ID        string         `json:"id"`        // 种子的唯一标识符
	Packets   []Packet       `json:"packets"`   // 用于变异的Packet切片
	Priority  int            `json:"priority"`  // 种子的优先级
	Mutations int            `json:"mutations"` // 该种子已经经过的变异次数
	Series    []*StateSeries `json:"series"`
}

type StateSeries struct {
	Type  string
	Nonce Nonce
	State int
}
