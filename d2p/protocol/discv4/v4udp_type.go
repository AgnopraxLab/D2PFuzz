package discv4

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/AgnopraxLab/D2PFuzz/d2p"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
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

	done chan struct{}
}

type replyMatchFunc func(Packet) (matched bool, requestDone bool, shouldComplete bool)

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

func (t *UDPv4) Pending(id enode.ID, ip net.IP, ptype byte, callback replyMatchFunc) *replyMatcher {
	ch := make(chan error, 1)
	done := make(chan struct{})
	actualIP := getActualIP(ip)
	p := &replyMatcher{
		from:     id,
		ip:       actualIP,
		ptype:    ptype,
		callback: callback,
		errc:     ch,
		done:     done,
	}
	select {
	case t.addReplyMatcher <- p:
		// loop will handle it
	case <-t.closeCtx.Done():
		ch <- errClosed
	}
	return p
}

// 新增：获取实际使用的IP
func getActualIP(ip net.IP) net.IP {
	// 如果是本地回环地址，尝试获取实际的网络接口IP
	if ip.IsLoopback() {
		// 获取所有网络接口
		interfaces, err := net.Interfaces()
		if err != nil {
			return ip
		}
		// 查找合适的非本地IP
		for _, i := range interfaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if !ipnet.IP.IsLoopback() {
						return ipnet.IP
					}
				}
			}
		}
	}
	return ip
}

func (rm *replyMatcher) WaitForResponse(timeout time.Duration) error {
	select {
	case err := <-rm.errc:
		return err
	case <-rm.done:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout waiting for response")
	}
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

func (t *UDPv4) GetPri() *ecdsa.PrivateKey {
	return t.priv
}

func (t *UDPv4) Send(n *enode.Node, req Packet) []byte {
	toaddr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	toid := n.ID()
	packet, hash, err := Encode(t.GetPri(), req)
	if err != nil {
		panic(fmt.Errorf("can't encode %v packet: %v", req.Name(), err))
	}
	//fmt.Printf("Packet: %x\n", packet)
	//fmt.Printf("Hash: %x\n", hash)
	//fmt.Printf("Packet: %s, Hash: %x\n", req.Name(), hash)
	if err := t.write(toaddr, toid, req.Name(), packet); err != nil {
		panic(fmt.Errorf("can't send %v: %v", req.Name(), err))
	}
	return hash
}

func (t *UDPv4) GenPacket(packetType string, n *enode.Node) Packet {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		packetTypes = []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
	)

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
		req := &Findnode{Expiration: uint64(time.Now().Add(expiration).Unix())}
		rand.Read(req.Target[:])
		return req
	case "neighbors":
		// Create a custom node record
		key, _ := crypto.GenerateKey()
		// Create a new enode.Node
		ip := net.IP{127, 0, 0, 1}
		customNode := enode.NewV4(&key.PublicKey, ip, 30303, 30303)
		// Set the custom node as the closest node
		closest := []*node{wrapNode(customNode)}
		// Create a Neighbors structure
		neighbors := &Neighbors{
			Expiration: uint64(time.Now().Add(expiration).Unix()),
		}
		// Convert nodes in `closest` to the format required by the Neighbors structure
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
		return t.GenPacket(randomType, n)
	default:
		return nil
	}
}

// func (t *UDPv4) GenPacket(f *filler.Filler, packetType string, n *enode.Node) Packet {
// 	var (
// 		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
// 		packetTypes = []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
// 	)

// 	switch packetType {
// 	case "ping":
// 		return &Ping{
// 			Version:    4,
// 			From:       t.ourEndpoint(),
// 			To:         NewEndpoint(addr, 0),
// 			Expiration: f.FillExpiration(),
// 			ENRSeq:     t.localNode.Node().Seq(),
// 			Rest:       f.FillRest(), // 随机填充 Rest 字段
// 		}
// 	case "pong":
// 		return &Pong{
// 			To:         NewEndpoint(addr, 0),
// 			ReplyTok:   f.FillReplyToken(),
// 			Expiration: f.FillExpiration(),
// 			ENRSeq:     t.localNode.Node().Seq(),
// 			Rest:       f.FillRest(), // 随机填充 Rest 字段
// 		}
// 	case "findnode":
// 		req := &Findnode{
// 			Target:     Pubkey(f.FillPubkey()), // 使用随机生成的 Pubkey
// 			Expiration: f.FillExpiration(),
// 			Rest:       f.FillRest(), // 随机填充 Rest 字段
// 		}
// 		return req
// 	case "neighbors":
// 		// 创建一个自定义的节点记录
// 		key, _ := crypto.GenerateKey()
// 		ip := f.FillIP() // 随机生成 IP 地址
// 		customNode := enode.NewV4(&key.PublicKey, ip, 30303, 30303)
// 		closest := []*node{wrapNode(customNode)}
// 		neighbors := &Neighbors{
// 			Expiration: f.FillExpiration(),
// 			Rest:       f.FillRest(), // 随机填充 Rest 字段
// 		}
// 		for _, n := range closest {
// 			neighbors.Nodes = append(neighbors.Nodes, nodeToRPC(n))
// 		}
// 		return neighbors
// 	case "ENRRequest":
// 		return &ENRRequest{
// 			Expiration: f.FillExpiration(),
// 			Rest:       f.FillRest(), // 随机填充 Rest 字段
// 		}
// 	case "ENRResponse":
// 		return &ENRResponse{
// 			ReplyTok: f.FillReplyToken(), // 随机生成的回复令牌
// 			Record:   *t.localNode.Node().Record(),
// 			Rest:     f.FillRest(), // 随机填充 Rest 字段
// 		}
// 	case "random":
// 		randomType := packetTypes[rand.Intn(len(packetTypes))]
// 		return t.GenPacket(f, randomType, n)
// 	default:
// 		return nil
// 	}
// }

//func (t *UDPv4) CreateSeed(node *enode.Node) (*V4Seed, error) {
//	var packets []Packet
//
//	// 生成各种类型的Packet并添加到packets切片中
//	packetTypes := []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
//
//	for _, pType := range packetTypes {
//		packet := t.GenPacket(pType, node)
//		if packet != nil {
//			packets = append(packets, packet)
//		}
//	}
//	seedID := fmt.Sprintf("%d", time.Now().Unix())
//	seed := &V4Seed{
//		ID:        seedID,
//		Packets:   packets,
//		Priority:  1,
//		Mutations: 0,
//		Series:    make([]*StateSeries, 0),
//	}
//
//	return seed, nil
//}

func (t *UDPv4) SelectSeed(seedQueue []*V4Seed) *V4Seed {
	var selectedSeed *V4Seed
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

//func (t *UDPv4) RunPacketTest(seed *V4Seed, node *enode.Node, mut *fuzzing.Mutator) (*V4Seed, error) {
//	for {
//		// 初始化一个 series
//		var series []*StateSeries
//		for _, req := range seed.Packets {
//			res := t.Send(node, req)
//			// 将结果 req.Name():res 保存到 series
//			series = append(series, &StateSeries{
//				Type: req.Name(),
//				Hash: res,
//			})
//		}
//		// 比较 seed.Series 与 series 中的每一项，如果有任何地方不同 则将 seed.Series 更新为 series 并返回 seed
//		if !compareSeries(seed.Series, series) {
//			seed.Series = series // 如果不同，则更新 seed.Series
//			seed.ID = fmt.Sprintf("%d", time.Now().Unix())
//			return seed, nil
//		}
//		// 对 seed 的 packet 进行变异操作
//		t.seedMutate(seed, mut)
//	}
//}

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

//func (t *UDPv4) seedMutate(seed *V4Seed, mut *fuzzing.Mutator) {
//	seed.Mutations++
//	//需要补充
//	if seed.Mutations < 100 {
//		seed.PacketMutate(seed.Packets, mut)
//	} else if seed.Mutations < 200 {
//		seed.SeriesMutate(seed.Packets, mut)
//	} else {
//		seed.HavocMutate(seed.Packets, mut)
//	}
//}

type V4Seed struct {
	ID        string         `json:"id"`        // 种子的唯一标识符
	Packets   []Packet       `json:"packets"`   // 用于变异的Packet切片
	Priority  int            `json:"priority"`  // 种子的优先级
	Mutations int            `json:"mutations"` // 该种子已经经过的变异次数
	Series    []*StateSeries `json:"series"`
}

type StateSeries struct {
	Type  string
	Hash  []byte
	State int
}
