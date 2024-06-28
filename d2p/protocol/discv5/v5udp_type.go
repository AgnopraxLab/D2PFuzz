package discv5

import (
	"D2PFuzz/d2p"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	lookupRequestLimit      = 3  // max requests against a single node during lookup
	findnodeResultLimit     = 16 // applies in FINDNODE handler
	totalNodesResponseLimit = 5  // applies in waitForNodes

	respTimeoutV5 = 700 * time.Millisecond
)

// codecV5 is implemented by v5wire.Codec (and testCodec).
//
// The UDPv5 transport is split into two objects: the codec object deals with
// encoding/decoding and with the handshake; the UDPv5 object handles higher-level concerns.
type codecV5 interface {
	// Encode encodes a packet.
	Encode(enode.ID, string, Packet, *Whoareyou) ([]byte, Nonce, error)

	// Decode decodes a packet. It returns a *v5wire.Unknown packet if decryption fails.
	// The *enode.Node return value is non-nil when the input contains a handshake response.
	Decode([]byte, string) (enode.ID, *enode.Node, Packet, error)
}

// UDPv5 is the implementation of protocol version 5.
type UDPv5 struct {
	// static fields
	conn         d2p.UDPConn
	priv         *ecdsa.PrivateKey
	localNode    *enode.LocalNode
	log          Logger
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
	err          chan error         // errors sent here

	// Valid for active calls only:
	nonce          Nonce      // nonce of request packet
	handshakeCount int               // # times we attempted handshake for this call
	challenge      *Whoareyou // last sent handshake challenge
	timeout        mclock.Timer
}

// callTimeout is the response timeout event of a call.
type callTimeout struct {
	c     *callV5
	timer mclock.Timer
}

// A Logger writes key/value pairs to a Handler
type Logger interface {
	// With returns a new Logger that has this logger's attributes plus the given attributes
	With(ctx ...interface{}) Logger

	// New With returns a new Logger that has this logger's attributes plus the given attributes. Identical to 'With'.
	New(ctx ...interface{}) Logger

	// Log logs a message at the specified level with context key/value pairs
	Log(level slog.Level, msg string, ctx ...interface{})

	// Trace logs a message at the trace level with context key/value pairs
	Trace(msg string, ctx ...interface{})

	// Debug logs a message at the debug level with context key/value pairs
	Debug(msg string, ctx ...interface{})

	// Info logs a message at the info level with context key/value pairs
	Info(msg string, ctx ...interface{})

	// Warn logs a message at to warn level with context key/value pairs
	Warn(msg string, ctx ...interface{})

	// Error logs a message at the error level with context key/value pairs
	Error(msg string, ctx ...interface{})

	// Crit logs a message at the crit level with context key/value pairs, and exits
	Crit(msg string, ctx ...interface{})

	// Write logs a message at the specified level
	Write(level slog.Level, msg string, attrs ...any)

	// Enabled reports whether l emits log records at the given context and level.
	Enabled(ctx context.Context, level slog.Level) bool

	// Handler returns the underlying handler of the inner logger.
	Handler() slog.Handler
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



















func (t *UDPv5) GenPacket(packetType string, count int, n *enode.Node) Packet {
	var (
		addr        = &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
		packetTypes = []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	)

	for i := 0; i < count; i++ {
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
			return t.GenPacket(randomType, 1, n)

		default:
			return nil
		}
	}
	return nil
}

func cryptoRandIntn(n int) int {
	b := make([]byte, 4)
	crand.Read(b)
	return int(binary.BigEndian.Uint32(b) % uint32(n))
}