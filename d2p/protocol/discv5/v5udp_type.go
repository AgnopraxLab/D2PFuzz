package discv5

import (
	"D2PFuzz/d2p"
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common/mclock"
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