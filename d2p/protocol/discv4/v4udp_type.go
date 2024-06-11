package discv4

import (
	"context"
	"crypto/ecdsa"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// UDPv4 implements the v4 wire protocol.
type UDPv4 struct {
	conn        UDPConn
	log         log.Logger
	priv        *ecdsa.PrivateKey
	localNode   *enode.LocalNode
	closeOnce   sync.Once
	wg          sync.WaitGroup

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

	reply v4wire.Packet
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
