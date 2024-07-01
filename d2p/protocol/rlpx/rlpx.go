package rlpx

import (
	"D2PFuzz/d2p/protocol/discv4"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"math/rand"
	"net"
	"time"
)

var (
	timeout = 2 * time.Second
)

func NewConn(conn net.Conn, dialDest *ecdsa.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

func (c Conn) GenPacket(packetType string) discv4.Packet {
	var msg discv4.Packet
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(17)

	switch code {
	case eth.StatusMsg:
		msg = new(eth.StatusPacket)
	case eth.GetBlockHeadersMsg:
		msg = new(eth.GetBlockHeadersPacket)
	case eth.BlockHeadersMsg:
		msg = new(eth.BlockHeadersPacket)
	case eth.GetBlockBodiesMsg:
		msg = new(eth.GetBlockBodiesPacket)
	case eth.BlockBodiesMsg:
		msg = new(eth.BlockBodiesPacket)
	case eth.NewBlockMsg:
		msg = new(eth.NewBlockPacket)
	case eth.NewBlockHashesMsg:
		msg = new(eth.NewBlockHashesPacket)
	case eth.TransactionsMsg:
		msg = new(eth.TransactionsPacket)
	case eth.NewPooledTransactionHashesMsg:
		msg = new(eth.NewPooledTransactionHashesPacket)
	case eth.GetPooledTransactionsMsg:
		msg = new(eth.GetPooledTransactionsPacket)
	case eth.PooledTransactionsMsg:
		msg = new(eth.PooledTransactionsPacket)
	default:
		panic(fmt.Sprintf("unhandled eth msg code %d", code))
	}

	return msg
}
