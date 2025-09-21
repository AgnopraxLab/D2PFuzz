// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	pretty = spew.ConfigState{
		Indent:                  "  ",
		DisableCapacities:       true,
		DisablePointerAddresses: true,
		SortKeys:                true,
	}
	timeout = 2 * time.Second
)

// dial attempts to dial the given node and perform a handshake, returning the
// created Conn if successful.
func (s *Suite) dial() (*Conn, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %v", err)
	}
	return s.dialAs(key)
}

func (s *Suite) Dial() (*Conn, error) {
	return s.dial()
}

// dialAs attempts to dial a given node and perform a handshake using the given
// private key.
// func (s *Suite) dialAs(key *ecdsa.PrivateKey) (*Conn, error) {
// 	tcpEndpoint, _ := s.Dest.TCPEndpoint()
// 	fd, err := net.Dial("tcp", tcpEndpoint.String())
// 	if err != nil {
// 		return nil, err
// 	}
// 	conn := Conn{Conn: rlpx.NewConn(fd, s.Dest.Pubkey())}
// 	conn.ourKey = key
// 	_, err = conn.Handshake(conn.ourKey)
// 	if err != nil {
// 		conn.Close()
// 		return nil, err
// 	}
// 	conn.caps = []p2p.Cap{
// 		{Name: "eth", Version: 69},
// 	}
// 	conn.ourHighestProtoVersion = 69
// 	return &conn, nil
// }

func (s *Suite) dialAs(key *ecdsa.PrivateKey) (*Conn, error) {
	// Validate basic parameters
	if s.Dest == nil {
		return nil, fmt.Errorf("error: target node information is empty")
	}
	if s.Dest.IP() == nil {
		return nil, fmt.Errorf("error: invalid target IP address")
	}
	if key == nil {
		return nil, fmt.Errorf("error: private key not set")
	}

	// Build target address
	targetAddr := fmt.Sprintf("%v:%d", s.Dest.IP(), s.Dest.TCP())

	// Attempt TCP connection
	fd, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// Provide detailed error diagnostic information
		return nil, fmt.Errorf("TCP connection failed (target=%s): %v\nPossible reasons:\n"+
			"1. Target node is not running\n"+
			"2. Port is not open\n"+
			"3. Network connectivity issues\n"+
			"4. Firewall restrictions", targetAddr, err)
	}

	// Create RLPx connection with the established TCP connection
	conn := Conn{Conn: rlpx.NewConn(fd, s.Dest.Pubkey())}
	conn.ourKey = key

	// Perform encryption handshake
	_, err = conn.Handshake(conn.ourKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("encryption handshake failed: %v", err)
	}

	// Set protocol versions and capabilities
	conn.caps = []p2p.Cap{
		{Name: "eth", Version: 67},
		{Name: "eth", Version: 68},
	}
	conn.ourHighestProtoVersion = 68

	return &conn, nil
}

// dialSnap creates a connection with snap/1 capability.
func (s *Suite) dialSnap() (*Conn, error) {
	conn, err := s.dial()
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	conn.caps = append(conn.caps, p2p.Cap{Name: "snap", Version: 1})
	conn.ourHighestSnapProtoVersion = 1
	return conn, nil
}

// Conn represents an individual connection with a peer
type Conn struct {
	*rlpx.Conn
	ourKey                     *ecdsa.PrivateKey
	negotiatedProtoVersion     uint
	negotiatedSnapProtoVersion uint
	ourHighestProtoVersion     uint
	ourHighestSnapProtoVersion uint
	caps                       []p2p.Cap
}

// Read reads a packet from the connection.
func (c *Conn) Read() (uint64, []byte, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	code, data, _, err := c.Conn.Read()
	if err != nil {
		return 0, nil, err
	}
	return code, data, nil
}

// ReadMsg attempts to read a devp2p message with a specific code.
func (c *Conn) ReadMsg(proto Proto, code uint64, msg any) error {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		got, data, err := c.Read()
		// fmt.Println("err: ", err)
		// fmt.Println("data: ", data)
		if err != nil {
			return err
		}
		if protoOffset(proto)+code == got {
			return rlp.DecodeBytes(data, msg)
		}
	}
}

// Write writes a eth packet to the connection.
func (c *Conn) Write(proto Proto, code uint64, msg any) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	payload, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(protoOffset(proto)+code, payload)
	return err
}

var errDisc error = errors.New("disconnect")

// ReadEth reads an Eth sub-protocol wire message.
func (c *Conn) ReadEth() (any, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		code, data, _, err := c.Conn.Read()
		if code == discMsg {
			return nil, errDisc
		}
		if err != nil {
			return nil, err
		}
		if code == pingMsg {
			c.Write(baseProto, pongMsg, []byte{})
			continue
		}
		if getProto(code) != ethProto {
			// Read until eth message.
			continue
		}
		code -= baseProtoLen

		var msg any
		switch int(code) {
		case eth.StatusMsg:
			msg = new(eth.StatusPacket69)
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
		if err := rlp.DecodeBytes(data, msg); err != nil {
			return nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return msg, nil
	}
}

// ReadSnap reads a snap/1 response with the given id from the connection.
func (c *Conn) ReadSnap() (any, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		code, data, _, err := c.Conn.Read()
		if err != nil {
			return nil, err
		}
		if getProto(code) != snapProto {
			// Read until snap message.
			continue
		}
		code -= baseProtoLen + ethProtoLen

		var msg any
		switch int(code) {
		case snap.GetAccountRangeMsg:
			msg = new(snap.GetAccountRangePacket)
		case snap.AccountRangeMsg:
			msg = new(snap.AccountRangePacket)
		case snap.GetStorageRangesMsg:
			msg = new(snap.GetStorageRangesPacket)
		case snap.StorageRangesMsg:
			msg = new(snap.StorageRangesPacket)
		case snap.GetByteCodesMsg:
			msg = new(snap.GetByteCodesPacket)
		case snap.ByteCodesMsg:
			msg = new(snap.ByteCodesPacket)
		case snap.GetTrieNodesMsg:
			msg = new(snap.GetTrieNodesPacket)
		case snap.TrieNodesMsg:
			msg = new(snap.TrieNodesPacket)
		default:
			panic(fmt.Errorf("unhandled snap code: %d", code))
		}
		if err := rlp.DecodeBytes(data, msg); err != nil {
			return nil, fmt.Errorf("could not rlp decode message: %v", err)
		}
		return msg, nil
	}
}

// dialAndPeer creates a peer connection and runs the handshake.
func (s *Suite) dialAndPeer(status *eth.StatusPacket68) (*Conn, error) {
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	if err = c.peer(status); err != nil {
		c.Close()
	}
	return c, err
}

func (s *Suite) DialAndPeer(status *eth.StatusPacket68) (*Conn, error) {
	c, err := s.dialAndPeer(status)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// peer performs both the protocol handshake and the status message
// exchange with the node in order to peer with it.
func (c *Conn) peer(status *eth.StatusPacket68) error {
	if err := c.handshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}
	if err := c.statusExchange(status); err != nil {
		return fmt.Errorf("status exchange failed: %v", err)
	}
	return nil
}

func (c *Conn) Peer(status *eth.StatusPacket68) error {
	c.peer(status)
	return nil
}

// handshake performs a protocol handshake with the node.
func (c *Conn) handshake() error {
	// Write hello to client.
	pub0 := crypto.FromECDSAPub(&c.ourKey.PublicKey)[1:]
	ourHandshake := &protoHandshake{
		Version: 5,
		Caps:    c.caps,
		ID:      pub0,
	}
	if err := c.Write(baseProto, handshakeMsg, ourHandshake); err != nil {
		return fmt.Errorf("write to connection failed: %v", err)
	}
	// Read hello from client.
	code, data, err := c.Read()
	if err != nil {
		return fmt.Errorf("erroring reading handshake: %v", err)
	}
	switch code {
	case handshakeMsg:
		msg := new(protoHandshake)
		if err := rlp.DecodeBytes(data, &msg); err != nil {
			return fmt.Errorf("error decoding handshake msg: %v", err)
		}
		// Set snappy if version is at least 5.
		if msg.Version >= 5 {
			c.SetSnappy(true)
		}
		c.negotiateEthProtocol(msg.Caps)
		if c.negotiatedProtoVersion == 0 {
			return fmt.Errorf("could not negotiate eth protocol (remote caps: %v, local eth version: %v)", msg.Caps, c.ourHighestProtoVersion)
		}
		// If we require snap, verify that it was negotiated.
		if c.ourHighestSnapProtoVersion != c.negotiatedSnapProtoVersion {
			return fmt.Errorf("could not negotiate snap protocol (remote caps: %v, local snap version: %v)", msg.Caps, c.ourHighestSnapProtoVersion)
		}
		return nil
	default:
		return fmt.Errorf("bad handshake: got msg code %d", code)
	}
}

// negotiateEthProtocol sets the Conn's eth protocol version to highest
// advertised capability from peer.
func (c *Conn) negotiateEthProtocol(caps []p2p.Cap) {
	var highestEthVersion uint
	var highestSnapVersion uint
	for _, capability := range caps {
		switch capability.Name {
		case "eth":
			if capability.Version > highestEthVersion && capability.Version <= c.ourHighestProtoVersion {
				highestEthVersion = capability.Version
			}
		case "snap":
			if capability.Version > highestSnapVersion && capability.Version <= c.ourHighestSnapProtoVersion {
				highestSnapVersion = capability.Version
			}
		}
	}
	c.negotiatedProtoVersion = highestEthVersion
	c.negotiatedSnapProtoVersion = highestSnapVersion
}

// statusExchange performs a `Status` message exchange with the given node.
func (c *Conn) statusExchange(status *eth.StatusPacket68) error {
loop:
	for {
		code, data, err := c.Read()
		// fmt.Println("data:", len(data))
		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch code {
		case eth.StatusMsg + protoOffset(ethProto):
			msg := new(eth.StatusPacket68)
			// msg := new(eth.StatusPacket69)
			if err := rlp.DecodeBytes(data, &msg); err != nil {
				return fmt.Errorf("error decoding status packet: %w", err)
			}
			// fmt.Println("msg:", msg)
			status = &eth.StatusPacket68{
				ProtocolVersion: msg.ProtocolVersion,
				NetworkID:       msg.NetworkID,
				TD:              msg.TD,
				Genesis:         msg.Genesis,
				ForkID:          msg.ForkID,
				Head:            msg.Head,
			}
			// status = &eth.StatusPacket69{
			// 	ProtocolVersion: msg.ProtocolVersion,
			// 	NetworkID:       msg.NetworkID,
			// 	Genesis:         msg.Genesis,
			// 	ForkID:          msg.ForkID,
			// 	EarliestBlock:   msg.EarliestBlock,
			// 	LatestBlock:     msg.LatestBlock,
			// 	LatestBlockHash: msg.LatestBlockHash,
			// }
			break loop
		case discMsg:
			var msg []p2p.DiscReason
			if rlp.DecodeBytes(data, &msg); len(msg) == 0 {
				return errors.New("invalid disconnect message")
			}
			return fmt.Errorf("disconnect received: %v", pretty.Sdump(msg))
		case pingMsg:
			// TODO (renaynay): in the future, this should be an error
			// (PINGs should not be a response upon fresh connection)
			c.Write(baseProto, pongMsg, nil)
		default:
			return fmt.Errorf("bad status message: code %d", code)
		}
	}
	// make sure eth protocol version is set for negotiation
	if c.negotiatedProtoVersion == 0 {
		return errors.New("eth protocol version must be set in Conn")
	}
	if status == nil {
		// default status message
		fmt.Println("statusPacket68 is nil!")
		// status = &eth.StatusPacket69{
		// 	ProtocolVersion: uint32(c.negotiatedProtoVersion),
		// 	NetworkID:       chain.config.ChainID.Uint64(),
		// 	Genesis:         chain.blocks[0].Hash(),
		// 	ForkID:          chain.ForkID(),
		// 	EarliestBlock:   0,
		// 	LatestBlock:     chain.blocks[chain.Len()-1].NumberU64(),
		// 	LatestBlockHash: chain.blocks[chain.Len()-1].Hash(),
		// }
	}
	if err := c.Write(ethProto, eth.StatusMsg, status); err != nil {
		return fmt.Errorf("write to connection failed: %v", err)
	}
	// printStatus(status)

	return nil
}

func printStatus(status *eth.StatusPacket68) {
	if status == nil {
		fmt.Println("Status: nil")
		return
	}

	fmt.Println("=== ETH Status Packet 68 ===")
	fmt.Printf("Protocol Version: %d\n", status.ProtocolVersion)
	fmt.Printf("Network ID: %d\n", status.NetworkID)

	if status.TD != nil {
		fmt.Printf("Total Difficulty: %s\n", status.TD.String())
	} else {
		fmt.Println("Total Difficulty: <nil>")
	}

	fmt.Printf("Genesis Hash: %s\n", status.Genesis.Hex())
	fmt.Printf("Head Hash: %s\n", status.Head.Hex())

	// Check if ForkID is zero value (empty)
	if status.ForkID.Hash != [4]byte{} || status.ForkID.Next != 0 {
		fmt.Printf("Fork ID Hash: %x\n", status.ForkID.Hash)
		fmt.Printf("Fork ID Next: %d\n", status.ForkID.Next)
	} else {
		fmt.Println("Fork ID: <empty>")
	}
	fmt.Println("==============================")
}

func (c *Conn) StatusExchange(status *eth.StatusPacket68) error {
	return c.statusExchange(status)
}
