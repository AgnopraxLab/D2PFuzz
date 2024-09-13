package eth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/crypto"
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

func (s *Suite) dial() (*Conn, error) {
	return s.dialAs(s.pri)
}

func (s *Suite) dialAs(key *ecdsa.PrivateKey) (*Conn, error) {
	fd, err := net.Dial("tcp", fmt.Sprintf("%v:%d", s.DestList.IP(), s.DestList.TCP()))
	if err != nil {
		return nil, err
	}
	conn := Conn{Conn: rlpx.NewConn(fd, s.DestList.Pubkey())}
	conn.ourKey = key
	_, err = conn.Handshake(conn.ourKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.caps = []p2p.Cap{
		{Name: "eth", Version: 67},
		{Name: "eth", Version: 68},
	}
	conn.ourHighestProtoVersion = 68
	return &conn, nil
}

type Conn struct {
	*rlpx.Conn
	ourKey                     *ecdsa.PrivateKey
	negotiatedProtoVersion     uint
	negotiatedSnapProtoVersion uint
	ourHighestProtoVersion     uint
	ourHighestSnapProtoVersion uint
	caps                       []p2p.Cap
}

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
		if err != nil {
			return err
		}
		if protoOffset(proto)+code == got {
			return rlp.DecodeBytes(data, msg)
		}
	}
}

func (s *Suite) ReadMsg(proto Proto, code uint64, msg interface{}) error {
	if s.conn == nil {
		return errors.New("connection not established")
	}

	s.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		got, data, err := s.conn.Read()
		if err != nil {
			return err
		}
		if protoOffset(proto)+code == got {
			return rlp.DecodeBytes(data, msg)
		}
	}
}

func (c *Conn) Write(proto Proto, code uint64, msg any) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	payload, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(protoOffset(proto)+code, payload)
	return err
}

func (s *Suite) SendMsg(proto Proto, code uint64, msg interface{}) error {
	if s.conn == nil {
		return errors.New("connection not established")
	}
	return s.conn.Write(proto, code, msg)
}

// peer performs both the protocol handshake and the status message
// exchange with the node in order to peer with it.
func (c *Conn) peer(chain *Chain, status *StatusPacket) error {
	if err := c.handshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}
	if err := c.statusExchange(chain, status); err != nil {
		return fmt.Errorf("status exchange failed: %v", err)
	}
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
func (c *Conn) statusExchange(chain *Chain, status *StatusPacket) error {
loop:
	for {
		code, data, err := c.Read()
		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch code {
		case StatusMsg + protoOffset(ethProto):
			msg := new(StatusPacket)
			if err := rlp.DecodeBytes(data, &msg); err != nil {
				return fmt.Errorf("error decoding status packet: %w", err)
			}
			if have, want := msg.Head, chain.blocks[chain.Len()-1].Hash(); have != want {
				return fmt.Errorf("wrong head block in status, want:  %#x (block %d) have %#x",
					want, chain.blocks[chain.Len()-1].NumberU64(), have)
			}
			if have, want := msg.TD.Cmp(chain.TD()), 0; have != want {
				return fmt.Errorf("wrong TD in status: have %v want %v", have, want)
			}
			if have, want := msg.ForkID, chain.ForkID(); !reflect.DeepEqual(have, want) {
				return fmt.Errorf("wrong fork ID in status: have %v, want %v", have, want)
			}
			if have, want := msg.ProtocolVersion, c.ourHighestProtoVersion; have != uint32(want) {
				return fmt.Errorf("wrong protocol version: have %v, want %v", have, want)
			}
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
		status = &StatusPacket{
			ProtocolVersion: uint32(c.negotiatedProtoVersion),
			NetworkID:       chain.config.ChainID.Uint64(),
			TD:              chain.TD(),
			Head:            chain.blocks[chain.Len()-1].Hash(),
			Genesis:         chain.blocks[0].Hash(),
			ForkID:          chain.ForkID(),
		}
	}
	if err := c.Write(ethProto, StatusMsg, status); err != nil {
		return fmt.Errorf("write to connection failed: %v", err)
	}
	return nil
}
