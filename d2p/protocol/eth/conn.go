package eth

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

var (
	timeout = 2 * time.Second
)

func (s *Suite) dial(num int) (*Conn, error) {
	return s.dialAs(s.pri, num)
}

func (s *Suite) dialAs(key *ecdsa.PrivateKey, num int) (*Conn, error) {
	fd, err := net.Dial("tcp", fmt.Sprintf("%v:%d", s.DestList[num].IP(), s.DestList[num].TCP()))
	if err != nil {
		return nil, err
	}
	conn := Conn{Conn: rlpx.NewConn(fd, s.DestList[num].Pubkey())}
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

func (c *Conn) Write(proto Proto, code uint64, msg any) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	payload, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(protoOffset(proto)+code, payload)
	return err
}
