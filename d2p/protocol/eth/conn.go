package eth

import (
	"crypto/ecdsa"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
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
