package rlpx

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"fmt"
	"hash"
	"net"
)

func NewConn(conn net.Conn, dialDest *ecdsa.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

func newHashMAC(cipher cipher.Block, h hash.Hash) hashMAC {
	m := hashMAC{cipher: cipher, hash: h}
	if cipher.BlockSize() != len(m.aesBuffer) {
		panic(fmt.Errorf("invalid MAC cipher block size %d", cipher.BlockSize()))
	}
	if h.Size() != len(m.hashBuffer) {
		panic(fmt.Errorf("invalid MAC digest size %d", h.Size()))
	}
	return m
}
