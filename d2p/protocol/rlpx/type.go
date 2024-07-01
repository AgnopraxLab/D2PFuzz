package rlpx

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"hash"
	"net"
)

// Constants for the handshake.
const (
	sskLen = 16                     // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = crypto.SignatureLength // elliptic S256
	pubLen = 64                     // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32                     // hash length (for nonce etc)

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */
)

const (
	AuthMsgV4 = iota + 1 // zero is 'reserved'
	AuthRespV4
)

type Conn struct {
	dialDest *ecdsa.PublicKey
	conn     net.Conn
	session  *sessionState

	// These are the buffers for snappy compression.
	// Compression is enabled if they are non-nil.
	snappyReadBuffer  []byte
	snappyWriteBuffer []byte
}

type sessionState struct {
	enc cipher.Stream
	dec cipher.Stream

	egressMAC  hashMAC
	ingressMAC hashMAC
	rbuf       readBuffer
	wbuf       writeBuffer
}

// hashMAC holds the state of the RLPx v4 MAC contraption.
type hashMAC struct {
	cipher     cipher.Block
	hash       hash.Hash
	aesBuffer  [16]byte
	hashBuffer [32]byte
	seedBuffer [32]byte
}

// Secrets represents the connection secrets which are negotiated during the handshake.
type Secrets struct {
	AES, MAC              []byte
	EgressMAC, IngressMAC hash.Hash
	remote                *ecdsa.PublicKey
}

// handshakeState contains the state of the encryption handshake.
type handshakeState struct {
	initiator            bool
	remote               *ecies.PublicKey  // remote-pubk
	initNonce, respNonce []byte            // nonce
	randomPrivKey        *ecies.PrivateKey // ecdhe-random
	remoteRandomPub      *ecies.PublicKey  // ecdhe-random-pubk

	rbuf readBuffer
	wbuf writeBuffer
}

// RLPx v4 handshake auth (defined in EIP-8).
type authMsgV4 struct {
	Signature       [sigLen]byte
	InitiatorPubkey [pubLen]byte
	Nonce           [shaLen]byte
	Version         uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
type authRespV4 struct {
	RandomPubkey [pubLen]byte
	Nonce        [shaLen]byte
	Version      uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

func (req *authMsgV4) Name() string   { return "AuthMsg/V4" }
func (req *authMsgV4) Kind() byte     { return AuthMsgV4 }
func (req *authMsgV4) OutPut() string { return "AuthMsg/V4" }

func (req *authRespV4) Name() string   { return "AuthResp/V4" }
func (req *authRespV4) Kind() byte     { return AuthRespV4 }
func (req *authRespV4) OutPut() string { return "AuthResp/V4" }
