package discv4

import (
	"encoding/hex"
	"fmt"

	"net"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// RPC packet types
const (
	PingPacket = iota + 1 // zero is 'reserved'
	PongPacket
	FindnodePacket
	NeighborsPacket
	ENRRequestPacket
	ENRResponsePacket
)

type Packet interface {
	// Name is the name of the package, for logging purposes.
	Name() string
	// Kind is the packet type, for logging purposes.
	Kind() byte
}

type (
	Ping struct {
		Version    uint
		From, To   Endpoint
		Expiration uint64
		ENRSeq     uint64 `rlp:"optional"` // Sequence number of local record, added by EIP-868.

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Pong is the reply to ping.
	Pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// external address (after NAT).
		To         Endpoint
		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		ENRSeq     uint64 `rlp:"optional"` // Sequence number of local record, added by EIP-868.

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Findnode is a query for nodes close to the given target.
	Findnode struct {
		Target     Pubkey
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Neighbors is the reply to findnode.
	Neighbors struct {
		Nodes      []Node
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// ENRRequest queries for the remote node's record.
	ENRRequest struct {
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// ENRResponse is the reply to ENRRequest.
	ENRResponse struct {
		ReplyTok []byte // Hash of the ENRRequest packet.
		Record   enr.Record
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}
)

const MaxNeighbors = 12

type Pubkey [64]byte

func (e Pubkey) ID() enode.ID {
	return enode.ID(crypto.Keccak256Hash(e[:]))
}

type Node struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for RLPx protocol
	ID  Pubkey
}

// Endpoint represents a network endpoint.
type Endpoint struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for RLPx protocol
}

func (e Endpoint) String() string {
	return fmt.Sprintf("%s (UDP: %d, TCP: %d)", e.IP, e.UDP, e.TCP)
}

func NewEndpoint(addr *net.UDPAddr, tcpPort uint16) Endpoint {
	ip := net.IP{}
	if ip4 := addr.IP.To4(); ip4 != nil {
		ip = ip4
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		ip = ip6
	}
	return Endpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (req *Ping) Name() string { return "PING/v4" }
func (req *Ping) Kind() byte   { return PingPacket }
func (req *Ping) String() string {
	return fmt.Sprintf("Version: %d\nFrom: %s\nTo: %s\nExpiration: %d\nENRSeq: %d",
		req.Version, req.From.String(), req.To.String(), req.Expiration, req.ENRSeq)
}

func (req *Pong) Name() string { return "PONG/v4" }
func (req *Pong) Kind() byte   { return PongPacket }
func (req *Pong) String() string {
	return fmt.Sprintf("To: %s\nReplyTok: %s\nExpiration: %d\nENRSeq: %d",
		req.To, hex.EncodeToString(req.ReplyTok), req.Expiration, req.ENRSeq)
}

func (req *Findnode) Name() string { return "FINDNODE/v4" }
func (req *Findnode) Kind() byte   { return FindnodePacket }
func (req *Findnode) String() string {
	return fmt.Sprintf("Target: %s\nExpiration: %d", hex.EncodeToString(req.Target[:]), req.Expiration)
}

func (req *Neighbors) Name() string   { return "NEIGHBORS/v4" }
func (req *Neighbors) Kind() byte     { return NeighborsPacket }
func (req *Neighbors) String() string { return "NEIGHBORS/v4" }

func (req *ENRRequest) Name() string { return "ENRREQUEST/v4" }
func (req *ENRRequest) Kind() byte   { return ENRRequestPacket }
func (req *ENRRequest) String() string {
	return fmt.Sprintf("Expiration: %d", req.Expiration)
}

func (req *ENRResponse) Name() string { return "ENRRESPONSE/v4" }
func (req *ENRResponse) Kind() byte   { return ENRResponsePacket }
func (req *ENRResponse) String() string {
	return fmt.Sprintf("ReplyTok: %s", hex.EncodeToString(req.ReplyTok))
}
