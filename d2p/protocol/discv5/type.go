package discv5

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"net"
)

const (
	// Encryption/authentication parameters.
	aesKeySize   = 16
	gcmNonceSize = 12
)

// Public errors.
var (
	// ErrInvalidReqID represents error when the ID is invalid.
	ErrInvalidReqID = errors.New("request ID larger than 8 bytes")
)

// Nonce represents a nonce used for AES/GCM.
type Nonce [gcmNonceSize]byte

type Packet interface {
	Name() string        // Name returns a string corresponding to the message type.
	Kind() byte          // Kind returns the message type.
	RequestID() []byte   // Returns the request ID.
	SetRequestID([]byte) // Sets the request ID.
	// String is the print of packet
	String() string
	// AppendLogInfo returns its argument 'ctx' with additional fields
	// appended for logging purposes.
	AppendLogInfo(ctx []interface{}) []interface{}
}

// Message types.
const (
	PingMsg byte = iota + 1
	PongMsg
	FindnodeMsg
	NodesMsg
	TalkRequestMsg
	TalkResponseMsg

	UnknownPacket   = byte(255) // any non-decryptable packet
	WhoareyouPacket = byte(254) // the WHOAREYOU packet
)

// Protocol messages.
type (
	// Unknown represents any packet that can't be decrypted.
	Unknown struct {
		Nonce Nonce
	}

	// Whoareyou contains the handshake challenge.
	Whoareyou struct {
		ChallengeData []byte   // Encoded challenge
		Nonce         Nonce    // Nonce of request packet
		IDNonce       [16]byte // Identity proof data
		RecordSeq     uint64   // ENR sequence number of recipient

		// Node is the locally known node record of recipient.
		// This must be set by the caller of Encode.
		Node *enode.Node

		sent mclock.AbsTime // for handshake GC.
	}

	// Ping is sent during liveness checks.
	Ping struct {
		ReqID  []byte
		ENRSeq uint64
	}

	// Pong is the reply to PING.
	Pong struct {
		ReqID  []byte
		ENRSeq uint64
		ToIP   net.IP // These fields should mirror the UDP envelope address of the ping
		ToPort uint16 // packet, which provides a way to discover the external address (after NAT).
	}

	// Findnode is a query for nodes in the given bucket.
	Findnode struct {
		ReqID     []byte
		Distances []uint

		// OpID is for debugging purposes and is not part of the packet encoding.
		// It identifies the 'operation' on behalf of which the request was sent.
		OpID uint64 `rlp:"-"`
	}

	// Nodes is a response to FINDNODE.
	Nodes struct {
		ReqID     []byte
		RespCount uint8 // total number of responses to the request
		Nodes     []*enr.Record
	}

	// TalkRequest TALKREQ is an application-level request.
	TalkRequest struct {
		ReqID    []byte
		Protocol string
		Message  []byte
	}

	// TalkResponse TALKRESP is the reply to TALKREQ.
	TalkResponse struct {
		ReqID   []byte
		Message []byte
	}
)

// DecodeMessage decodes the message body of a packet.
func DecodeMessage(ptype byte, body []byte) (Packet, error) {
	var dec Packet
	switch ptype {
	case PingMsg:
		dec = new(Ping)
	case PongMsg:
		dec = new(Pong)
	case FindnodeMsg:
		dec = new(Findnode)
	case NodesMsg:
		dec = new(Nodes)
	case TalkRequestMsg:
		dec = new(TalkRequest)
	case TalkResponseMsg:
		dec = new(TalkResponse)
	default:
		return nil, fmt.Errorf("unknown packet type %d", ptype)
	}
	if err := rlp.DecodeBytes(body, dec); err != nil {
		return nil, err
	}
	if dec.RequestID() != nil && len(dec.RequestID()) > 8 {
		return nil, ErrInvalidReqID
	}
	return dec, nil
}

func (req *Whoareyou) Name() string        { return "WHOAREYOU/v5" }
func (req *Whoareyou) Kind() byte          { return WhoareyouPacket }
func (req *Whoareyou) RequestID() []byte   { return nil }
func (req *Whoareyou) SetRequestID([]byte) {}
func (req *Whoareyou) String() string {
	return fmt.Sprintf("ChallengeData: %x\nIDNonce: %x\nRecordSeq: %d",
		req.ChallengeData, req.IDNonce, req.RecordSeq)
}

func (req *Whoareyou) AppendLogInfo(ctx []interface{}) []interface{} {
	return ctx
}

func (req *Unknown) Name() string        { return "UNKNOWN/v5" }
func (req *Unknown) Kind() byte          { return UnknownPacket }
func (req *Unknown) RequestID() []byte   { return nil }
func (req *Unknown) SetRequestID([]byte) {}
func (req *Unknown) String() string {
	return fmt.Sprintf("Nonce: %x\n",
		req.Nonce)
}

func (req *Unknown) AppendLogInfo(ctx []interface{}) []interface{} {
	return ctx
}

func (req *Ping) Name() string           { return "PING/v5" }
func (req *Ping) Kind() byte             { return PingMsg }
func (req *Ping) RequestID() []byte      { return req.ReqID }
func (req *Ping) SetRequestID(id []byte) { req.ReqID = id }
func (req *Ping) String() string {
	return fmt.Sprintf("Ping{ReqID: %x, ENRSeq: %d}", req.ReqID, req.ENRSeq)
}

func (req *Ping) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(req.ReqID), "enrseq", req.ENRSeq)
}

func (req *Pong) Name() string           { return "PONG/v5" }
func (req *Pong) Kind() byte             { return PongMsg }
func (req *Pong) RequestID() []byte      { return req.ReqID }
func (req *Pong) SetRequestID(id []byte) { req.ReqID = id }
func (req *Pong) String() string {
	return fmt.Sprintf("ReqID: %x\nENRSeq: %d\nToIP: %s\nToPort: %d\n",
		req.ReqID, req.ENRSeq, req.ToIP.String(), req.ToPort)
}

func (req *Pong) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(req.ReqID), "enrseq", req.ENRSeq)
}

func (req *Findnode) Name() string           { return "FINDNODE/v5" }
func (req *Findnode) Kind() byte             { return FindnodeMsg }
func (req *Findnode) RequestID() []byte      { return req.ReqID }
func (req *Findnode) SetRequestID(id []byte) { req.ReqID = id }
func (req *Findnode) String() string {
	return fmt.Sprintf("ReqID: %x\nDistances: %d\n",
		req.ReqID, req.Distances)
}

func (req *Findnode) AppendLogInfo(ctx []interface{}) []interface{} {
	ctx = append(ctx, "req", hexutil.Bytes(req.ReqID))
	if req.OpID != 0 {
		ctx = append(ctx, "opid", req.OpID)
	}
	return ctx
}

func (req *Nodes) Name() string           { return "NODES/v5" }
func (req *Nodes) Kind() byte             { return NodesMsg }
func (req *Nodes) RequestID() []byte      { return req.ReqID }
func (req *Nodes) SetRequestID(id []byte) { req.ReqID = id }
func (req *Nodes) String() string {
	return fmt.Sprintf("ReqID: %x\nDistances: %d\n",
		req.ReqID, req.RespCount)
}

func (req *Nodes) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx,
		"req", hexutil.Bytes(req.ReqID),
		"tot", req.RespCount,
		"n", len(req.Nodes),
	)
}

func (req *TalkRequest) Name() string           { return "TALKREQ/v5" }
func (*TalkRequest) Kind() byte                 { return TalkRequestMsg }
func (req *TalkRequest) RequestID() []byte      { return req.ReqID }
func (req *TalkRequest) SetRequestID(id []byte) { req.ReqID = id }
func (req *TalkRequest) String() string {
	return fmt.Sprintf("ReqID: %x\nProtocol: %s\nMessage: %s\n",
		req.ReqID, req.Protocol, req.Message)
}

func (req *TalkRequest) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "proto", req.Protocol, "req", hexutil.Bytes(req.ReqID), "len", len(req.Message))
}

func (req *TalkResponse) Name() string           { return "TALKRESP/v5" }
func (req *TalkResponse) Kind() byte             { return TalkResponseMsg }
func (req *TalkResponse) RequestID() []byte      { return req.ReqID }
func (req *TalkResponse) SetRequestID(id []byte) { req.ReqID = id }
func (req *TalkResponse) String() string {
	return fmt.Sprintf("ReqID: %x\nMessage: %s\n",
		req.ReqID, req.Message)
}

func (req *TalkResponse) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(req.ReqID), "len", len(req.Message))
}
