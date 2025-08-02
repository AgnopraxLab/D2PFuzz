package p2p

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
)

// Snap protocol message codes
const (
	// snap protocol message codes
	GetAccountRangeMsg  = 0x00
	AccountRangeMsg     = 0x01
	GetStorageRangesMsg = 0x02
	StorageRangesMsg    = 0x03
	GetByteCodesMsg     = 0x04
	ByteCodesMsg        = 0x05
	GetTrieNodesMsg     = 0x06
	TrieNodesMsg        = 0x07
)

// GetAccountRangePacket represents a request for account ranges
type GetAccountRangePacket struct {
	ID     uint64      // Request ID to match up responses with
	Root   common.Hash // Root hash of the account trie to serve
	Origin common.Hash // Hash of the first account to retrieve
	Limit  common.Hash // Hash of the last account to retrieve
	Bytes  uint64      // Soft limit at which to stop returning data
}

// AccountRangePacket represents a response to GetAccountRangePacket
type AccountRangePacket struct {
	ID       uint64         // ID of the request this is a response for
	Accounts []*AccountData // List of consecutive accounts from the trie
	Proof    [][]byte       // List of trie nodes proving the account range
}

// AccountData represents account data in snap protocol
type AccountData struct {
	Hash common.Hash // Hash of the account
	Body []byte      // RLP encoded account
}

// GetStorageRangesPacket represents a request for storage ranges
type GetStorageRangesPacket struct {
	ID       uint64        // Request ID to match up responses with
	Root     common.Hash   // Root hash of the account trie to serve
	Accounts []common.Hash // Account hashes to retrieve storage for
	Origin   common.Hash   // Hash of the first storage slot to retrieve
	Limit    common.Hash   // Hash of the last storage slot to retrieve
	Bytes    uint64        // Soft limit at which to stop returning data
}

// StorageRangesPacket represents a response to GetStorageRangesPacket
type StorageRangesPacket struct {
	ID    uint64           // ID of the request this is a response for
	Slots [][]*StorageData // List of storage slots for the requested accounts
	Proof [][]byte         // List of trie nodes proving the storage ranges
}

// StorageData represents storage data in snap protocol
type StorageData struct {
	Hash common.Hash // Hash of the storage slot
	Body []byte      // Storage slot data
}

// GetByteCodesPacket represents a request for contract bytecodes
type GetByteCodesPacket struct {
	ID     uint64        // Request ID to match up responses with
	Hashes []common.Hash // Code hashes to retrieve the code for
	Bytes  uint64        // Soft limit at which to stop returning data
}

// ByteCodesPacket represents a response to GetByteCodesPacket
type ByteCodesPacket struct {
	ID    uint64   // ID of the request this is a response for
	Codes [][]byte // Requested contract bytecodes
}

// GetTrieNodesPacket represents a request for trie nodes
type GetTrieNodesPacket struct {
	ID    uint64            // Request ID to match up responses with
	Root  common.Hash       // Root hash of the trie to serve
	Paths []TrieNodePathSet // Trie node paths to retrieve
	Bytes uint64            // Soft limit at which to stop returning data
}

// TrieNodePathSet represents a set of trie node paths
type TrieNodePathSet [][]byte

// TrieNodesPacket represents a response to GetTrieNodesPacket
type TrieNodesPacket struct {
	ID    uint64   // ID of the request this is a response for
	Nodes [][]byte // Requested trie nodes
}

// SnapProtocolHandler handles Snap protocol messages
type SnapProtocolHandler struct {
	client *fuzzer.FuzzClient
	logger fuzzer.Logger
}

// NewSnapProtocolHandler creates a new Snap protocol handler
func NewSnapProtocolHandler(client *fuzzer.FuzzClient, logger fuzzer.Logger) *SnapProtocolHandler {
	return &SnapProtocolHandler{
		client: client,
		logger: logger,
	}
}

// RequestAccountRange requests account ranges from a peer
func (h *SnapProtocolHandler) RequestAccountRange(peerID enode.ID, req *GetAccountRangePacket) error {
	return h.client.SendSnapMessage(peerID, GetAccountRangeMsg, req)
}

// SendAccountRange sends account ranges to a peer
func (h *SnapProtocolHandler) SendAccountRange(peerID enode.ID, resp *AccountRangePacket) error {
	return h.client.SendSnapMessage(peerID, AccountRangeMsg, resp)
}

// RequestStorageRanges requests storage ranges from a peer
func (h *SnapProtocolHandler) RequestStorageRanges(peerID enode.ID, req *GetStorageRangesPacket) error {
	return h.client.SendSnapMessage(peerID, GetStorageRangesMsg, req)
}

// SendStorageRanges sends storage ranges to a peer
func (h *SnapProtocolHandler) SendStorageRanges(peerID enode.ID, resp *StorageRangesPacket) error {
	return h.client.SendSnapMessage(peerID, StorageRangesMsg, resp)
}

// RequestByteCodes requests contract bytecodes from a peer
func (h *SnapProtocolHandler) RequestByteCodes(peerID enode.ID, req *GetByteCodesPacket) error {
	return h.client.SendSnapMessage(peerID, GetByteCodesMsg, req)
}

// SendByteCodes sends contract bytecodes to a peer
func (h *SnapProtocolHandler) SendByteCodes(peerID enode.ID, resp *ByteCodesPacket) error {
	return h.client.SendSnapMessage(peerID, ByteCodesMsg, resp)
}

// RequestTrieNodes requests trie nodes from a peer
func (h *SnapProtocolHandler) RequestTrieNodes(peerID enode.ID, req *GetTrieNodesPacket) error {
	return h.client.SendSnapMessage(peerID, GetTrieNodesMsg, req)
}

// SendTrieNodes sends trie nodes to a peer
func (h *SnapProtocolHandler) SendTrieNodes(peerID enode.ID, resp *TrieNodesPacket) error {
	return h.client.SendSnapMessage(peerID, TrieNodesMsg, resp)
}

// HandleMessage processes incoming Snap protocol messages
func (h *SnapProtocolHandler) HandleMessage(peerID enode.ID, msg *p2p.Msg) error {
	switch msg.Code {
	case GetAccountRangeMsg:
		return h.handleGetAccountRange(peerID, msg)
	case AccountRangeMsg:
		return h.handleAccountRange(peerID, msg)
	case GetStorageRangesMsg:
		return h.handleGetStorageRanges(peerID, msg)
	case StorageRangesMsg:
		return h.handleStorageRanges(peerID, msg)
	case GetByteCodesMsg:
		return h.handleGetByteCodes(peerID, msg)
	case ByteCodesMsg:
		return h.handleByteCodes(peerID, msg)
	case GetTrieNodesMsg:
		return h.handleGetTrieNodes(peerID, msg)
	case TrieNodesMsg:
		return h.handleTrieNodes(peerID, msg)
	default:
		h.logger.Debug("Unknown snap message code: %x from peer %s", msg.Code, peerID)
		return nil
	}
}

func (h *SnapProtocolHandler) handleGetAccountRange(peerID enode.ID, msg *p2p.Msg) error {
	var req GetAccountRangePacket
	if err := msg.Decode(&req); err != nil {
		return fmt.Errorf("failed to decode get account range: %w", err)
	}

	h.logger.Info("Received account range request from %s: ID=%d, root=%s, bytes=%d",
		peerID, req.ID, req.Root.Hex(), req.Bytes)
	return nil
}

func (h *SnapProtocolHandler) handleAccountRange(peerID enode.ID, msg *p2p.Msg) error {
	var resp AccountRangePacket
	if err := msg.Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode account range: %w", err)
	}

	h.logger.Info("Received account range response from %s: ID=%d, accounts=%d, proof=%d",
		peerID, resp.ID, len(resp.Accounts), len(resp.Proof))
	return nil
}

func (h *SnapProtocolHandler) handleGetStorageRanges(peerID enode.ID, msg *p2p.Msg) error {
	var req GetStorageRangesPacket
	if err := msg.Decode(&req); err != nil {
		return fmt.Errorf("failed to decode get storage ranges: %w", err)
	}

	h.logger.Info("Received storage ranges request from %s: ID=%d, root=%s, accounts=%d, bytes=%d",
		peerID, req.ID, req.Root.Hex(), len(req.Accounts), req.Bytes)
	return nil
}

func (h *SnapProtocolHandler) handleStorageRanges(peerID enode.ID, msg *p2p.Msg) error {
	var resp StorageRangesPacket
	if err := msg.Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode storage ranges: %w", err)
	}

	h.logger.Info("Received storage ranges response from %s: ID=%d, slots=%d, proof=%d",
		peerID, resp.ID, len(resp.Slots), len(resp.Proof))
	return nil
}

func (h *SnapProtocolHandler) handleGetByteCodes(peerID enode.ID, msg *p2p.Msg) error {
	var req GetByteCodesPacket
	if err := msg.Decode(&req); err != nil {
		return fmt.Errorf("failed to decode get bytecodes: %w", err)
	}

	h.logger.Info("Received bytecodes request from %s: ID=%d, hashes=%d, bytes=%d",
		peerID, req.ID, len(req.Hashes), req.Bytes)
	return nil
}

func (h *SnapProtocolHandler) handleByteCodes(peerID enode.ID, msg *p2p.Msg) error {
	var resp ByteCodesPacket
	if err := msg.Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode bytecodes: %w", err)
	}

	h.logger.Info("Received bytecodes response from %s: ID=%d, codes=%d",
		peerID, resp.ID, len(resp.Codes))
	return nil
}

func (h *SnapProtocolHandler) handleGetTrieNodes(peerID enode.ID, msg *p2p.Msg) error {
	var req GetTrieNodesPacket
	if err := msg.Decode(&req); err != nil {
		return fmt.Errorf("failed to decode get trie nodes: %w", err)
	}

	h.logger.Info("Received trie nodes request from %s: ID=%d, root=%s, paths=%d, bytes=%d",
		peerID, req.ID, req.Root.Hex(), len(req.Paths), req.Bytes)
	return nil
}

func (h *SnapProtocolHandler) handleTrieNodes(peerID enode.ID, msg *p2p.Msg) error {
	var resp TrieNodesPacket
	if err := msg.Decode(&resp); err != nil {
		return fmt.Errorf("failed to decode trie nodes: %w", err)
	}

	h.logger.Info("Received trie nodes response from %s: ID=%d, nodes=%d",
		peerID, resp.ID, len(resp.Nodes))
	return nil
}

// CreateFuzzedAccountRangeRequest creates a potentially fuzzed account range request
func (h *SnapProtocolHandler) CreateFuzzedAccountRangeRequest(id uint64) *GetAccountRangePacket {
	return &GetAccountRangePacket{
		ID:     id,
		Root:   common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		Origin: common.Hash{},
		Limit:  common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		Bytes:  1024 * 1024, // 1MB
	}
}

// CreateFuzzedStorageRangesRequest creates a potentially fuzzed storage ranges request
func (h *SnapProtocolHandler) CreateFuzzedStorageRangesRequest(id uint64) *GetStorageRangesPacket {
	return &GetStorageRangesPacket{
		ID:   id,
		Root: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		Accounts: []common.Hash{
			common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
		},
		Origin: common.Hash{},
		Limit:  common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		Bytes:  1024 * 1024, // 1MB
	}
}

// CreateFuzzedByteCodesRequest creates a potentially fuzzed bytecodes request
func (h *SnapProtocolHandler) CreateFuzzedByteCodesRequest(id uint64) *GetByteCodesPacket {
	return &GetByteCodesPacket{
		ID: id,
		Hashes: []common.Hash{
			common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
		},
		Bytes: 1024 * 1024, // 1MB
	}
}

// CreateFuzzedTrieNodesRequest creates a potentially fuzzed trie nodes request
func (h *SnapProtocolHandler) CreateFuzzedTrieNodesRequest(id uint64) *GetTrieNodesPacket {
	return &GetTrieNodesPacket{
		ID:   id,
		Root: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		Paths: []TrieNodePathSet{
			{[]byte{0x01, 0x02, 0x03}},
			{[]byte{0x04, 0x05, 0x06}},
		},
		Bytes: 1024 * 1024, // 1MB
	}
}
