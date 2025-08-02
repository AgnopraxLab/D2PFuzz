package p2p

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
)

// Ethereum protocol message codes
const (
	// eth protocol message codes
	StatusMsg                     = 0x00
	NewBlockHashesMsg             = 0x01
	TransactionsMsg               = 0x02
	GetBlockHeadersMsg            = 0x03
	BlockHeadersMsg               = 0x04
	GetBlockBodiesMsg             = 0x05
	BlockBodiesMsg                = 0x06
	NewBlockMsg                   = 0x07
	NewPooledTransactionHashesMsg = 0x08
	GetPooledTransactionsMsg      = 0x09
	PooledTransactionsMsg         = 0x0a
	GetReceiptsMsg                = 0x0f
	ReceiptsMsg                   = 0x10
	BlockRangeUpdateMsg           = 0x11
)

// StatusData represents the eth protocol status message
type StatusData struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	BestHash        common.Hash
	GenesisHash     common.Hash
	ForkID          ForkID
}

// ForkID represents the fork identifier
type ForkID struct {
	Hash [4]byte // CRC32 checksum of the genesis hash and fork blocks
	Next uint64  // Block number of the next fork, or 0 if no next fork is known
}

// NewBlockHashesData represents new block hashes announcement
type NewBlockHashesData []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}

// GetBlockHeadersData represents a block header query
type GetBlockHeadersData struct {
	Origin  HashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

// HashOrNumber represents either a block hash or block number
type HashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

// BlockHeadersData represents a batch of block headers
type BlockHeadersData []*types.Header

// GetBlockBodiesData represents a block body query
type GetBlockBodiesData []common.Hash

// BlockBodiesData represents a batch of block bodies
type BlockBodiesData []*types.Body

// NewBlockData represents a new block announcement
type NewBlockData struct {
	Block *types.Block
	TD    *big.Int
}

// TransactionsData represents a batch of transactions
type TransactionsData []*types.Transaction

// EthProtocolHandler handles Ethereum protocol messages
type EthProtocolHandler struct {
	client *fuzzer.FuzzClient
	logger fuzzer.Logger
}

// NewEthProtocolHandler creates a new Ethereum protocol handler
func NewEthProtocolHandler(client *fuzzer.FuzzClient, logger fuzzer.Logger) *EthProtocolHandler {
	return &EthProtocolHandler{
		client: client,
		logger: logger,
	}
}

// SendStatus sends a status message to a peer
func (h *EthProtocolHandler) SendStatus(peerID enode.ID, status *StatusData) error {
	return h.client.SendEthMessage(peerID, StatusMsg, status)
}

// SendNewBlockHashes sends new block hashes to a peer
func (h *EthProtocolHandler) SendNewBlockHashes(peerID enode.ID, hashes NewBlockHashesData) error {
	return h.client.SendEthMessage(peerID, NewBlockHashesMsg, hashes)
}

// SendTransactions sends transactions to a peer
func (h *EthProtocolHandler) SendTransactions(peerID enode.ID, txs TransactionsData) error {
	return h.client.SendEthMessage(peerID, TransactionsMsg, txs)
}

// RequestBlockHeaders requests block headers from a peer
func (h *EthProtocolHandler) RequestBlockHeaders(peerID enode.ID, query *GetBlockHeadersData) error {
	return h.client.SendEthMessage(peerID, GetBlockHeadersMsg, query)
}

// SendBlockHeaders sends block headers to a peer
func (h *EthProtocolHandler) SendBlockHeaders(peerID enode.ID, headers BlockHeadersData) error {
	return h.client.SendEthMessage(peerID, BlockHeadersMsg, headers)
}

// RequestBlockBodies requests block bodies from a peer
func (h *EthProtocolHandler) RequestBlockBodies(peerID enode.ID, hashes GetBlockBodiesData) error {
	return h.client.SendEthMessage(peerID, GetBlockBodiesMsg, hashes)
}

// SendBlockBodies sends block bodies to a peer
func (h *EthProtocolHandler) SendBlockBodies(peerID enode.ID, bodies BlockBodiesData) error {
	return h.client.SendEthMessage(peerID, BlockBodiesMsg, bodies)
}

// SendNewBlock sends a new block to a peer
func (h *EthProtocolHandler) SendNewBlock(peerID enode.ID, block *NewBlockData) error {
	return h.client.SendEthMessage(peerID, NewBlockMsg, block)
}

// HandleMessage processes incoming Ethereum protocol messages
func (h *EthProtocolHandler) HandleMessage(peerID enode.ID, msg *p2p.Msg) error {
	switch msg.Code {
	case StatusMsg:
		return h.handleStatus(peerID, msg)
	case NewBlockHashesMsg:
		return h.handleNewBlockHashes(peerID, msg)
	case TransactionsMsg:
		return h.handleTransactions(peerID, msg)
	case GetBlockHeadersMsg:
		return h.handleGetBlockHeaders(peerID, msg)
	case BlockHeadersMsg:
		return h.handleBlockHeaders(peerID, msg)
	case GetBlockBodiesMsg:
		return h.handleGetBlockBodies(peerID, msg)
	case BlockBodiesMsg:
		return h.handleBlockBodies(peerID, msg)
	case NewBlockMsg:
		return h.handleNewBlock(peerID, msg)
	default:
		h.logger.Debug("Unknown eth message code: %x from peer %s", msg.Code, peerID)
		return nil
	}
}

func (h *EthProtocolHandler) handleStatus(peerID enode.ID, msg *p2p.Msg) error {
	var status StatusData
	if err := msg.Decode(&status); err != nil {
		return fmt.Errorf("failed to decode status message: %w", err)
	}

	h.logger.Info("Received status from %s: protocol=%d, network=%d, td=%s, best=%s",
		peerID, status.ProtocolVersion, status.NetworkID, status.TD.String(), status.BestHash.Hex())
	return nil
}

func (h *EthProtocolHandler) handleNewBlockHashes(peerID enode.ID, msg *p2p.Msg) error {
	var hashes NewBlockHashesData
	if err := msg.Decode(&hashes); err != nil {
		return fmt.Errorf("failed to decode new block hashes: %w", err)
	}

	h.logger.Info("Received %d new block hashes from %s", len(hashes), peerID)
	for _, hash := range hashes {
		h.logger.Debug("New block hash: %s, number: %d", hash.Hash.Hex(), hash.Number)
	}
	return nil
}

func (h *EthProtocolHandler) handleTransactions(peerID enode.ID, msg *p2p.Msg) error {
	var txs TransactionsData
	if err := msg.Decode(&txs); err != nil {
		return fmt.Errorf("failed to decode transactions: %w", err)
	}

	h.logger.Info("Received %d transactions from %s", len(txs), peerID)
	return nil
}

func (h *EthProtocolHandler) handleGetBlockHeaders(peerID enode.ID, msg *p2p.Msg) error {
	var query GetBlockHeadersData
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("failed to decode get block headers: %w", err)
	}

	h.logger.Info("Received block headers request from %s: amount=%d, skip=%d, reverse=%t",
		peerID, query.Amount, query.Skip, query.Reverse)
	return nil
}

func (h *EthProtocolHandler) handleBlockHeaders(peerID enode.ID, msg *p2p.Msg) error {
	var headers BlockHeadersData
	if err := msg.Decode(&headers); err != nil {
		return fmt.Errorf("failed to decode block headers: %w", err)
	}

	h.logger.Info("Received %d block headers from %s", len(headers), peerID)
	return nil
}

func (h *EthProtocolHandler) handleGetBlockBodies(peerID enode.ID, msg *p2p.Msg) error {
	var hashes GetBlockBodiesData
	if err := msg.Decode(&hashes); err != nil {
		return fmt.Errorf("failed to decode get block bodies: %w", err)
	}

	h.logger.Info("Received block bodies request for %d blocks from %s", len(hashes), peerID)
	return nil
}

func (h *EthProtocolHandler) handleBlockBodies(peerID enode.ID, msg *p2p.Msg) error {
	var bodies BlockBodiesData
	if err := msg.Decode(&bodies); err != nil {
		return fmt.Errorf("failed to decode block bodies: %w", err)
	}

	h.logger.Info("Received %d block bodies from %s", len(bodies), peerID)
	return nil
}

func (h *EthProtocolHandler) handleNewBlock(peerID enode.ID, msg *p2p.Msg) error {
	var newBlock NewBlockData
	if err := msg.Decode(&newBlock); err != nil {
		return fmt.Errorf("failed to decode new block: %w", err)
	}

	h.logger.Info("Received new block from %s: number=%d, hash=%s, td=%s",
		peerID, newBlock.Block.Number(), newBlock.Block.Hash().Hex(), newBlock.TD.String())
	return nil
}

// CreateFuzzedStatusMessage creates a status message with potentially fuzzed data
func (h *EthProtocolHandler) CreateFuzzedStatusMessage() *StatusData {
	return &StatusData{
		ProtocolVersion: 68, // eth/68
		NetworkID:       1,  // Mainnet
		TD:              big.NewInt(1000000),
		BestHash:        common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		GenesisHash:     common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
		ForkID: ForkID{
			Hash: [4]byte{0x12, 0x34, 0x56, 0x78},
			Next: 0,
		},
	}
}

// CreateFuzzedTransactions creates a batch of potentially fuzzed transactions
func (h *EthProtocolHandler) CreateFuzzedTransactions(count int) TransactionsData {
	txs := make(TransactionsData, count)
	for i := 0; i < count; i++ {
		// Create a simple transaction (this would be fuzzed in practice)
		tx := types.NewTransaction(
			uint64(i),
			common.HexToAddress("0x1234567890123456789012345678901234567890"),
			big.NewInt(1000),
			21000,
			big.NewInt(20000000000),
			[]byte{},
		)
		txs[i] = tx
	}
	return txs
}
