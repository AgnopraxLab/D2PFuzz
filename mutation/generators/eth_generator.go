package generators

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/AgnopraxLab/D2PFuzz/mutation"
)

// ETH protocol message codes
const (
	StatusMsg          = 0x00
	NewBlockHashesMsg  = 0x01
	TransactionsMsg    = 0x02
	GetBlockHeadersMsg = 0x03
	BlockHeadersMsg    = 0x04
	GetBlockBodiesMsg  = 0x05
	BlockBodiesMsg     = 0x06
	NewBlockMsg        = 0x07
	GetNodeDataMsg     = 0x0d
	NodeDataMsg        = 0x0e
	GetReceiptsMsg     = 0x0f
	ReceiptsMsg        = 0x10
)

// ETHGenerator generates ETH protocol messages for testing
type ETHGenerator struct {
	rng    *mathrand.Rand
	config *mutation.MutationConfig
}

// NewETHGenerator creates a new ETH message generator
func NewETHGenerator(config *mutation.MutationConfig) *ETHGenerator {
	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	
	return &ETHGenerator{
		rng:    mathrand.New(mathrand.NewSource(seed)),
		config: config,
	}
}

// GenerateMessage generates a random ETH protocol message
func (g *ETHGenerator) GenerateMessage(msgType uint64) ([]byte, error) {
	switch msgType {
	case StatusMsg:
		return g.GenerateStatusMessage()
	case NewBlockHashesMsg:
		return g.GenerateNewBlockHashesMessage()
	case TransactionsMsg:
		return g.GenerateTransactionsMessage()
	case GetBlockHeadersMsg:
		return g.GenerateGetBlockHeadersMessage()
	case BlockHeadersMsg:
		return g.GenerateBlockHeadersMessage()
	case GetBlockBodiesMsg:
		return g.GenerateGetBlockBodiesMessage()
	case BlockBodiesMsg:
		return g.GenerateBlockBodiesMessage()
	case NewBlockMsg:
		return g.GenerateNewBlockMessage()
	case GetNodeDataMsg:
		return g.GenerateGetNodeDataMessage()
	case NodeDataMsg:
		return g.GenerateNodeDataMessage()
	case GetReceiptsMsg:
		return g.GenerateGetReceiptsMessage()
	case ReceiptsMsg:
		return g.GenerateReceiptsMessage()
	default:
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}
}

// GenerateRandomMessage generates a random message of any type
func (g *ETHGenerator) GenerateRandomMessage() ([]byte, error) {
	msgTypes := []uint64{
		StatusMsg, NewBlockHashesMsg, TransactionsMsg,
		GetBlockHeadersMsg, BlockHeadersMsg, GetBlockBodiesMsg,
		BlockBodiesMsg, NewBlockMsg, GetNodeDataMsg,
		NodeDataMsg, GetReceiptsMsg, ReceiptsMsg,
	}
	
	msgType := msgTypes[g.rng.Intn(len(msgTypes))]
	return g.GenerateMessage(msgType)
}

// Status message generation
func (g *ETHGenerator) GenerateStatusMessage() ([]byte, error) {
	status := struct {
		ProtocolVersion uint32
		NetworkID       uint64
		TD              *big.Int
		BestHash        common.Hash
		GenesisHash     common.Hash
		ForkID          struct {
			Hash common.Hash
			Next uint64
		}
	}{
		ProtocolVersion: uint32(g.config.ETH.TargetProtocolVersion),
		NetworkID:       uint64(g.rng.Uint32()),
		TD:              big.NewInt(int64(g.rng.Uint64())),
		BestHash:        g.generateRandomHash(),
		GenesisHash:     g.generateRandomHash(),
		ForkID: struct {
			Hash common.Hash
			Next uint64
		}{
			Hash: g.generateRandomHash(),
			Next: uint64(g.rng.Uint32()),
		},
	}
	
	return rlp.EncodeToBytes(status)
}

// NewBlockHashes message generation
func (g *ETHGenerator) GenerateNewBlockHashesMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	hashes := make([]struct {
		Hash   common.Hash
		Number uint64
	}, count)
	
	for i := 0; i < count; i++ {
		hashes[i] = struct {
			Hash   common.Hash
			Number uint64
		}{
			Hash:   g.generateRandomHash(),
			Number: uint64(g.rng.Uint32()) % g.config.ETH.MaxBlockNumber,
		}
	}
	
	return rlp.EncodeToBytes(hashes)
}

// Transactions message generation
func (g *ETHGenerator) GenerateTransactionsMessage() ([]byte, error) {
	count := g.rng.Intn(5) + 1
	txs := make([]*types.Transaction, count)
	
	for i := 0; i < count; i++ {
		tx, err := g.generateRandomTransaction()
		if err != nil {
			return nil, fmt.Errorf("failed to generate transaction: %v", err)
		}
		txs[i] = tx
	}
	
	return rlp.EncodeToBytes(txs)
}

// GetBlockHeaders message generation
func (g *ETHGenerator) GenerateGetBlockHeadersMessage() ([]byte, error) {
	request := struct {
		Origin  interface{} // Hash or number
		Amount  uint64
		Skip    uint64
		Reverse bool
	}{
		Origin:  g.generateBlockOrigin(),
		Amount:  uint64(g.rng.Intn(100) + 1),
		Skip:    uint64(g.rng.Intn(10)),
		Reverse: g.rng.Intn(2) == 0,
	}
	
	return rlp.EncodeToBytes(request)
}

// BlockHeaders message generation
func (g *ETHGenerator) GenerateBlockHeadersMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	headers := make([]*types.Header, count)
	
	for i := 0; i < count; i++ {
		headers[i] = g.generateRandomHeader()
	}
	
	return rlp.EncodeToBytes(headers)
}

// GetBlockBodies message generation
func (g *ETHGenerator) GenerateGetBlockBodiesMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	hashes := make([]common.Hash, count)
	
	for i := 0; i < count; i++ {
		hashes[i] = g.generateRandomHash()
	}
	
	return rlp.EncodeToBytes(hashes)
}

// BlockBodies message generation
func (g *ETHGenerator) GenerateBlockBodiesMessage() ([]byte, error) {
	count := g.rng.Intn(5) + 1
	bodies := make([]*types.Body, count)
	
	for i := 0; i < count; i++ {
		bodies[i] = g.generateRandomBody()
	}
	
	return rlp.EncodeToBytes(bodies)
}

// NewBlock message generation
func (g *ETHGenerator) GenerateNewBlockMessage() ([]byte, error) {
	block := struct {
		Block *types.Block
		TD    *big.Int
	}{
		Block: g.generateRandomBlock(),
		TD:    big.NewInt(int64(g.rng.Uint64())),
	}
	
	return rlp.EncodeToBytes(block)
}

// GetNodeData message generation
func (g *ETHGenerator) GenerateGetNodeDataMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	hashes := make([]common.Hash, count)
	
	for i := 0; i < count; i++ {
		hashes[i] = g.generateRandomHash()
	}
	
	return rlp.EncodeToBytes(hashes)
}

// NodeData message generation
func (g *ETHGenerator) GenerateNodeDataMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	data := make([][]byte, count)
	
	for i := 0; i < count; i++ {
		length := g.rng.Intn(1024) + 1
		data[i] = make([]byte, length)
		rand.Read(data[i])
	}
	
	return rlp.EncodeToBytes(data)
}

// GetReceipts message generation
func (g *ETHGenerator) GenerateGetReceiptsMessage() ([]byte, error) {
	count := g.rng.Intn(10) + 1
	hashes := make([]common.Hash, count)
	
	for i := 0; i < count; i++ {
		hashes[i] = g.generateRandomHash()
	}
	
	return rlp.EncodeToBytes(hashes)
}

// Receipts message generation
func (g *ETHGenerator) GenerateReceiptsMessage() ([]byte, error) {
	count := g.rng.Intn(5) + 1
	receipts := make([][]*types.Receipt, count)
	
	for i := 0; i < count; i++ {
		receiptCount := g.rng.Intn(10) + 1
		receipts[i] = make([]*types.Receipt, receiptCount)
		
		for j := 0; j < receiptCount; j++ {
			receipts[i][j] = g.generateRandomReceipt()
		}
	}
	
	return rlp.EncodeToBytes(receipts)
}

// Helper functions for generating random data

func (g *ETHGenerator) generateRandomHash() common.Hash {
	var hash common.Hash
	rand.Read(hash[:])
	return hash
}

func (g *ETHGenerator) generateRandomAddress() common.Address {
	var addr common.Address
	rand.Read(addr[:])
	return addr
}

func (g *ETHGenerator) generateBlockOrigin() interface{} {
	if g.rng.Intn(2) == 0 {
		// Return block number
		return uint64(g.rng.Uint32()) % g.config.ETH.MaxBlockNumber
	} else {
		// Return block hash
		return g.generateRandomHash()
	}
}

func (g *ETHGenerator) generateRandomTransaction() (*types.Transaction, error) {
	// Generate different transaction types
	txType := g.rng.Intn(3) // 0: Legacy, 1: EIP-2930, 2: EIP-1559
	
	to := g.generateRandomAddress()
	// Ensure positive values to avoid RLP encoding errors
	value := big.NewInt(int64(g.rng.Uint32() % 1000000)) // Smaller positive values
	gasLimit := uint64(21000 + g.rng.Uint32()%100000)   // Reasonable gas limit
	data := make([]byte, g.rng.Intn(256))                // Smaller data size
	rand.Read(data)
	
	switch txType {
	case 0:
		// Legacy transaction
		gasPrice := big.NewInt(int64(1000000000 + g.rng.Uint32()%3000000000)) // 1-4 Gwei
		return types.NewTransaction(
			uint64(g.rng.Uint32()),
			to,
			value,
			gasLimit,
			gasPrice,
			data,
		), nil
		
	case 1:
		// EIP-2930 transaction
		gasPrice := big.NewInt(int64(1000000000 + g.rng.Uint32()%3000000000)) // 1-4 Gwei
		accessList := g.generateRandomAccessList()
		return types.NewTx(&types.AccessListTx{
			ChainID:    big.NewInt(1),
			Nonce:      uint64(g.rng.Uint32()),
			To:         &to,
			Value:      value,
			Gas:        gasLimit,
			GasPrice:   gasPrice,
			Data:       data,
			AccessList: accessList,
		}), nil
		
	case 2:
		// EIP-1559 transaction
		gasTipCap := big.NewInt(int64(1000000000 + g.rng.Uint32()%2000000000))  // 1-3 Gwei
		gasFeeCap := big.NewInt(int64(3000000000 + g.rng.Uint32()%1000000000)) // 3-4 Gwei
		accessList := g.generateRandomAccessList()
		return types.NewTx(&types.DynamicFeeTx{
			ChainID:    big.NewInt(1),
			Nonce:      uint64(g.rng.Uint32()),
			To:         &to,
			Value:      value,
			Gas:        gasLimit,
			GasTipCap:  gasTipCap,
			GasFeeCap:  gasFeeCap,
			Data:       data,
			AccessList: accessList,
		}), nil
		
	default:
		return nil, fmt.Errorf("invalid transaction type: %d", txType)
	}
}

func (g *ETHGenerator) generateRandomAccessList() types.AccessList {
	count := g.rng.Intn(5)
	accessList := make(types.AccessList, count)
	
	for i := 0; i < count; i++ {
		storageKeyCount := g.rng.Intn(10)
		storageKeys := make([]common.Hash, storageKeyCount)
		
		for j := 0; j < storageKeyCount; j++ {
			storageKeys[j] = g.generateRandomHash()
		}
		
		accessList[i] = types.AccessTuple{
			Address:     g.generateRandomAddress(),
			StorageKeys: storageKeys,
		}
	}
	
	return accessList
}

func (g *ETHGenerator) generateRandomHeader() *types.Header {
	return &types.Header{
		ParentHash:  g.generateRandomHash(),
		UncleHash:   g.generateRandomHash(),
		Coinbase:    g.generateRandomAddress(),
		Root:        g.generateRandomHash(),
		TxHash:      g.generateRandomHash(),
		ReceiptHash: g.generateRandomHash(),
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(int64(g.rng.Uint64())),
		Number:      big.NewInt(int64(g.rng.Uint32()) % int64(g.config.ETH.MaxBlockNumber)),
		GasLimit:    uint64(g.rng.Uint32()) % g.config.ETH.MaxGasLimit,
		GasUsed:     uint64(g.rng.Uint32()) % g.config.ETH.MaxGasLimit,
		Time:        uint64(time.Now().Unix()),
		Extra:       make([]byte, g.rng.Intn(32)),
		MixDigest:   g.generateRandomHash(),
		Nonce:       types.BlockNonce{},
		BaseFee:     big.NewInt(int64(g.rng.Uint64()) % int64(g.config.ETH.MaxGasPrice)),
	}
}

func (g *ETHGenerator) generateRandomBody() *types.Body {
	txCount := g.rng.Intn(5) // Reduce transaction count
	txs := make([]*types.Transaction, 0, txCount)
	
	for i := 0; i < txCount; i++ {
		tx, err := g.generateRandomTransaction()
		if err == nil && tx != nil {
			txs = append(txs, tx)
		}
	}
	
	return &types.Body{
		Transactions: txs,
		Uncles:       []*types.Header{}, // Empty uncles for simplicity
	}
}

func (g *ETHGenerator) generateRandomBlock() *types.Block {
	header := g.generateRandomHeader()
	
	// Create empty body to avoid nil pointer issues
	body := &types.Body{
		Transactions: []*types.Transaction{},
		Uncles:       []*types.Header{},
	}
	
	// Create block with proper parameters - use empty receipts and withdrawals
	receipts := types.Receipts{}
	return types.NewBlock(header, body, receipts, nil)
}

func (g *ETHGenerator) generateRandomReceipt() *types.Receipt {
	return &types.Receipt{
		Type:              uint8(g.rng.Intn(3)),
		PostState:         make([]byte, 32),
		Status:            uint64(g.rng.Intn(2)),
		CumulativeGasUsed: uint64(g.rng.Uint32()) % g.config.ETH.MaxGasLimit,
		Bloom:             types.Bloom{},
		Logs:              []*types.Log{}, // Empty logs for simplicity
		TxHash:            g.generateRandomHash(),
		ContractAddress:   g.generateRandomAddress(),
		GasUsed:           uint64(g.rng.Uint32()) % g.config.ETH.MaxGasLimit,
		BlockHash:         g.generateRandomHash(),
		BlockNumber:       big.NewInt(int64(g.rng.Uint32()) % int64(g.config.ETH.MaxBlockNumber)),
		TransactionIndex:  uint(g.rng.Intn(100)),
	}
}

// GenerateMalformedMessage generates intentionally malformed messages for testing
func (g *ETHGenerator) GenerateMalformedMessage() ([]byte, error) {
	// Generate various types of malformed messages
	malformedTypes := []func() ([]byte, error){
		g.generateTruncatedMessage,
		g.generateOversizedMessage,
		g.generateInvalidRLPMessage,
		g.generateMissingFieldsMessage,
		g.generateExtraFieldsMessage,
	}
	
	generatorIndex := g.rng.Intn(len(malformedTypes))
	return malformedTypes[generatorIndex]()
}

func (g *ETHGenerator) generateTruncatedMessage() ([]byte, error) {
	// Generate a normal message and truncate it
	normalMsg, err := g.GenerateRandomMessage()
	if err != nil {
		return nil, err
	}
	
	if len(normalMsg) > 1 {
		truncateAt := g.rng.Intn(len(normalMsg)-1) + 1
		return normalMsg[:truncateAt], nil
	}
	
	return normalMsg, nil
}

func (g *ETHGenerator) generateOversizedMessage() ([]byte, error) {
	// Generate a message with excessive data
	excessiveData := make([]byte, 1024*1024) // 1MB of random data
	rand.Read(excessiveData)
	return rlp.EncodeToBytes(excessiveData)
}

func (g *ETHGenerator) generateInvalidRLPMessage() ([]byte, error) {
	// Generate invalid RLP structures
	invalidPatterns := [][]byte{
		{0xc0, 0x80}, // Empty list followed by empty string
		{0x85, 0x01, 0x02}, // Claims 5 bytes but only has 2
		{0xf8, 0x00}, // Long list with zero length
		{0xbf, 0xff, 0xff}, // Invalid long string
	}
	
	pattern := invalidPatterns[g.rng.Intn(len(invalidPatterns))]
	return pattern, nil
}

func (g *ETHGenerator) generateMissingFieldsMessage() ([]byte, error) {
	// Generate a status message with missing fields
	incompleteStatus := struct {
		ProtocolVersion uint32
		// Missing other required fields
	}{
		ProtocolVersion: uint32(g.config.ETH.TargetProtocolVersion),
	}
	
	return rlp.EncodeToBytes(incompleteStatus)
}

func (g *ETHGenerator) generateExtraFieldsMessage() ([]byte, error) {
	// Generate a status message with extra fields
	extendedStatus := struct {
		ProtocolVersion uint32
		NetworkID       uint64
		TD              *big.Int
		BestHash        common.Hash
		GenesisHash     common.Hash
		ExtraField1     []byte // Extra field
		ExtraField2     uint64 // Another extra field
	}{
		ProtocolVersion: uint32(g.config.ETH.TargetProtocolVersion),
		NetworkID:       uint64(g.rng.Uint32()),
		TD:              big.NewInt(int64(g.rng.Uint64())),
		BestHash:        g.generateRandomHash(),
		GenesisHash:     g.generateRandomHash(),
		ExtraField1:     make([]byte, 32),
		ExtraField2:     uint64(g.rng.Uint64()),
	}
	
	return rlp.EncodeToBytes(extendedStatus)
}