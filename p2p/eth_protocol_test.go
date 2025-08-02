package p2p

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"D2PFuzz/fuzzer"
)

// TestNewEthProtocolHandler tests the creation of EthProtocolHandler
func TestNewEthProtocolHandler(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewEthProtocolHandler(client, mockLogger)

	assert.NotNil(t, handler)
	assert.Equal(t, client, handler.client)
	assert.Equal(t, mockLogger, handler.logger)
}

// TestStatusData_Structure tests the StatusData structure
func TestStatusData_Structure(t *testing.T) {
	status := &StatusData{
		ProtocolVersion: 68,
		NetworkID:       1,
		TD:              big.NewInt(1000000),
		BestHash:        common.HexToHash("0x1234567890abcdef"),
		GenesisHash:     common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
		ForkID: ForkID{
			Hash: [4]byte{0x01, 0x02, 0x03, 0x04},
			Next: 12345,
		},
	}

	assert.Equal(t, uint32(68), status.ProtocolVersion)
	assert.Equal(t, uint64(1), status.NetworkID)
	assert.Equal(t, big.NewInt(1000000), status.TD)
	assert.Equal(t, common.HexToHash("0x1234567890abcdef"), status.BestHash)
	assert.Equal(t, common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"), status.GenesisHash)
	assert.Equal(t, [4]byte{0x01, 0x02, 0x03, 0x04}, status.ForkID.Hash)
	assert.Equal(t, uint64(12345), status.ForkID.Next)
}

// TestForkID_Structure tests the ForkID structure
func TestForkID_Structure(t *testing.T) {
	forkID := ForkID{
		Hash: [4]byte{0xaa, 0xbb, 0xcc, 0xdd},
		Next: 54321,
	}

	assert.Equal(t, [4]byte{0xaa, 0xbb, 0xcc, 0xdd}, forkID.Hash)
	assert.Equal(t, uint64(54321), forkID.Next)
}

// TestNewBlockHashesData_Structure tests the NewBlockHashesData structure
func TestNewBlockHashesData_Structure(t *testing.T) {
	newBlockHashes := NewBlockHashesData{
		{
			Hash:   common.HexToHash("0x1111"),
			Number: 100,
		},
		{
			Hash:   common.HexToHash("0x2222"),
			Number: 101,
		},
	}

	assert.Len(t, newBlockHashes, 2)
	assert.Equal(t, common.HexToHash("0x1111"), newBlockHashes[0].Hash)
	assert.Equal(t, uint64(100), newBlockHashes[0].Number)
	assert.Equal(t, common.HexToHash("0x2222"), newBlockHashes[1].Hash)
	assert.Equal(t, uint64(101), newBlockHashes[1].Number)
}

// TestGetBlockHeadersData_Structure tests the GetBlockHeadersData structure
func TestGetBlockHeadersData_Structure(t *testing.T) {
	// Test with hash origin
	headerReq1 := &GetBlockHeadersData{
		Origin: HashOrNumber{
			Hash: common.HexToHash("0x1234"),
		},
		Amount:  10,
		Skip:    0,
		Reverse: false,
	}

	assert.Equal(t, common.HexToHash("0x1234"), headerReq1.Origin.Hash)
	assert.Equal(t, uint64(0), headerReq1.Origin.Number)
	assert.Equal(t, uint64(10), headerReq1.Amount)
	assert.Equal(t, uint64(0), headerReq1.Skip)
	assert.False(t, headerReq1.Reverse)

	// Test with number origin
	headerReq2 := &GetBlockHeadersData{
		Origin: HashOrNumber{
			Number: 12345,
		},
		Amount:  5,
		Skip:    1,
		Reverse: true,
	}

	assert.Equal(t, common.Hash{}, headerReq2.Origin.Hash)
	assert.Equal(t, uint64(12345), headerReq2.Origin.Number)
	assert.Equal(t, uint64(5), headerReq2.Amount)
	assert.Equal(t, uint64(1), headerReq2.Skip)
	assert.True(t, headerReq2.Reverse)
}

// TestHashOrNumber_Structure tests the HashOrNumber structure
func TestHashOrNumber_Structure(t *testing.T) {
	// Test hash-based
	hashOrNum1 := HashOrNumber{
		Hash: common.HexToHash("0xabcd"),
	}
	assert.Equal(t, common.HexToHash("0xabcd"), hashOrNum1.Hash)
	assert.Equal(t, uint64(0), hashOrNum1.Number)

	// Test number-based
	hashOrNum2 := HashOrNumber{
		Number: 98765,
	}
	assert.Equal(t, common.Hash{}, hashOrNum2.Hash)
	assert.Equal(t, uint64(98765), hashOrNum2.Number)
}

// TestNewBlockData_Structure tests the NewBlockData structure
func TestNewBlockData_Structure(t *testing.T) {
	// Create a mock block header
	header := &types.Header{
		Number:      big.NewInt(100),
		ParentHash:  common.HexToHash("0x1111"),
		Root:        common.HexToHash("0x2222"),
		TxHash:      common.HexToHash("0x3333"),
		ReceiptHash: common.HexToHash("0x4444"),
		GasLimit:    8000000,
		GasUsed:     5000000,
		Time:        1234567890,
	}

	// Create a mock block
	body := &types.Body{}
	block := types.NewBlock(header, body, nil, nil)

	newBlockData := &NewBlockData{
		Block: block,
		TD:    big.NewInt(2000000),
	}

	assert.Equal(t, block, newBlockData.Block)
	assert.Equal(t, big.NewInt(2000000), newBlockData.TD)
	assert.Equal(t, big.NewInt(100), newBlockData.Block.Number())
}

// TestEthProtocolHandler_CreateFuzzedStatusMessage tests creating fuzzed status messages
func TestEthProtocolHandler_CreateFuzzedStatusMessage(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewEthProtocolHandler(client, mockLogger)

	// Test creating multiple fuzzed status messages
	for i := 0; i < 5; i++ {
		status := handler.CreateFuzzedStatusMessage()
		assert.NotNil(t, status)
		assert.NotNil(t, status.TD)
		assert.True(t, status.TD.Cmp(big.NewInt(0)) >= 0)
		assert.NotEqual(t, common.Hash{}, status.BestHash)
		assert.NotEqual(t, common.Hash{}, status.GenesisHash)
	}
}

// TestEthProtocolHandler_CreateFuzzedTransactions tests creating fuzzed transactions
func TestEthProtocolHandler_CreateFuzzedTransactions(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewEthProtocolHandler(client, mockLogger)

	// Test creating different numbers of transactions
	testCases := []int{0, 1, 5, 10}
	for _, count := range testCases {
		txs := handler.CreateFuzzedTransactions(count)
		assert.Len(t, txs, count)

		// Verify each transaction has valid properties
		for _, tx := range txs {
			assert.NotNil(t, tx)
			assert.NotNil(t, tx.Value())
			assert.NotNil(t, tx.GasPrice())
			assert.True(t, tx.Gas() > 0)
		}
	}
}

// TestEthMessageCodes tests the Ethereum protocol message codes
func TestEthMessageCodes(t *testing.T) {
	assert.Equal(t, 0x00, StatusMsg)
	assert.Equal(t, 0x01, NewBlockHashesMsg)
	assert.Equal(t, 0x02, TransactionsMsg)
	assert.Equal(t, 0x03, GetBlockHeadersMsg)
	assert.Equal(t, 0x04, BlockHeadersMsg)
	assert.Equal(t, 0x05, GetBlockBodiesMsg)
	assert.Equal(t, 0x06, BlockBodiesMsg)
	assert.Equal(t, 0x07, NewBlockMsg)
	assert.Equal(t, 0x08, NewPooledTransactionHashesMsg)
	assert.Equal(t, 0x09, GetPooledTransactionsMsg)
	assert.Equal(t, 0x0a, PooledTransactionsMsg)
	assert.Equal(t, 0x0f, GetReceiptsMsg)
	assert.Equal(t, 0x10, ReceiptsMsg)
	assert.Equal(t, 0x11, BlockRangeUpdateMsg)
}

// BenchmarkCreateFuzzedStatusMessage benchmarks creating fuzzed status messages
func BenchmarkCreateFuzzedStatusMessage(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	handler := NewEthProtocolHandler(client, mockLogger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.CreateFuzzedStatusMessage()
	}
}

// BenchmarkCreateFuzzedTransactions benchmarks creating fuzzed transactions
func BenchmarkCreateFuzzedTransactions(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	handler := NewEthProtocolHandler(client, mockLogger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.CreateFuzzedTransactions(5)
	}
}
