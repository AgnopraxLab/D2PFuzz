package p2p

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"D2PFuzz/fuzzer"
)

// TestNewSnapProtocolHandler tests the creation of SnapProtocolHandler
func TestNewSnapProtocolHandler(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	assert.NotNil(t, handler)
	assert.Equal(t, client, handler.client)
	assert.Equal(t, mockLogger, handler.logger)
}

// TestGetAccountRangePacket_Structure tests the GetAccountRangePacket structure
func TestGetAccountRangePacket_Structure(t *testing.T) {
	packet := &GetAccountRangePacket{
		ID:     12345,
		Root:   common.HexToHash("0x1111"),
		Origin: common.HexToHash("0x2222"),
		Limit:  common.HexToHash("0x3333"),
		Bytes:  1024,
	}

	assert.Equal(t, uint64(12345), packet.ID)
	assert.Equal(t, common.HexToHash("0x1111"), packet.Root)
	assert.Equal(t, common.HexToHash("0x2222"), packet.Origin)
	assert.Equal(t, common.HexToHash("0x3333"), packet.Limit)
	assert.Equal(t, uint64(1024), packet.Bytes)
}

// TestAccountRangePacket_Structure tests the AccountRangePacket structure
func TestAccountRangePacket_Structure(t *testing.T) {
	accounts := []*AccountData{
		{
			Hash: common.HexToHash("0xaaaa"),
			Body: []byte{1, 2, 3, 4},
		},
		{
			Hash: common.HexToHash("0xbbbb"),
			Body: []byte{5, 6, 7, 8},
		},
	}

	proof := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	}

	packet := &AccountRangePacket{
		ID:       54321,
		Accounts: accounts,
		Proof:    proof,
	}

	assert.Equal(t, uint64(54321), packet.ID)
	assert.Len(t, packet.Accounts, 2)
	assert.Equal(t, common.HexToHash("0xaaaa"), packet.Accounts[0].Hash)
	assert.Equal(t, []byte{1, 2, 3, 4}, packet.Accounts[0].Body)
	assert.Equal(t, common.HexToHash("0xbbbb"), packet.Accounts[1].Hash)
	assert.Equal(t, []byte{5, 6, 7, 8}, packet.Accounts[1].Body)
	assert.Len(t, packet.Proof, 2)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, packet.Proof[0])
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, packet.Proof[1])
}

// TestAccountData_Structure tests the AccountData structure
func TestAccountData_Structure(t *testing.T) {
	accountData := &AccountData{
		Hash: common.HexToHash("0xdeadbeef"),
		Body: []byte{0xde, 0xad, 0xbe, 0xef},
	}

	assert.Equal(t, common.HexToHash("0xdeadbeef"), accountData.Hash)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, accountData.Body)
}

// TestGetStorageRangesPacket_Structure tests the GetStorageRangesPacket structure
func TestGetStorageRangesPacket_Structure(t *testing.T) {
	accounts := []common.Hash{
		common.HexToHash("0x1111"),
		common.HexToHash("0x2222"),
	}

	packet := &GetStorageRangesPacket{
		ID:       98765,
		Root:     common.HexToHash("0xroot"),
		Accounts: accounts,
		Origin:   common.HexToHash("0xorigin"),
		Limit:    common.HexToHash("0xlimit"),
		Bytes:    2048,
	}

	assert.Equal(t, uint64(98765), packet.ID)
	assert.Equal(t, common.HexToHash("0xroot"), packet.Root)
	assert.Len(t, packet.Accounts, 2)
	assert.Equal(t, common.HexToHash("0x1111"), packet.Accounts[0])
	assert.Equal(t, common.HexToHash("0x2222"), packet.Accounts[1])
	assert.Equal(t, common.HexToHash("0xorigin"), packet.Origin)
	assert.Equal(t, common.HexToHash("0xlimit"), packet.Limit)
	assert.Equal(t, uint64(2048), packet.Bytes)
}

// TestStorageRangesPacket_Structure tests the StorageRangesPacket structure
func TestStorageRangesPacket_Structure(t *testing.T) {
	slots := [][]*StorageData{
		{
			{Hash: common.HexToHash("0x1111"), Body: []byte{1, 2}},
			{Hash: common.HexToHash("0x2222"), Body: []byte{3, 4}},
		},
		{
			{Hash: common.HexToHash("0x3333"), Body: []byte{5, 6}},
		},
	}

	proof := [][]byte{
		{0xaa, 0xbb},
		{0xcc, 0xdd},
	}

	packet := &StorageRangesPacket{
		ID:    11111,
		Slots: slots,
		Proof: proof,
	}

	assert.Equal(t, uint64(11111), packet.ID)
	assert.Len(t, packet.Slots, 2)
	assert.Len(t, packet.Slots[0], 2)
	assert.Len(t, packet.Slots[1], 1)
	assert.Equal(t, common.HexToHash("0x1111"), packet.Slots[0][0].Hash)
	assert.Equal(t, []byte{1, 2}, packet.Slots[0][0].Body)
	assert.Equal(t, common.HexToHash("0x3333"), packet.Slots[1][0].Hash)
	assert.Equal(t, []byte{5, 6}, packet.Slots[1][0].Body)
	assert.Len(t, packet.Proof, 2)
}

// TestStorageData_Structure tests the StorageData structure
func TestStorageData_Structure(t *testing.T) {
	storageData := &StorageData{
		Hash: common.HexToHash("0xcafebabe"),
		Body: []byte{0xca, 0xfe, 0xba, 0xbe},
	}

	assert.Equal(t, common.HexToHash("0xcafebabe"), storageData.Hash)
	assert.Equal(t, []byte{0xca, 0xfe, 0xba, 0xbe}, storageData.Body)
}

// TestGetByteCodesPacket_Structure tests the GetByteCodesPacket structure
func TestGetByteCodesPacket_Structure(t *testing.T) {
	hashes := []common.Hash{
		common.HexToHash("0xcode1"),
		common.HexToHash("0xcode2"),
		common.HexToHash("0xcode3"),
	}

	packet := &GetByteCodesPacket{
		ID:     22222,
		Hashes: hashes,
		Bytes:  4096,
	}

	assert.Equal(t, uint64(22222), packet.ID)
	assert.Len(t, packet.Hashes, 3)
	assert.Equal(t, common.HexToHash("0xcode1"), packet.Hashes[0])
	assert.Equal(t, common.HexToHash("0xcode2"), packet.Hashes[1])
	assert.Equal(t, common.HexToHash("0xcode3"), packet.Hashes[2])
	assert.Equal(t, uint64(4096), packet.Bytes)
}

// TestByteCodesPacket_Structure tests the ByteCodesPacket structure
func TestByteCodesPacket_Structure(t *testing.T) {
	codes := [][]byte{
		{0x60, 0x80, 0x60, 0x40}, // Sample bytecode
		{0x60, 0x00, 0x35},       // Another sample
	}

	packet := &ByteCodesPacket{
		ID:    33333,
		Codes: codes,
	}

	assert.Equal(t, uint64(33333), packet.ID)
	assert.Len(t, packet.Codes, 2)
	assert.Equal(t, []byte{0x60, 0x80, 0x60, 0x40}, packet.Codes[0])
	assert.Equal(t, []byte{0x60, 0x00, 0x35}, packet.Codes[1])
}

// TestGetTrieNodesPacket_Structure tests the GetTrieNodesPacket structure
func TestGetTrieNodesPacket_Structure(t *testing.T) {
	paths := []TrieNodePathSet{
		{[]byte{0x01, 0x02}, []byte{0x03, 0x04}},
		{[]byte{0x05, 0x06}},
	}

	packet := &GetTrieNodesPacket{
		ID:    44444,
		Root:  common.HexToHash("0xtrie"),
		Paths: paths,
		Bytes: 8192,
	}

	assert.Equal(t, uint64(44444), packet.ID)
	assert.Equal(t, common.HexToHash("0xtrie"), packet.Root)
	assert.Len(t, packet.Paths, 2)
	assert.Len(t, packet.Paths[0], 2)
	assert.Len(t, packet.Paths[1], 1)
	assert.Equal(t, []byte{0x01, 0x02}, packet.Paths[0][0])
	assert.Equal(t, []byte{0x03, 0x04}, packet.Paths[0][1])
	assert.Equal(t, []byte{0x05, 0x06}, packet.Paths[1][0])
	assert.Equal(t, uint64(8192), packet.Bytes)
}

// TestTrieNodesPacket_Structure tests the TrieNodesPacket structure
func TestTrieNodesPacket_Structure(t *testing.T) {
	nodes := [][]byte{
		{0xf8, 0x51, 0x80}, // Sample trie node
		{0xe2, 0x20, 0x01}, // Another sample
	}

	packet := &TrieNodesPacket{
		ID:    55555,
		Nodes: nodes,
	}

	assert.Equal(t, uint64(55555), packet.ID)
	assert.Len(t, packet.Nodes, 2)
	assert.Equal(t, []byte{0xf8, 0x51, 0x80}, packet.Nodes[0])
	assert.Equal(t, []byte{0xe2, 0x20, 0x01}, packet.Nodes[1])
}

// TestSnapProtocolHandler_CreateFuzzedAccountRangeRequest tests creating fuzzed account range requests
func TestSnapProtocolHandler_CreateFuzzedAccountRangeRequest(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	// Test creating multiple fuzzed requests
	for i := uint64(1); i <= 5; i++ {
		req := handler.CreateFuzzedAccountRangeRequest(i)
		assert.NotNil(t, req)
		assert.Equal(t, i, req.ID)
		assert.NotEqual(t, common.Hash{}, req.Root)
		assert.True(t, req.Bytes > 0)
	}
}

// TestSnapProtocolHandler_CreateFuzzedStorageRangesRequest tests creating fuzzed storage ranges requests
func TestSnapProtocolHandler_CreateFuzzedStorageRangesRequest(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	// Test creating multiple fuzzed requests
	for i := uint64(10); i <= 15; i++ {
		req := handler.CreateFuzzedStorageRangesRequest(i)
		assert.NotNil(t, req)
		assert.Equal(t, i, req.ID)
		assert.NotEqual(t, common.Hash{}, req.Root)
		assert.True(t, len(req.Accounts) > 0)
		assert.True(t, req.Bytes > 0)
	}
}

// TestSnapProtocolHandler_CreateFuzzedByteCodesRequest tests creating fuzzed bytecode requests
func TestSnapProtocolHandler_CreateFuzzedByteCodesRequest(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	// Test creating multiple fuzzed requests
	for i := uint64(20); i <= 25; i++ {
		req := handler.CreateFuzzedByteCodesRequest(i)
		assert.NotNil(t, req)
		assert.Equal(t, i, req.ID)
		assert.True(t, len(req.Hashes) > 0)
		assert.True(t, req.Bytes > 0)
	}
}

// TestSnapProtocolHandler_CreateFuzzedTrieNodesRequest tests creating fuzzed trie nodes requests
func TestSnapProtocolHandler_CreateFuzzedTrieNodesRequest(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	assert.NoError(t, err)
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	// Test creating multiple fuzzed requests
	for i := uint64(30); i <= 35; i++ {
		req := handler.CreateFuzzedTrieNodesRequest(i)
		assert.NotNil(t, req)
		assert.Equal(t, i, req.ID)
		assert.NotEqual(t, common.Hash{}, req.Root)
		assert.True(t, len(req.Paths) > 0)
		assert.True(t, req.Bytes > 0)
	}
}

// TestSnapMessageCodes tests the Snap protocol message codes
func TestSnapMessageCodes(t *testing.T) {
	assert.Equal(t, 0x00, GetAccountRangeMsg)
	assert.Equal(t, 0x01, AccountRangeMsg)
	assert.Equal(t, 0x02, GetStorageRangesMsg)
	assert.Equal(t, 0x03, StorageRangesMsg)
	assert.Equal(t, 0x04, GetByteCodesMsg)
	assert.Equal(t, 0x05, ByteCodesMsg)
	assert.Equal(t, 0x06, GetTrieNodesMsg)
	assert.Equal(t, 0x07, TrieNodesMsg)
}

// BenchmarkCreateFuzzedAccountRangeRequest benchmarks creating fuzzed account range requests
func BenchmarkCreateFuzzedAccountRangeRequest(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.CreateFuzzedAccountRangeRequest(uint64(i))
	}
}

// BenchmarkCreateFuzzedStorageRangesRequest benchmarks creating fuzzed storage ranges requests
func BenchmarkCreateFuzzedStorageRangesRequest(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := fuzzer.NewFuzzClient(mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	handler := NewSnapProtocolHandler(client, mockLogger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.CreateFuzzedStorageRangesRequest(uint64(i))
	}
}