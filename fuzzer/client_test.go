package fuzzer

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockLogger is a mock implementation of Logger interface
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.Called(msg, args)
}

// TestNewFuzzClient tests the creation of a new FuzzClient
func TestNewFuzzClient(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := NewFuzzClient(mockLogger)

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotNil(t, client.privateKey)
	assert.NotNil(t, client.localNode)
	assert.NotNil(t, client.peers)
	assert.NotNil(t, client.ctx)
	assert.NotNil(t, client.cancel)
	assert.Equal(t, mockLogger, client.logger)
}

// TestFuzzClient_GetConnectedPeers tests getting connected peers
func TestFuzzClient_GetConnectedPeers(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := NewFuzzClient(mockLogger)
	assert.NoError(t, err)

	// Initially should have no peers
	peers := client.GetConnectedPeers()
	assert.Empty(t, peers)

	// Add a mock peer with valid secp256k1 public key
	mockNode := enode.MustParse("enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303")
	mockPeer := &Peer{
		Node:      mockNode,
		Connected: time.Now(),
	}

	client.peersMu.Lock()
	client.peers[mockNode.ID()] = mockPeer
	client.peersMu.Unlock()

	// Should now have one peer
	peers = client.GetConnectedPeers()
	assert.Len(t, peers, 1)
	assert.Equal(t, mockNode.ID(), peers[0])
}

// TestFuzzClient_DisconnectPeer tests disconnecting a peer
func TestFuzzClient_DisconnectPeer(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything, mock.Anything).Return()

	client, err := NewFuzzClient(mockLogger)
	assert.NoError(t, err)

	// Test disconnecting non-existent peer with valid secp256k1 public key
	mockNode := enode.MustParse("enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303")
	err = client.DisconnectPeer(mockNode.ID())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "peer not found")
}

// TestFuzzClient_Close tests closing the client
func TestFuzzClient_Close(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := NewFuzzClient(mockLogger)
	assert.NoError(t, err)

	// Test closing
	err = client.Close()
	assert.NoError(t, err)

	// Context should be cancelled
	select {
	case <-client.ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Context was not cancelled")
	}
}

// TestPeer_Structure tests the Peer structure
func TestPeer_Structure(t *testing.T) {
	mockNode := enode.MustParse("enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303")
	connectedTime := time.Now()

	peer := &Peer{
		Node:      mockNode,
		Protocols: make(map[string]Protocol),
		Connected: connectedTime,
	}

	assert.Equal(t, mockNode, peer.Node)
	assert.NotNil(t, peer.Protocols)
	assert.Equal(t, connectedTime, peer.Connected)
}

// TestProtocol_Structure tests the Protocol structure
func TestProtocol_Structure(t *testing.T) {
	protocol := Protocol{
		Name:    "eth",
		Version: 68,
		Length:  17,
		Run: func(peer *Peer) error {
			return nil
		},
	}

	assert.Equal(t, "eth", protocol.Name)
	assert.Equal(t, uint(68), protocol.Version)
	assert.Equal(t, uint64(17), protocol.Length)
	assert.NotNil(t, protocol.Run)

	// Test running the protocol
	mockNode := enode.MustParse("enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@127.0.0.1:30303")
	mockPeer := &Peer{Node: mockNode}
	err := protocol.Run(mockPeer)
	assert.NoError(t, err)
}

// TestHelloMsg_Structure tests the HelloMsg structure
func TestHelloMsg_Structure(t *testing.T) {
	helloMsg := HelloMsg{
		Version:    5,
		Name:       "D2PFuzz",
		Caps:       []Cap{{Name: "eth", Version: 68}, {Name: "snap", Version: 1}},
		ListenPort: 30303,
		ID:         []byte{1, 2, 3, 4},
	}

	assert.Equal(t, uint64(5), helloMsg.Version)
	assert.Equal(t, "D2PFuzz", helloMsg.Name)
	assert.Len(t, helloMsg.Caps, 2)
	assert.Equal(t, "eth", helloMsg.Caps[0].Name)
	assert.Equal(t, uint(68), helloMsg.Caps[0].Version)
	assert.Equal(t, "snap", helloMsg.Caps[1].Name)
	assert.Equal(t, uint(1), helloMsg.Caps[1].Version)
	assert.Equal(t, uint64(30303), helloMsg.ListenPort)
	assert.Equal(t, []byte{1, 2, 3, 4}, helloMsg.ID)
}

// TestCap_Structure tests the Cap structure
func TestCap_Structure(t *testing.T) {
	cap := Cap{
		Name:    "eth",
		Version: 68,
	}

	assert.Equal(t, "eth", cap.Name)
	assert.Equal(t, uint(68), cap.Version)
}

// BenchmarkNewFuzzClient benchmarks the creation of FuzzClient
func BenchmarkNewFuzzClient(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := NewFuzzClient(mockLogger)
		if err != nil {
			b.Fatal(err)
		}
		client.Close()
	}
}

// BenchmarkGetConnectedPeers benchmarks getting connected peers
func BenchmarkGetConnectedPeers(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	client, err := NewFuzzClient(mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	// Add some mock peers
	for i := 0; i < 10; i++ {
		mockNode := enode.MustParse("enode://1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef@127.0.0.1:30303")
		mockPeer := &Peer{
			Node:      mockNode,
			Connected: time.Now(),
		}
		client.peersMu.Lock()
		client.peers[mockNode.ID()] = mockPeer
		client.peersMu.Unlock()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.GetConnectedPeers()
	}
}
