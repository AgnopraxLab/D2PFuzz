package p2p

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

)

// TestNewManager tests the creation of P2P Manager
func TestNewManager(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       10,
		ListenPort:     30303,
		BootstrapNodes: []string{"enode://test@127.0.0.1:30303"},
	}

	manager, err := NewManager(config, mockLogger)

	assert.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, config, manager.config)
	assert.Equal(t, mockLogger, manager.logger)
	assert.NotNil(t, manager.client)
	assert.NotNil(t, manager.ethHandler)
	assert.NotNil(t, manager.snapHandler)
	assert.NotNil(t, manager.sessions)
}

// TestConfig_Structure tests the Config structure
func TestConfig_Structure(t *testing.T) {
	config := &Config{
		MaxPeers:   25,
		ListenPort: 30304,
		BootstrapNodes: []string{
			"enode://node1@192.168.1.1:30303",
			"enode://node2@192.168.1.2:30303",
		},
	}

	assert.Equal(t, 25, config.MaxPeers)
	assert.Equal(t, 30304, config.ListenPort)
	assert.Len(t, config.BootstrapNodes, 2)
	assert.Equal(t, "enode://node1@192.168.1.1:30303", config.BootstrapNodes[0])
	assert.Equal(t, "enode://node2@192.168.1.2:30303", config.BootstrapNodes[1])
}

// TestManager_GetStats tests getting P2P statistics
func TestManager_GetStats(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       15,
		ListenPort:     30305,
		BootstrapNodes: []string{"enode://test@127.0.0.1:30303"},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	stats := manager.GetStats()

	assert.NotNil(t, stats)
	assert.Equal(t, 0, stats["connected_peers"])
	assert.Equal(t, 15, stats["max_peers"])
	assert.Equal(t, 30305, stats["listen_port"])
	assert.Equal(t, 1, stats["bootstrap_nodes"])
}

// TestManager_GetFuzzingStats tests getting fuzzing statistics
func TestManager_GetFuzzingStats(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       20,
		ListenPort:     30306,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	fuzzStats := manager.GetFuzzingStats()

	assert.NotNil(t, fuzzStats)
	assert.Equal(t, 0, fuzzStats.TotalConnections)
	assert.Equal(t, 0, fuzzStats.ActiveConnections)
	assert.Equal(t, 0, fuzzStats.MessagesSent)
	assert.Equal(t, 0, fuzzStats.MessagesReceived)
	assert.Equal(t, 0, fuzzStats.ErrorsEncountered)
	assert.Equal(t, time.Duration(0), fuzzStats.Uptime)
	assert.Contains(t, fuzzStats.ProtocolsSupported, "eth")
	assert.Contains(t, fuzzStats.ProtocolsSupported, "snap")
}

// TestFuzzingStats_Structure tests the FuzzingStats structure
func TestFuzzingStats_Structure(t *testing.T) {
	stats := &FuzzingStats{
		TotalConnections:   5,
		ActiveConnections:  3,
		MessagesSent:       100,
		MessagesReceived:   85,
		ErrorsEncountered:  2,
		Uptime:             time.Hour * 2,
		ProtocolsSupported: []string{"eth", "snap", "les"},
	}

	assert.Equal(t, 5, stats.TotalConnections)
	assert.Equal(t, 3, stats.ActiveConnections)
	assert.Equal(t, 100, stats.MessagesSent)
	assert.Equal(t, 85, stats.MessagesReceived)
	assert.Equal(t, 2, stats.ErrorsEncountered)
	assert.Equal(t, time.Hour*2, stats.Uptime)
	assert.Len(t, stats.ProtocolsSupported, 3)
	assert.Contains(t, stats.ProtocolsSupported, "eth")
	assert.Contains(t, stats.ProtocolsSupported, "snap")
	assert.Contains(t, stats.ProtocolsSupported, "les")
}

// TestManager_Start tests starting the P2P manager
func TestManager_Start(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:   5,
		ListenPort: 30307,
		BootstrapNodes: []string{
			"enode://invalid@127.0.0.1:30303", // Invalid node for testing
		},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	// Start should not return an error even if connections fail
	err = manager.Start()
	assert.NoError(t, err)

	// Give some time for connection attempts
	time.Sleep(200 * time.Millisecond)

	// Verify logger was called with appropriate messages
	mockLogger.AssertCalled(t, "Info", mock.MatchedBy(func(msg string) bool {
		return msg == "Starting P2P manager with config: max_peers=%d, listen_port=%d"
	}), mock.Anything, mock.Anything)
}

// TestManager_Stop tests stopping the P2P manager
func TestManager_Stop(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       5,
		ListenPort:     30308,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)

	// Start and then stop
	err = manager.Start()
	assert.NoError(t, err)

	err = manager.Stop()
	assert.NoError(t, err)

	// Verify stop message was logged
	mockLogger.AssertCalled(t, "Info", "Stopping P2P manager", mock.Anything)
}

// TestManager_ConnectToNode tests connecting to a specific node
func TestManager_ConnectToNode(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       5,
		ListenPort:     30309,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	// Test connecting to an invalid node (should not return error immediately)
	err = manager.ConnectToNode("enode://invalid@127.0.0.1:30303")
	assert.NoError(t, err)

	// Give some time for connection attempt
	time.Sleep(100 * time.Millisecond)

	// Verify connection attempt was logged
	mockLogger.AssertCalled(t, "Info", mock.Anything, mock.Anything)
}

// TestManager_GetConnectedPeers tests getting connected peers from manager
func TestManager_GetConnectedPeers(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       5,
		ListenPort:     30310,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	// Initially should have no connected peers
	peers := manager.GetConnectedPeers()
	assert.Empty(t, peers)
}

// TestManager_SendMessages tests sending messages through manager
func TestManager_SendMessages(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       5,
		ListenPort:     30311,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	// Create a fake peer ID using enode.ID
	var fakePeerID enode.ID
	copy(fakePeerID[:], []byte{1, 2, 3, 4})

	// Test sending eth message (should fail since no peer is connected)
	err = manager.SendEthMessage(fakePeerID, 0x00, nil)
	assert.Error(t, err)

	// Test sending snap message (should fail since no peer is connected)
	err = manager.SendSnapMessage(fakePeerID, 0x00, nil)
	assert.Error(t, err)
}

// TestManager_DisconnectPeer tests disconnecting a peer through manager
func TestManager_DisconnectPeer(t *testing.T) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       5,
		ListenPort:     30312,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	assert.NoError(t, err)
	defer manager.Stop()

	// Create a fake peer ID using enode.ID
	var fakePeerID enode.ID
	copy(fakePeerID[:], []byte{1, 2, 3, 4})

	// Test disconnecting non-existent peer (should return error)
	err = manager.DisconnectPeer(fakePeerID)
	assert.Error(t, err)
}

// BenchmarkNewManager benchmarks creating a new P2P manager
func BenchmarkNewManager(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       10,
		ListenPort:     30313,
		BootstrapNodes: []string{"enode://test@127.0.0.1:30303"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager, err := NewManager(config, mockLogger)
		if err != nil {
			b.Fatal(err)
		}
		manager.Stop()
	}
}

// BenchmarkGetStats benchmarks getting P2P statistics
func BenchmarkGetStats(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       10,
		ListenPort:     30314,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetStats()
	}
}

// BenchmarkGetFuzzingStats benchmarks getting fuzzing statistics
func BenchmarkGetFuzzingStats(b *testing.B) {
	mockLogger := &MockLogger{}
	mockLogger.On("Info", mock.Anything, mock.Anything).Return()

	config := &Config{
		MaxPeers:       10,
		ListenPort:     30315,
		BootstrapNodes: []string{},
	}

	manager, err := NewManager(config, mockLogger)
	if err != nil {
		b.Fatal(err)
	}
	defer manager.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetFuzzingStats()
	}
}