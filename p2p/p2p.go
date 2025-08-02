package p2p

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
)

// Config represents P2P configuration
type Config struct {
	MaxPeers       int      `yaml:"max_peers"`
	ListenPort     int      `yaml:"listen_port"`
	BootstrapNodes []string `yaml:"bootstrap_nodes"`
}

// Manager manages P2P connections and fuzzing operations
type Manager struct {
	client      *fuzzer.FuzzClient
	ethHandler  *EthProtocolHandler
	snapHandler *SnapProtocolHandler
	logger      fuzzer.Logger
	config      *Config
	sessions    map[enode.ID]*FuzzingSession
}

// NewManager creates a new P2P manager
func NewManager(config *Config, logger fuzzer.Logger) (*Manager, error) {
	client, err := fuzzer.NewFuzzClient(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuzz client: %w", err)
	}

	ethHandler := NewEthProtocolHandler(client, logger)
	snapHandler := NewSnapProtocolHandler(client, logger)

	return &Manager{
		client:      client,
		ethHandler:  ethHandler,
		snapHandler: snapHandler,
		logger:      logger,
		config:      config,
		sessions:    make(map[enode.ID]*FuzzingSession),
	}, nil
}

// Start starts the P2P manager
func (m *Manager) Start() error {
	m.logger.Info("Starting P2P manager with config: max_peers=%d, listen_port=%d",
		m.config.MaxPeers, m.config.ListenPort)

	// Connect to bootstrap nodes
	for _, nodeURL := range m.config.BootstrapNodes {
		go func(url string) {
			if err := m.ConnectToNode(url); err != nil {
				m.logger.Error("Failed to connect to bootstrap node %s: %v", url, err)
			}
		}(nodeURL)
		// Add small delay between connections
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// ConnectToNode connects to a specific node and starts fuzzing
func (m *Manager) ConnectToNode(nodeURL string) error {
	m.logger.Info("Connecting to node: %s", nodeURL)

	// Create a new fuzzing session
	session, err := NewFuzzingSession(m.logger)
	if err != nil {
		return fmt.Errorf("failed to create fuzzing session: %w", err)
	}

	// Connect and start fuzzing
	go func() {
		defer session.Close()
		if err := session.ConnectAndFuzz(nodeURL); err != nil {
			m.logger.Error("Fuzzing session failed for %s: %v", nodeURL, err)
		}
	}()

	return nil
}

// GetConnectedPeers returns a list of connected peer IDs
func (m *Manager) GetConnectedPeers() []enode.ID {
	return m.client.GetConnectedPeers()
}

// DisconnectPeer disconnects from a specific peer
func (m *Manager) DisconnectPeer(peerID enode.ID) error {
	return m.client.DisconnectPeer(peerID)
}

// SendEthMessage sends an Ethereum protocol message to a peer
func (m *Manager) SendEthMessage(peerID enode.ID, msgCode uint64, data interface{}) error {
	return m.client.SendEthMessage(peerID, msgCode, data)
}

// SendSnapMessage sends a Snap protocol message to a peer
func (m *Manager) SendSnapMessage(peerID enode.ID, msgCode uint64, data interface{}) error {
	return m.client.SendSnapMessage(peerID, msgCode, data)
}

// GetStats returns P2P statistics
func (m *Manager) GetStats() map[string]interface{} {
	connectedPeers := m.GetConnectedPeers()
	return map[string]interface{}{
		"connected_peers": len(connectedPeers),
		"max_peers":      m.config.MaxPeers,
		"listen_port":    m.config.ListenPort,
		"bootstrap_nodes": len(m.config.BootstrapNodes),
	}
}

// Stop stops the P2P manager and closes all connections
func (m *Manager) Stop() error {
	m.logger.Info("Stopping P2P manager")

	// Close all sessions
	for _, session := range m.sessions {
		session.Close()
	}

	// Close the client
	return m.client.Close()
}

// FuzzingStats represents fuzzing statistics
type FuzzingStats struct {
	TotalConnections    int           `json:"total_connections"`
	ActiveConnections   int           `json:"active_connections"`
	MessagesSent        int           `json:"messages_sent"`
	MessagesReceived    int           `json:"messages_received"`
	ErrorsEncountered   int           `json:"errors_encountered"`
	Uptime              time.Duration `json:"uptime"`
	ProtocolsSupported  []string      `json:"protocols_supported"`
}

// GetFuzzingStats returns detailed fuzzing statistics
func (m *Manager) GetFuzzingStats() *FuzzingStats {
	connectedPeers := m.GetConnectedPeers()
	return &FuzzingStats{
		TotalConnections:   len(m.sessions),
		ActiveConnections:  len(connectedPeers),
		MessagesSent:       0, // TODO: implement counters
		MessagesReceived:   0, // TODO: implement counters
		ErrorsEncountered:  0, // TODO: implement counters
		Uptime:             0, // TODO: implement uptime tracking
		ProtocolsSupported: []string{"eth", "snap"},
	}
}