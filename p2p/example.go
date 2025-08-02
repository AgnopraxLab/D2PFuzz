package p2p

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
)

// FuzzingSession represents a fuzzing session
type FuzzingSession struct {
	client      *fuzzer.FuzzClient
	ethHandler  *EthProtocolHandler
	snapHandler *SnapProtocolHandler
	logger      fuzzer.Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewFuzzingSession creates a new fuzzing session
func NewFuzzingSession(logger fuzzer.Logger) (*FuzzingSession, error) {
	client, err := fuzzer.NewFuzzClient(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuzz client: %w", err)
	}

	ethHandler := NewEthProtocolHandler(client, logger)
	snapHandler := NewSnapProtocolHandler(client, logger)

	ctx, cancel := context.WithCancel(context.Background())

	return &FuzzingSession{
		client:      client,
		ethHandler:  ethHandler,
		snapHandler: snapHandler,
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// ConnectAndFuzz connects to a target node and performs fuzzing
func (fs *FuzzingSession) ConnectAndFuzz(nodeURL string) error {
	fs.logger.Info("Starting fuzzing session for node: %s", nodeURL)

	// Connect to the target peer
	peer, err := fs.client.ConnectToPeer(nodeURL)
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	peerID := peer.Node.ID()
	fs.logger.Info("Successfully connected to peer: %s", peerID)

	// Start message handling goroutine
	go fs.handleMessages(peerID)

	// Perform various fuzzing operations
	if err := fs.performEthFuzzing(peerID); err != nil {
		fs.logger.Error("Eth fuzzing failed: %v", err)
	}

	if err := fs.performSnapFuzzing(peerID); err != nil {
		fs.logger.Error("Snap fuzzing failed: %v", err)
	}

	// Keep the session alive for a while
	select {
	case <-fs.ctx.Done():
		fs.logger.Info("Fuzzing session cancelled")
	case <-time.After(30 * time.Second):
		fs.logger.Info("Fuzzing session completed")
	}

	return nil
}

// handleMessages handles incoming messages from peers
func (fs *FuzzingSession) handleMessages(peerID enode.ID) {
	for {
		select {
		case <-fs.ctx.Done():
			return
		default:
			// Try to receive a message with timeout
			msg, err := fs.client.ReceiveMessage(peerID)
			if err != nil {
				fs.logger.Debug("Failed to receive message: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Determine message type and handle accordingly
			if err := fs.handleMessage(peerID, msg); err != nil {
				fs.logger.Error("Failed to handle message: %v", err)
			}
			msg.Discard()
		}
	}
}

// handleMessage routes messages to appropriate handlers
func (fs *FuzzingSession) handleMessage(peerID enode.ID, msg *p2p.Msg) error {
	// Determine protocol based on message code
	// This is a simplified approach - in practice, you'd need proper protocol negotiation
	if msg.Code >= 0x10 && msg.Code < 0x20 {
		// Assume eth protocol messages
		adjustedMsg := *msg
		adjustedMsg.Code -= 0x10
		return fs.ethHandler.HandleMessage(peerID, &adjustedMsg)
	} else if msg.Code >= 0x20 && msg.Code < 0x30 {
		// Assume snap protocol messages
		adjustedMsg := *msg
		adjustedMsg.Code -= 0x20
		return fs.snapHandler.HandleMessage(peerID, &adjustedMsg)
	} else {
		// Handle devp2p base protocol messages
		fs.logger.Debug("Received devp2p message: code=%x", msg.Code)
		return nil
	}
}

// performEthFuzzing performs Ethereum protocol fuzzing
func (fs *FuzzingSession) performEthFuzzing(peerID enode.ID) error {
	fs.logger.Info("Starting Ethereum protocol fuzzing")

	// Send a status message
	status := fs.ethHandler.CreateFuzzedStatusMessage()
	if err := fs.ethHandler.SendStatus(peerID, status); err != nil {
		return fmt.Errorf("failed to send status: %w", err)
	}
	fs.logger.Info("Sent status message")

	// Wait a bit
	time.Sleep(1 * time.Second)

	// Send some transactions
	txs := fs.ethHandler.CreateFuzzedTransactions(5)
	if err := fs.ethHandler.SendTransactions(peerID, txs); err != nil {
		return fmt.Errorf("failed to send transactions: %w", err)
	}
	fs.logger.Info("Sent %d transactions", len(txs))

	// Request block headers
	headerQuery := &GetBlockHeadersData{
		Origin:  HashOrNumber{Number: 1},
		Amount:  10,
		Skip:    0,
		Reverse: false,
	}
	if err := fs.ethHandler.RequestBlockHeaders(peerID, headerQuery); err != nil {
		return fmt.Errorf("failed to request headers: %w", err)
	}
	fs.logger.Info("Requested block headers")

	return nil
}

// performSnapFuzzing performs Snap protocol fuzzing
func (fs *FuzzingSession) performSnapFuzzing(peerID enode.ID) error {
	fs.logger.Info("Starting Snap protocol fuzzing")

	// Request account range
	accountReq := fs.snapHandler.CreateFuzzedAccountRangeRequest(1)
	if err := fs.snapHandler.RequestAccountRange(peerID, accountReq); err != nil {
		return fmt.Errorf("failed to request account range: %w", err)
	}
	fs.logger.Info("Requested account range")

	// Wait a bit
	time.Sleep(1 * time.Second)

	// Request storage ranges
	storageReq := fs.snapHandler.CreateFuzzedStorageRangesRequest(2)
	if err := fs.snapHandler.RequestStorageRanges(peerID, storageReq); err != nil {
		return fmt.Errorf("failed to request storage ranges: %w", err)
	}
	fs.logger.Info("Requested storage ranges")

	// Request bytecodes
	bytecodeReq := fs.snapHandler.CreateFuzzedByteCodesRequest(3)
	if err := fs.snapHandler.RequestByteCodes(peerID, bytecodeReq); err != nil {
		return fmt.Errorf("failed to request bytecodes: %w", err)
	}
	fs.logger.Info("Requested bytecodes")

	// Request trie nodes
	trieReq := fs.snapHandler.CreateFuzzedTrieNodesRequest(4)
	if err := fs.snapHandler.RequestTrieNodes(peerID, trieReq); err != nil {
		return fmt.Errorf("failed to request trie nodes: %w", err)
	}
	fs.logger.Info("Requested trie nodes")

	return nil
}

// Close closes the fuzzing session
func (fs *FuzzingSession) Close() error {
	fs.cancel()
	return fs.client.Close()
}

// RunExample demonstrates how to use the fuzzing client
func RunExample() error {
	// Create logger
	logger := NewSimpleLogger(LogLevelInfo)

	// Create fuzzing session
	session, err := NewFuzzingSession(logger)
	if err != nil {
		return fmt.Errorf("failed to create fuzzing session: %w", err)
	}
	defer session.Close()

	// Connect and fuzz a target node
	// Replace with your actual node URL
	nodeURL := "enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303"

	if err := session.ConnectAndFuzz(nodeURL); err != nil {
		return fmt.Errorf("fuzzing failed: %w", err)
	}

	logger.Info("Fuzzing example completed successfully")
	return nil
}