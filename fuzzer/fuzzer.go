package fuzzer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// FuzzClient represents a P2P client for fuzzing Ethereum nodes
type FuzzClient struct {
	privateKey *ecdsa.PrivateKey
	localNode  *enode.LocalNode
	peers      map[enode.ID]*Peer
	peersMu    sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	logger     utils.Logger
	txFuzzer   *TxFuzzer // Transaction fuzzer integration
}

// Peer represents a connected peer
type Peer struct {
	Node      *enode.Node
	Conn      *rlpx.Conn
	RW        p2p.MsgReadWriter
	Protocols map[string]Protocol
	Connected time.Time
	mu        sync.RWMutex
}

// Protocol represents a supported protocol
type Protocol struct {
	Name    string
	Version uint
	Length  uint64
	Run     func(*Peer) error
}

// NewFuzzClient creates a new P2P fuzzing client
func NewFuzzClient(logger utils.Logger) (*FuzzClient, error) {
	// Generate a private key for this client
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &FuzzClient{
		privateKey: privateKey,
		peers:      make(map[enode.ID]*Peer),
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
	}, nil
}

func (f *FuzzClient) Start() {
	f.logger.Info("Fuzz client starting...")
	// Start listening for incoming connections
	f.logger.Info("Main Fuzz Strategy")
	// TODO: Implement fuzzing strategy
	f.logger.Info("Fuzz test is Complished")
}

// StartTxFuzzing starts transaction fuzzing with the given configuration
func (f *FuzzClient) StartTxFuzzing(cfg *TxFuzzConfig, accounts []config.Account) error {
	if f.txFuzzer != nil {
		return fmt.Errorf("transaction fuzzing is already running")
	}

	txFuzzer, err := NewTxFuzzer(cfg, accounts, f.logger)
	if err != nil {
		return fmt.Errorf("failed to create transaction fuzzer: %v", err)
	}

	f.txFuzzer = txFuzzer

	// Start transaction fuzzing in a separate goroutine
	go func() {
		if err := f.txFuzzer.Start(cfg); err != nil {
			f.logger.Error("Transaction fuzzing failed: %v", err)
		}
	}()

	f.logger.Info("Transaction fuzzing started")
	return nil
}

// StopTxFuzzing stops the transaction fuzzing process
func (f *FuzzClient) StopTxFuzzing() {
	if f.txFuzzer != nil {
		f.txFuzzer.Stop()
		f.txFuzzer = nil
		f.logger.Info("Transaction fuzzing stopped")
	}
}

// IsTxFuzzingActive returns true if transaction fuzzing is currently active
func (f *FuzzClient) IsTxFuzzingActive() bool {
	return f.txFuzzer != nil
}
