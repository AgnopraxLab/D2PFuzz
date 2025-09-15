package fuzzer

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"D2PFuzz/config"
	"D2PFuzz/mutation"
	"D2PFuzz/mutation/generators"
	"D2PFuzz/mutation/strategies"
	"D2PFuzz/utils"
)

// TransactionRecord records detailed information about each transaction
type TransactionRecord struct {
	Hash           common.Hash   `json:"hash"`
	From           common.Address `json:"from"`
	To             *common.Address `json:"to"`
	Value          *big.Int      `json:"value"`
	Gas            uint64        `json:"gas"`
	GasPrice       *big.Int      `json:"gasPrice"`
	GasFeeCap      *big.Int      `json:"gasFeeCap,omitempty"`
	GasTipCap      *big.Int      `json:"gasTipCap,omitempty"`
	Nonce          uint64        `json:"nonce"`
	Data           []byte        `json:"data"`
	TxType         uint8         `json:"txType"`
	SentTime       time.Time     `json:"sentTime"`
	MinedTime      *time.Time    `json:"minedTime,omitempty"`
	ConfirmedTime  *time.Time    `json:"confirmedTime,omitempty"`
	Status         string        `json:"status"` // pending, mined, failed, confirmed
	GasUsed        *uint64       `json:"gasUsed,omitempty"`
	BlockNumber    *uint64       `json:"blockNumber,omitempty"`
	Error          string        `json:"error,omitempty"`
	MutationUsed   bool          `json:"mutationUsed"`
	MutationType   string        `json:"mutationType,omitempty"`
}

// TxFuzzer represents a transaction fuzzer with mutation capabilities
type TxFuzzer struct {
	client         *ethclient.Client
	accounts       []config.Account
	chainID        *big.Int
	logger         utils.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	rng            *rand.Rand
	mutationConfig *mutation.MutationConfig
	ethGenerator   *generators.ETHGenerator
	ethMutator     *strategies.ETHMutator
	rlpMutator     *strategies.RLPMutator
	txRecords      map[common.Hash]*TransactionRecord
	recordsMutex   sync.RWMutex
	stats          *TxStats
	successTxHashes []string     // 成功发送的交易哈希值列表
	failedTxHashes  []string     // 发送失败的交易哈希值列表
	hashMutex       sync.RWMutex // 保护哈希值列表的互斥锁
}

// TxStats holds statistics about transaction fuzzing
type TxStats struct {
	TotalSent      int64     `json:"totalSent"`
	TotalMined     int64     `json:"totalMined"`
	TotalFailed    int64     `json:"totalFailed"`
	TotalPending   int64     `json:"totalPending"`
	MutationUsed   int64     `json:"mutationUsed"`
	RandomUsed     int64     `json:"randomUsed"`
	StartTime      time.Time `json:"startTime"`
	LastUpdateTime time.Time `json:"lastUpdateTime"`
	mutex          sync.RWMutex
}

// TxFuzzConfig holds configuration for transaction fuzzing
type TxFuzzConfig struct {
	RPCEndpoint     string
	ChainID         int64
	MaxGasPrice     *big.Int
	MaxGasLimit     uint64
	TxPerSecond     int
	FuzzDuration    time.Duration
	Seed            int64
	UseMutation     bool
	MutationRatio   float64 // 0.0-1.0, ratio of transactions using mutation vs random generation
	EnableTracking  bool
	OutputFile      string
	ConfirmBlocks   uint64 // Number of blocks to wait for confirmation
	SuccessHashFile string // 成功交易哈希文件路径
	FailedHashFile  string // 失败交易哈希文件路径
}

// NewTxFuzzer creates a new transaction fuzzer with mutation capabilities
func NewTxFuzzer(cfg *TxFuzzConfig, accounts []config.Account, logger utils.Logger) (*TxFuzzer, error) {
	// Connect to Ethereum client
	client, err := ethclient.Dial(cfg.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum client: %v", err)
	}

	// Get chain ID
	chainID := big.NewInt(cfg.ChainID)
	if cfg.ChainID == 0 {
		chainID, err = client.ChainID(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get chain ID: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize random number generator
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	// Initialize mutation components if enabled
	var mutationConfig *mutation.MutationConfig
	var ethGenerator *generators.ETHGenerator
	var ethMutator *strategies.ETHMutator
	var rlpMutator *strategies.RLPMutator

	if cfg.UseMutation {
		mutationConfig = mutation.DefaultMutationConfig()
		mutationConfig.ETH.TargetProtocolVersion = uint(chainID.Uint64())
		ethGenerator = generators.NewETHGenerator(mutationConfig)
		ethMutator = strategies.NewETHMutator(seed)
		rlpMutator = strategies.NewRLPMutator(seed)
	}

	// Initialize statistics
	stats := &TxStats{
		StartTime:      time.Now(),
		LastUpdateTime: time.Now(),
	}

	return &TxFuzzer{
		client:         client,
		accounts:       accounts,
		chainID:        chainID,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		rng:            rng,
		mutationConfig: mutationConfig,
		ethGenerator:   ethGenerator,
		ethMutator:     ethMutator,
		rlpMutator:     rlpMutator,
		txRecords:      make(map[common.Hash]*TransactionRecord),
		stats:          stats,
	}, nil
}

// Start begins the transaction fuzzing process
func (tf *TxFuzzer) Start(cfg *TxFuzzConfig) error {
	tf.logger.Info("Starting transaction fuzzing with seed: %d", tf.rng.Int63())

	ticker := time.NewTicker(time.Second / time.Duration(cfg.TxPerSecond))
	defer ticker.Stop()

	timeout := time.After(cfg.FuzzDuration)
	txCount := 0

	for {
		select {
		case <-tf.ctx.Done():
			tf.logger.Info("Transaction fuzzing stopped, sent %d transactions", txCount)
			return nil
		case <-timeout:
			tf.logger.Info("Transaction fuzzing completed, sent %d transactions", txCount)
			return nil
		case <-ticker.C:
			if err := tf.sendRandomTransaction(cfg); err != nil {
				tf.logger.Error("Failed to send transaction: %v", err)
			} else {
				txCount++
				if txCount%100 == 0 {
					tf.logger.Info("Sent %d transactions", txCount)
				}
			}
		}
	}
}

// sendRandomTransaction generates and sends a random transaction with mutation support
func (tf *TxFuzzer) sendRandomTransaction(cfg *TxFuzzConfig) error {
	// Select a random account
	if len(tf.accounts) == 0 {
		return fmt.Errorf("no accounts available for fuzzing")
	}

	account := tf.accounts[tf.rng.Intn(len(tf.accounts))]
	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Get account nonce
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := tf.client.PendingNonceAt(tf.ctx, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %v", err)
	}

	// Generate transaction (with or without mutation)
	tx, mutationUsed, mutationType, err := tf.generateTransaction(privateKey, nonce, cfg)
	if err != nil {
		return fmt.Errorf("failed to generate transaction: %v", err)
	}

	// Create transaction record
	record := &TransactionRecord{
		Hash:         tx.Hash(),
		From:         fromAddress,
		To:           tx.To(),
		Value:        tx.Value(),
		Gas:          tx.Gas(),
		Nonce:        tx.Nonce(),
		Data:         tx.Data(),
		SentTime:     time.Now(),
		Status:       "pending",
		MutationUsed: mutationUsed,
		MutationType: mutationType,
	}

	// Set gas price fields based on transaction type
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType:
		record.GasPrice = tx.GasPrice()
		record.TxType = tx.Type()
	case types.DynamicFeeTxType:
		record.GasFeeCap = tx.GasFeeCap()
		record.GasTipCap = tx.GasTipCap()
		record.TxType = tx.Type()
	}

	// Send transaction
	err = tf.client.SendTransaction(tf.ctx, tx)
	if err != nil {
		record.Status = "failed"
		record.Error = err.Error()
		tf.updateStats("failed", mutationUsed)
		tf.logger.Error("Failed to send transaction %s: %v", tx.Hash().Hex(), err)
		
		// 记录失败交易哈希
		tf.hashMutex.Lock()
		tf.failedTxHashes = append(tf.failedTxHashes, tx.Hash().Hex())
		tf.hashMutex.Unlock()
	} else {
		tf.updateStats("sent", mutationUsed)
		tf.logger.Debug("Sent transaction: %s (mutation: %v, type: %s)", tx.Hash().Hex(), mutationUsed, mutationType)
		
		// 记录成功交易哈希
		tf.hashMutex.Lock()
		tf.successTxHashes = append(tf.successTxHashes, tx.Hash().Hex())
		tf.hashMutex.Unlock()
		
		// Start monitoring transaction if tracking is enabled
		if cfg.EnableTracking {
			go tf.monitorTransaction(tx.Hash(), cfg.ConfirmBlocks)
		}
	}

	// Store transaction record
	if cfg.EnableTracking {
		tf.recordsMutex.Lock()
		tf.txRecords[tx.Hash()] = record
		tf.recordsMutex.Unlock()
	}

	return nil
}

// generateTransaction creates a transaction using mutation or random generation
func (tf *TxFuzzer) generateTransaction(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, bool, string, error) {
	// Decide whether to use mutation or random generation
	useMutation := cfg.UseMutation && tf.rng.Float64() < cfg.MutationRatio
	
	if useMutation && tf.ethGenerator != nil {
		// Use mutation-based generation
		return tf.generateMutatedTx(privateKey, nonce, cfg)
	} else {
		// Use random generation
		tx, err := tf.generateRandomTx(privateKey, nonce, cfg)
		return tx, false, "random", err
	}
}

// generateMutatedTx creates a transaction using mutation strategies
func (tf *TxFuzzer) generateMutatedTx(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, bool, string, error) {
	// Generate a base transaction using ETH generator
	message, err := tf.ethGenerator.GenerateRandomMessage()
	if err != nil {
		return nil, false, "", err
	}
	
	// Try to mutate the message
	if tf.ethMutator != nil && tf.ethMutator.CanMutate(message) {
		mutatedMessage, err := tf.ethMutator.Mutate(message, tf.mutationConfig)
		if err == nil {
			// Try to convert mutated message to transaction
			if tx := tf.messageToTransaction(mutatedMessage, privateKey, nonce); tx != nil {
				return tx, true, "eth_mutator", nil
			}
		}
	}
	
	// Fallback to random generation with RLP mutation
	tx, err := tf.generateRandomTx(privateKey, nonce, cfg)
	if err != nil {
		return nil, false, "", err
	}
	
	// Try RLP mutation on the transaction
	if tf.rlpMutator != nil {
		txBytes, err := tx.MarshalBinary()
		if err == nil && tf.rlpMutator.CanMutate(txBytes) {
			mutatedBytes, err := tf.rlpMutator.Mutate(txBytes, tf.mutationConfig)
			if err == nil {
				// Try to decode mutated bytes back to transaction
				var mutatedTx types.Transaction
				if err := mutatedTx.UnmarshalBinary(mutatedBytes); err == nil {
					return &mutatedTx, true, "rlp_mutator", nil
				}
			}
		}
	}
	
	return tx, true, "mutation_fallback", nil
}

// messageToTransaction converts a mutated message to a transaction (simplified)
func (tf *TxFuzzer) messageToTransaction(message []byte, privateKey *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
	// This is a simplified conversion - in practice, you'd need to parse the message
	// and extract transaction fields. For now, return nil to fallback to random generation
	return nil
}

// generateRandomTx creates a random transaction using basic random generation
func (tf *TxFuzzer) generateRandomTx(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, error) {
	// Use tx-fuzz to generate random transaction parameters
	txType := tf.rng.Intn(3) // 0: Legacy, 1: EIP-1559, 2: EIP-2930

	// Generate random recipient address
	to := tf.generateRandomAddress()

	// Generate random value (0 to 1 ETH)
	value := big.NewInt(tf.rng.Int63n(1000000000000000000)) // 0 to 1 ETH in wei

	// Generate random gas limit
	gasLimit := uint64(21000 + tf.rng.Intn(int(cfg.MaxGasLimit-21000)))

	// Generate random data
	data := tf.generateRandomData()

	var tx *types.Transaction
	var err error

	switch txType {
	case 0: // Legacy transaction
		gasPrice := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		tx = types.NewTransaction(nonce, *to, value, gasLimit, gasPrice, data)
	case 1: // EIP-1559 transaction
		maxFeePerGas := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		maxPriorityFeePerGas := big.NewInt(tf.rng.Int63n(maxFeePerGas.Int64()))
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   tf.chainID,
			Nonce:     nonce,
			To:        to,
			Value:     value,
			Gas:       gasLimit,
			GasFeeCap: maxFeePerGas,
			GasTipCap: maxPriorityFeePerGas,
			Data:      data,
		})
	case 2: // EIP-2930 transaction (Access List)
		gasPrice := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		tx = types.NewTx(&types.AccessListTx{
			ChainID:    tf.chainID,
			Nonce:      nonce,
			To:         to,
			Value:      value,
			Gas:        gasLimit,
			GasPrice:   gasPrice,
			Data:       data,
			AccessList: tf.generateRandomAccessList(),
		})
	}

	// Sign the transaction with appropriate signer
	var signer types.Signer
	switch tx.Type() {
	case types.LegacyTxType:
		signer = types.NewEIP155Signer(tf.chainID)
	case types.AccessListTxType:
		signer = types.NewEIP2930Signer(tf.chainID)
	case types.DynamicFeeTxType:
		signer = types.NewLondonSigner(tf.chainID)
	default:
		signer = types.NewEIP155Signer(tf.chainID)
	}
	
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return signedTx, nil
}

// generateRandomAddress creates a random Ethereum address
func (tf *TxFuzzer) generateRandomAddress() *common.Address {
	addr := make([]byte, 20)
	tf.rng.Read(addr)
	address := common.BytesToAddress(addr)
	return &address
}

// generateRandomData creates random transaction data
func (tf *TxFuzzer) generateRandomData() []byte {
	length := tf.rng.Intn(1024) // 0 to 1KB of data
	data := make([]byte, length)
	tf.rng.Read(data)
	return data
}

// generateRandomAccessList creates a random access list for EIP-2930 transactions
func (tf *TxFuzzer) generateRandomAccessList() types.AccessList {
	listLength := tf.rng.Intn(5) // 0 to 4 entries
	accessList := make(types.AccessList, listLength)

	for i := 0; i < listLength; i++ {
		addr := tf.generateRandomAddress()
		storageKeys := make([]common.Hash, tf.rng.Intn(3)) // 0 to 2 storage keys
		for j := range storageKeys {
			key := make([]byte, 32)
			tf.rng.Read(key)
			storageKeys[j] = common.BytesToHash(key)
		}
		accessList[i] = types.AccessTuple{
			Address:     *addr,
			StorageKeys: storageKeys,
		}
	}

	return accessList
}

// Stop stops the transaction fuzzing process
func (tf *TxFuzzer) Stop() {
	if tf.cancel != nil {
		tf.cancel()
	}
}

// updateStats updates the transaction statistics
func (tf *TxFuzzer) updateStats(status string, mutationUsed bool) {
	tf.stats.mutex.Lock()
	defer tf.stats.mutex.Unlock()
	
	switch status {
	case "sent":
		tf.stats.TotalSent++
	case "mined":
		tf.stats.TotalMined++
	case "failed":
		tf.stats.TotalFailed++
	case "pending":
		tf.stats.TotalPending++
	}
	
	if mutationUsed {
		tf.stats.MutationUsed++
	} else {
		tf.stats.RandomUsed++
	}
	
	tf.stats.LastUpdateTime = time.Now()
}

// monitorTransaction monitors a transaction until it's mined or fails
func (tf *TxFuzzer) monitorTransaction(txHash common.Hash, confirmBlocks uint64) {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()
	
	timeout := time.After(10 * time.Minute) // Timeout after 10 minutes
	
	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-timeout:
			// Mark as failed due to timeout
			tf.recordsMutex.Lock()
			if record, exists := tf.txRecords[txHash]; exists {
				record.Status = "failed"
				record.Error = "timeout"
			}
			tf.recordsMutex.Unlock()
			tf.updateStats("failed", false)
			return
		case <-ticker.C:
			// Check transaction receipt
			receipt, err := tf.client.TransactionReceipt(tf.ctx, txHash)
			if err != nil {
				continue // Transaction not mined yet
			}
			
			// Transaction mined, update record
			tf.recordsMutex.Lock()
			if record, exists := tf.txRecords[txHash]; exists {
				now := time.Now()
				record.MinedTime = &now
				record.Status = "mined"
				record.GasUsed = &receipt.GasUsed
				blockNum := receipt.BlockNumber.Uint64()
				record.BlockNumber = &blockNum
				
				if receipt.Status == types.ReceiptStatusFailed {
					record.Status = "failed"
					record.Error = "transaction reverted"
					tf.updateStats("failed", record.MutationUsed)
				} else {
					tf.updateStats("mined", record.MutationUsed)
				}
			}
			tf.recordsMutex.Unlock()
			
			// Wait for confirmation blocks if needed
			if confirmBlocks > 0 {
				go tf.waitForConfirmation(txHash, receipt.BlockNumber.Uint64(), confirmBlocks)
			}
			return
		}
	}
}

// waitForConfirmation waits for the specified number of confirmation blocks
func (tf *TxFuzzer) waitForConfirmation(txHash common.Hash, minedBlock uint64, confirmBlocks uint64) {
	ticker := time.NewTicker(15 * time.Second) // Check every 15 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-ticker.C:
			currentBlock, err := tf.client.BlockNumber(tf.ctx)
			if err != nil {
				continue
			}
			
			if currentBlock >= minedBlock+confirmBlocks {
				// Transaction confirmed
				tf.recordsMutex.Lock()
				if record, exists := tf.txRecords[txHash]; exists {
					now := time.Now()
					record.ConfirmedTime = &now
					record.Status = "confirmed"
				}
				tf.recordsMutex.Unlock()
				return
			}
		}
	}
}

// GetStats returns current transaction statistics
func (tf *TxFuzzer) GetStats() TxStats {
	tf.stats.mutex.RLock()
	defer tf.stats.mutex.RUnlock()
	return *tf.stats
}

// GetTransactionRecords returns all transaction records
func (tf *TxFuzzer) GetTransactionRecords() map[common.Hash]*TransactionRecord {
	tf.recordsMutex.RLock()
	defer tf.recordsMutex.RUnlock()
	
	// Create a copy to avoid race conditions
	records := make(map[common.Hash]*TransactionRecord)
	for hash, record := range tf.txRecords {
		records[hash] = record
	}
	return records
}

// ExportRecordsJSON exports transaction records as JSON
func (tf *TxFuzzer) ExportRecordsJSON() ([]byte, error) {
	records := tf.GetTransactionRecords()
	return json.Marshal(records)
}

// ExportSuccessHashes exports successful transaction hashes to a file
func (tf *TxFuzzer) ExportSuccessHashes(filename string) error {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()
	
	if len(tf.successTxHashes) == 0 {
		return fmt.Errorf("no successful transaction hashes to export")
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}
	defer file.Close()
	
	for _, hash := range tf.successTxHashes {
		if _, err := file.WriteString(hash + "\n"); err != nil {
			return fmt.Errorf("failed to write hash to file: %v", err)
		}
	}
	
	return nil
}

// ExportFailedHashes exports failed transaction hashes to a file
func (tf *TxFuzzer) ExportFailedHashes(filename string) error {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()
	
	if len(tf.failedTxHashes) == 0 {
		return fmt.Errorf("no failed transaction hashes to export")
	}
	
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}
	defer file.Close()
	
	for _, hash := range tf.failedTxHashes {
		if _, err := file.WriteString(hash + "\n"); err != nil {
			return fmt.Errorf("failed to write hash to file: %v", err)
		}
	}
	
	return nil
}

// GetSuccessHashes returns a copy of successful transaction hashes
func (tf *TxFuzzer) GetSuccessHashes() []string {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()
	
	hashes := make([]string, len(tf.successTxHashes))
	copy(hashes, tf.successTxHashes)
	return hashes
}

// GetFailedHashes returns a copy of failed transaction hashes
func (tf *TxFuzzer) GetFailedHashes() []string {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()
	
	hashes := make([]string, len(tf.failedTxHashes))
	copy(hashes, tf.failedTxHashes)
	return hashes
}

// Close closes the fuzzer and cleans up resources
func (tf *TxFuzzer) Close() error {
	tf.Stop()
	if tf.client != nil {
		tf.client.Close()
	}
	return nil
}
