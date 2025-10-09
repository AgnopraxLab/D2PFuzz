package testing

import (
	"bufio"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/config"
	ethtest "D2PFuzz/devp2p/protocol/eth"
	"D2PFuzz/ethclient"
	"D2PFuzz/transaction"
	"D2PFuzz/utils"
)

// SoftLimitTest tests all clients' soft limit implementation
type SoftLimitTest struct{}

func (t *SoftLimitTest) Name() string {
	return "test-soft-limit"
}

func (t *SoftLimitTest) Description() string {
	return "Test soft limit implementation for all clients"
}

func (t *SoftLimitTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Test All Clients Soft Limit ===")
	return TestAllClientsSoftLimitImpl(cfg)
}

// SoftLimitSingleTest tests single client's soft limit
type SoftLimitSingleTest struct{}

func (t *SoftLimitSingleTest) Name() string {
	return "test-soft-limit-single"
}

func (t *SoftLimitSingleTest) Description() string {
	return "Test soft limit for a single client"
}

func (t *SoftLimitSingleTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Test Single Client Soft Limit ===")

	nodeIndex := cfg.Test.SingleNodeIndex
	hashCount := 4096 // Test at soft limit
	nonceStr := cfg.Test.SingleNodeNonce

	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	// Parse nonce value
	startNonce, _, err := utils.ParseNonceValue(nonceStr)
	if err != nil {
		return fmt.Errorf("failed to parse nonce: %w", err)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	fmt.Printf("\n========================================\n")
	fmt.Printf("Testing: %s\n", strings.ToUpper(nodeName))
	fmt.Printf("Scenario: %d items\n", hashCount)
	fmt.Printf("Starting nonce: %s -> %d\n", nonceStr, startNonce)
	fmt.Printf("========================================\n\n")

	requested, status, err := TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(cfg, nodeIndex, hashCount, startNonce)
	if err != nil {
		fmt.Printf("❌ Test error: %v\n", err)
		return err
	}

	percentage := float64(requested) * 100.0 / float64(hashCount)
	symbol := "✓"
	if requested < hashCount && hashCount > 4096 {
		symbol = "⚠"
	}
	if status != "SUCCESS" {
		symbol = "❌"
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("Result: %s %d/%d (%.1f%%) [%s]\n", symbol, requested, hashCount, percentage, status)

	// Analyze result
	if status == "SUCCESS" {
		if requested == hashCount {
			if hashCount <= 4096 {
				fmt.Printf("Status: ✅ PASS - All announcements accepted (within limit)\n")
			} else {
				fmt.Printf("Status: ❌ FAIL - No soft limit enforced\n")
			}
		} else if requested == 4096 && hashCount > 4096 {
			fmt.Printf("Status: ✅ PASS - Soft limit (4096) correctly enforced\n")
		} else if requested < 4096 {
			fmt.Printf("Status: ⚠ PARTIAL - Custom limit at %d items\n", requested)
		} else {
			fmt.Printf("Status: ⚠ MIXED - Inconsistent behavior\n")
		}
	} else {
		fmt.Printf("Status: %s\n", status)
	}
	fmt.Printf("========================================\n")

	return nil
}

// SoftLimitReportTest generates soft limit test report
type SoftLimitReportTest struct{}

func (t *SoftLimitReportTest) Name() string {
	return "test-soft-limit-report"
}

func (t *SoftLimitReportTest) Description() string {
	return "Generate concise soft limit test report for all clients"
}

func (t *SoftLimitReportTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Soft Limit Test Report ===")
	return TestSoftLimitForReportImpl(cfg)
}

// GetPooledTxsTest tests GetPooledTransactions
type GetPooledTxsTest struct{}

func (t *GetPooledTxsTest) Name() string {
	return "GetPooledTxs"
}

func (t *GetPooledTxsTest) Description() string {
	return "Test GetPooledTransactions protocol message"
}

func (t *GetPooledTxsTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz GetPooledTxs Testing Tool ===")

	nodeIndex := cfg.Test.GetPooledTxsNodeIndex
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return fmt.Errorf("failed to create suite: %v", err)
	}

	txHashes := []common.Hash{}

	// Read hash values from file
	file, err := os.Open(cfg.Paths.TxHashesExt)
	if err != nil {
		// Try alternative path
		file, err = os.Open(cfg.Paths.TxHashes)
		if err != nil {
			return fmt.Errorf("failed to open tx hashes file: %v", err)
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and lines starting with #
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Convert hex string to common.Hash and add to array
		txHashes = append(txHashes, common.HexToHash(line))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading tx hashes file: %v", err)
	}

	fmt.Printf("Loaded %d transaction hashes from file\n", len(txHashes))

	// Query transactions
	foundTxs, err := transaction.Query(ethclient.ClientFromSuite(s, cfg, nodeIndex), txHashes)
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return err
	}

	fmt.Printf("Query completed successfully, found %d transactions\n", len(foundTxs))

	// Print found transactions
	utils.PrintPooledTransactions(eth.PooledTransactionsResponse(foundTxs))

	return nil
}

// OneTransactionTest sends a single transaction
type OneTransactionTest struct{}

func (t *OneTransactionTest) Name() string {
	return "oneTransaction"
}

func (t *OneTransactionTest) Description() string {
	return "Send a single transaction for testing"
}

func (t *OneTransactionTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Single-Transaction Testing Tool ===")

	nodeIndex := cfg.Test.SingleNodeIndex
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d", nodeIndex)
	}

	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return fmt.Errorf("failed to create suite: %v", err)
	}

	fmt.Printf("🎯 Starting single transaction testing for %s ...\n", s.GetElName())

	nonceStr := cfg.Test.SingleNodeNonce
	fromAccount := config.PredefinedAccounts[0]
	toAccount := config.PredefinedAccounts[5]

	// Parse nonce value
	nonce, _, err := utils.ParseNonceValue(nonceStr)
	if err != nil {
		return fmt.Errorf("failed to parse nonce: %w", err)
	}

	var to common.Address = common.HexToAddress(toAccount.Address)
	txdata := &types.DynamicFeeTx{
		ChainID:   cfg.ChainID,
		Nonce:     nonce,
		GasTipCap: cfg.DefaultGasTipCap,
		GasFeeCap: cfg.DefaultGasFeeCap,
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1),
	}
	innertx := types.NewTx(txdata)

	prik, err := crypto.HexToECDSA(fromAccount.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	tx, err := types.SignTx(innertx, types.NewLondonSigner(cfg.ChainID), prik)
	if err != nil {
		return fmt.Errorf("failed to sign tx: %v", err)
	}

	// Send transaction
	err = s.SendTxs([]*types.Transaction{tx})
	if err != nil {
		return fmt.Errorf("failed to send tx: %v", err)
	}

	txHash := tx.Hash()
	fmt.Printf("Transaction sent successfully!\n")
	fmt.Printf("Transaction hash: %s\n", txHash.Hex())

	// Verify transaction was received
	foundTxs, err := transaction.Query(ethclient.ClientFromSuite(s, cfg, nodeIndex), []common.Hash{txHash})
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return err
	}

	if len(foundTxs) > 0 {
		fmt.Printf("✅ Transaction verified in node's pool\n")
		utils.PrintPooledTransactions(eth.PooledTransactionsResponse(foundTxs))
	} else {
		fmt.Printf("⚠ Transaction not found in pool\n")
	}

	return nil
}

// LargeTransactionsTest sends large batch of transactions
type LargeTransactionsTest struct{}

func (t *LargeTransactionsTest) Name() string {
	return "largeTransactions"
}

func (t *LargeTransactionsTest) Description() string {
	return "Send large batch of transactions for testing"
}

func (t *LargeTransactionsTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Large-Transaction Testing Tool ===")

	nodeIndex := cfg.Test.SingleNodeIndex
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		nodeIndex = 0 // Default to first node
	}

	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return fmt.Errorf("failed to create suite: %v", err)
	}

	fmt.Printf("🎯 Starting large transactions testing for %s ...\n", s.GetElName())

	// Generate large batch of transactions
	var (
		nonce  = uint64(math.MaxUint64)
		from   = config.PredefinedAccounts[0].PrivateKey
		count  = 1000
		txs    []*types.Transaction
		hashes []common.Hash
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	var to common.Address = common.HexToAddress(config.PredefinedAccounts[5].Address)

	fmt.Printf("Generating %d transactions...\n", count)
	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   cfg.ChainID,
			Nonce:     nonce - uint64(i),
			GasTipCap: cfg.DefaultGasTipCap,
			GasFeeCap: cfg.DefaultGasFeeCap,
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(1),
		}
		tx := types.NewTx(inner)
		tx, err = types.SignTx(tx, types.NewLondonSigner(cfg.ChainID), prik)
		if err != nil {
			return fmt.Errorf("failed to sign tx: %v", err)
		}
		txs = append(txs, tx)
		hashes = append(hashes, tx.Hash())
	}

	fmt.Printf("Sending %d transactions...\n", len(txs))

	// Send transactions
	err = s.SendTxsWithoutRecv(txs)
	if err != nil {
		return fmt.Errorf("failed to send transactions: %v", err)
	}

	fmt.Printf("✅ %d transactions sent successfully!\n", len(txs))
	fmt.Printf("First transaction hash: %s\n", hashes[0].Hex())

	// Write to file
	if err := utils.WriteHashesToFile(hashes, cfg.Paths.TxHashes); err != nil {
		fmt.Printf("⚠ Failed to write hashes to file: %v\n", err)
	} else {
		fmt.Printf("📄 Transaction hashes saved to: %s\n", cfg.Paths.TxHashes)
	}

	return nil
}

// InteractiveTest provides interactive test mode selection
type InteractiveTest struct{}

func (t *InteractiveTest) Name() string {
	return "interactive"
}

func (t *InteractiveTest) Description() string {
	return "Interactive mode - select test options at runtime"
}

func (t *InteractiveTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Interactive Testing Tool ===")
	fmt.Println("Available test modes:")
	fmt.Println("1. Multi-node testing (all nodes)")
	fmt.Println("2. Single node testing (specific node)")
	fmt.Print("Please select test mode (1 or 2): ")

	var choice int
	fmt.Scanln(&choice)

	switch choice {
	case 1:
		fmt.Println("\n🚀 Starting multi-node testing...")
		return (&MultiNodeTest{}).Run(cfg)

	case 2:
		fmt.Println("\n🎯 Starting single node testing...")
		return runInteractiveSingleNodeTest(cfg)

	default:
		return fmt.Errorf("invalid choice: %d. Please select 1 or 2", choice)
	}
}

// runInteractiveSingleNodeTest handles interactive single node testing
func runInteractiveSingleNodeTest(cfg *config.Config) error {
	fmt.Println("\nAvailable nodes:")
	for i := 0; i < cfg.GetNodeCount(); i++ {
		fmt.Printf("  %d. %s\n", i, cfg.GetNodeName(i))
	}

	fmt.Print("Please select node index: ")
	var nodeIndex int
	fmt.Scanln(&nodeIndex)

	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d. Valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	fmt.Print("Enter starting nonce (press Enter for 'auto'): ")
	var nonceInput string
	fmt.Scanln(&nonceInput)

	nonceStr := "auto"
	if nonceInput != "" {
		nonceStr = nonceInput
	}

	fmt.Print("Enter number of transactions to send (default 3): ")
	var batchSizeInput string
	fmt.Scanln(&batchSizeInput)

	batchSize := 3
	if batchSizeInput != "" {
		if size, err := strconv.Atoi(batchSizeInput); err == nil && size > 0 {
			batchSize = size
		}
	}

	// Update config with user input
	cfg.Test.SingleNodeIndex = nodeIndex
	cfg.Test.SingleNodeNonce = nonceStr
	cfg.Test.SingleNodeBatchSize = batchSize

	fmt.Printf("\n🎯 Starting single node testing for %s (Node %d)...\n", cfg.GetNodeName(nodeIndex), nodeIndex)

	// Run single node test
	return (&SingleNodeTest{}).Run(cfg)
}
