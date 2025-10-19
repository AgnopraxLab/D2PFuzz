package testing

import (
	"fmt"
	"math/big"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/account"
	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"

	"github.com/ethereum/go-ethereum/common"
)

// SingleNodeTest implements single node testing
type SingleNodeTest struct{}

func (t *SingleNodeTest) Name() string {
	return "single"
}

func (t *SingleNodeTest) Description() string {
	return "Single node testing - send transactions to one specific node"
}

func (t *SingleNodeTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Single-Node Testing Tool ===")

	// Get test parameters from config - prefer new SingleNode section, fallback to legacy
	var nodeIndex int
	var batchSize int
	var nonceStr string
	var saveHashes bool

	if cfg.Test.SingleNode.BatchSize > 0 { // New config section detected
		nodeIndex = cfg.Test.SingleNode.NodeIndex
		batchSize = cfg.Test.SingleNode.BatchSize
		nonceStr = cfg.Test.SingleNode.Nonce
		saveHashes = cfg.Test.SingleNode.SaveHashes
		fmt.Println("📋 Using new single_node configuration section")
	} else { // Fallback to legacy fields
		nodeIndex = cfg.Test.SingleNodeIndex
		batchSize = cfg.Test.SingleNodeBatchSize
		nonceStr = cfg.Test.SingleNodeNonce
		saveHashes = true // default
		fmt.Println("📋 Using legacy configuration fields")
	}

	// Validate node index
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	fmt.Printf("🎯 Starting single node testing for %s (Node %d)...\n", nodeName, nodeIndex)
	fmt.Printf("●Execution Client: %v (Node %d)\n", nodeName, nodeIndex)

	// Create client (using our new unified client!)
	client, err := ethclient.NewClient(cfg, nodeIndex)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Get account address for this node (using predefined pattern: node i uses account i)
	if nodeIndex >= len(config.PredefinedAccounts) {
		return fmt.Errorf("no account configured for node %d", nodeIndex)
	}
	fromAddress := common.HexToAddress(config.PredefinedAccounts[nodeIndex].Address)

	// Resolve nonce (auto or specific value)
	resolvedNonce, err := utils.ResolveNonce(client, nonceStr, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve nonce: %w", err)
	}
	fmt.Printf("📋 Nonce resolved: %s -> %d\n", nonceStr, resolvedNonce)

	// Create node account manager
	nodeNonceInitialValues := []uint64{0, 0, 0, 0, 0}
	if nodeIndex < len(nodeNonceInitialValues) {
		nodeNonceInitialValues[nodeIndex] = resolvedNonce
	}

	nodeAccountManager := account.NewNodeAccountManagerWithNonces(
		config.PredefinedAccounts,
		cfg.GetNodeCount(),
		nodeNonceInitialValues,
	)

	// Get fixed account information for current node
	nodeAccount := nodeAccountManager.GetNodeAccount(nodeIndex)
	if nodeAccount == nil {
		return fmt.Errorf("failed to get account for node %d", nodeIndex)
	}

	fmt.Printf("💳Using accounts:\n")
	fmt.Printf("   From: %s (Initial Nonce: %d)\n", nodeAccount.FromAccount.Address, nodeAccount.Nonce)
	fmt.Printf("   To: %s\n", nodeAccount.ToAccount.Address)

	// Initialize transaction hash record file
	hashFilePath := cfg.Paths.TxHashes
	if err := utils.InitHashFile(hashFilePath, nodeName); err != nil {
		return fmt.Errorf("failed to initialize hash file: %w", err)
	}

	// Batch transaction sending test
	fmt.Printf("📤 Sending %d transactions...\n", batchSize)

	chainID := big.NewInt(3151908)
	successCount := 0

	for j := 0; j < batchSize; j++ {
		currentNonce := nodeAccountManager.GetCurrentNonce(nodeIndex)
		fmt.Printf("   Transaction %d/%d (Nonce: %d)...", j+1, batchSize, currentNonce)

		// Use our new unified transaction sending!
		txHash, err := transaction.QuickSendDynamic(
			client,
			nodeAccount.FromAccount,
			nodeAccount.ToAccount,
			currentNonce,
			chainID,
		)

		if err != nil {
			fmt.Printf(" ❌ Failed: %v\n", err)
			break
		}

		// Write transaction hash to file (if enabled)
		if saveHashes {
			if err := utils.AppendHashToFile(hashFilePath, txHash); err != nil {
				fmt.Printf(" ⚠️ Failed to write hash to file: %v", err)
			}
		}

		// Increment nonce for this node after successful transaction
		nodeAccountManager.IncrementNonce(nodeIndex)
		fmt.Printf(" ✅ Finished! (New Nonce: %d, Hash: %s)\n",
			nodeAccountManager.GetCurrentNonce(nodeIndex), txHash.Hex())
		successCount++

		// Add small delay between transactions to avoid nonce conflicts
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("=== Single Node Testing Completed ===\n")
	fmt.Printf("Transactions sent: %d/%d\n", successCount, batchSize)

	return nil
}
