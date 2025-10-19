package testing

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/account"
	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"

	"github.com/ethereum/go-ethereum/common"
)

// MultiNodeTest implements multi-node testing
type MultiNodeTest struct{}

func (t *MultiNodeTest) Name() string {
	return "multi"
}

func (t *MultiNodeTest) Description() string {
	return "Multi-node testing - send transactions to all configured nodes"
}

func (t *MultiNodeTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Multi-Node Testing Tool ===")
	fmt.Println("🚀 Starting multi-node testing...")

	// Get test parameters from config - prefer new MultiNode section, fallback to legacy
	var batchSize int
	var nodeNonceStrs []string
	var saveHashes bool

	if cfg.Test.MultiNode.BatchSize > 0 { // New config section detected
		batchSize = cfg.Test.MultiNode.BatchSize
		nodeNonceStrs = cfg.Test.MultiNode.Nonces
		saveHashes = cfg.Test.MultiNode.SaveHashes
		fmt.Println("📋 Using new multi_node configuration section")
	} else { // Fallback to legacy fields
		batchSize = cfg.Test.MultiNodeBatchSize
		nodeNonceStrs = cfg.Test.MultiNodeNonces
		saveHashes = true // default
		fmt.Println("📋 Using legacy configuration fields")
	}

	// Ensure nonce string list has sufficient length (default to "auto")
	for len(nodeNonceStrs) < cfg.GetNodeCount() {
		nodeNonceStrs = append(nodeNonceStrs, "auto")
	}

	// Resolve nonces for all nodes
	nodeNonceInitialValues := make([]uint64, cfg.GetNodeCount())
	fmt.Printf("\n=== Resolving Nonces ===\n")
	for i := 0; i < cfg.GetNodeCount(); i++ {
		// Create temporary client to resolve nonce
		client, err := ethclient.NewClient(cfg, i)
		if err != nil {
			return fmt.Errorf("failed to create client for node %d: %w", i, err)
		}

		// Get account address for this node
		if i >= len(config.PredefinedAccounts) {
			return fmt.Errorf("no account configured for node %d", i)
		}
		fromAddress := common.HexToAddress(config.PredefinedAccounts[i].Address)

		// Resolve nonce
		nonce, err := utils.ResolveNonce(client, nodeNonceStrs[i], fromAddress)
		if err != nil {
			return fmt.Errorf("failed to resolve nonce for node %d: %w", i, err)
		}

		nodeNonceInitialValues[i] = nonce
		fmt.Printf("Node %d (%s): %s -> %d\n", i, cfg.GetNodeName(i), nodeNonceStrs[i], nonce)
	}
	fmt.Println()

	// Create node account manager
	nodeAccountManager := account.NewNodeAccountManagerWithNonces(
		config.PredefinedAccounts,
		cfg.GetNodeCount(),
		nodeNonceInitialValues,
	)

	fmt.Printf("\n=== Multi-Node Testing Started ===\n")

	// Initialize transaction hash record file
	hashFilePath := cfg.Paths.TxHashes
	if err := utils.WriteStringToFile(hashFilePath, ""); err != nil {
		return fmt.Errorf("failed to initialize hash file: %w", err)
	}

	chainID := big.NewInt(3151908)

	// Loop test all nodes
	for i := 0; i < cfg.GetNodeCount(); i++ {
		nodeName := cfg.GetNodeName(i)
		fmt.Printf("●Execution Client: %v (Node %d/%d)\n", nodeName, i+1, cfg.GetNodeCount())

		// Create client for this node
		client, err := ethclient.NewClient(cfg, i)
		if err != nil {
			fmt.Printf("❌ Failed to create client: %v\n", err)
			continue
		}

		// Get fixed account information for current node
		nodeAccount := nodeAccountManager.GetNodeAccount(i)
		if nodeAccount == nil {
			fmt.Printf("❌ Failed to get account for node %d\n", i)
			continue
		}

		fmt.Printf("💳 Node %d - Using fixed accounts:\n", i+1)
		fmt.Printf("   From: %s (Nonce: %d)\n", nodeAccount.FromAccount.Address, nodeAccount.Nonce)
		fmt.Printf("   To: %s\n", nodeAccount.ToAccount.Address)

		// Write node name to hash file
		nodeHeader := fmt.Sprintf("# %s\n", nodeName)
		if err := utils.AppendToFile(hashFilePath, nodeHeader); err != nil {
			fmt.Printf("❌ Failed to write node header to hash file: %v\n", err)
		}

		// Batch transaction sending test
		fmt.Printf("📤 Sending %d transactions for Node %d...\n", batchSize, i+1)

		for j := 0; j < batchSize; j++ {
			currentNonce := nodeAccountManager.GetCurrentNonce(i)
			fmt.Printf("   Transaction %d/%d (Nonce: %d)...", j+1, batchSize, currentNonce)

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
			nodeAccountManager.IncrementNonce(i)
			fmt.Printf(" Finished. (New Nonce: %d, Hash: %s)\n",
				nodeAccountManager.GetCurrentNonce(i), txHash.Hex())

			// Add small delay between transactions to avoid nonce conflicts
			time.Sleep(100 * time.Millisecond)
		}

		fmt.Println(strings.Repeat("-", 60))
	}

	// Print test summary
	fmt.Printf("Total nodes tested: %d\n", cfg.GetNodeCount())

	// Print final nonce status
	fmt.Println("\n=== Final Nonce Status ===")
	for i := 0; i < cfg.GetNodeCount(); i++ {
		nodeAccount := nodeAccountManager.GetNodeAccount(i)
		if nodeAccount != nil {
			fmt.Printf("Node %d (%-10s): From=%s, (Nonce should be %d)\n",
				i+1, cfg.GetNodeName(i), nodeAccount.FromAccount.Address, nodeAccount.Nonce)
		}
	}

	fmt.Printf("\n=== Multi-Node Testing Completed ===\n")
	fmt.Printf("📄 Transaction hashes saved to: %s\n", hashFilePath)

	return nil
}
