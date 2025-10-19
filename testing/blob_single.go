package testing

import (
	"fmt"
	"math/big"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/blob"
	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"

	"github.com/ethereum/go-ethereum/common"
)

// BlobSingleNodeTest implements single-node blob transaction testing
type BlobSingleNodeTest struct{}

func (t *BlobSingleNodeTest) Name() string {
	return "blob-single"
}

func (t *BlobSingleNodeTest) Description() string {
	return "Send blob transactions to a single node and verify"
}

func (t *BlobSingleNodeTest) Run(cfg *config.Config) error {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Transaction Single Node Test")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Get configuration - prefer new BlobSingle section, fallback to BlobTest
	var nodeIndex int
	var blobCount int
	var blobDataSize int
	var maxFeePerBlobGas string
	var generatorType string
	var totalBlobTxs int
	var sendInterval int
	var nonceStr string
	var saveHashes bool
	var fromAccountIndex int
	var toAccountIndex int

	if cfg.Test.BlobSingle.BlobCount > 0 { // New config section detected
		nodeIndex = cfg.Test.BlobSingle.NodeIndex
		blobCount = cfg.Test.BlobSingle.BlobCount
		blobDataSize = cfg.Test.BlobSingle.BlobDataSize
		maxFeePerBlobGas = cfg.Test.BlobSingle.MaxFeePerBlobGas
		generatorType = cfg.Test.BlobSingle.GeneratorType
		totalBlobTxs = cfg.Test.BlobSingle.TotalTransactions
		sendInterval = cfg.Test.BlobSingle.SendIntervalMS
		nonceStr = cfg.Test.BlobSingle.Nonce
		saveHashes = cfg.Test.BlobSingle.SaveHashes
		fromAccountIndex = cfg.Test.BlobSingle.FromAccountIndex
		toAccountIndex = cfg.Test.BlobSingle.ToAccountIndex
		fmt.Println("📋 Using new blob_single configuration section")
	} else { // Fallback to BlobTest
		blobCfg := cfg.Test.BlobTest
		nodeIndex = blobCfg.SingleNodeIndex
		blobCount = blobCfg.BlobCount
		blobDataSize = blobCfg.BlobDataSize
		maxFeePerBlobGas = blobCfg.MaxFeePerBlobGas
		if len(blobCfg.Scenarios) > 0 {
			generatorType = blobCfg.Scenarios[0]
		} else {
			generatorType = "random"
		}
		totalBlobTxs = blobCfg.TotalBlobTxs
		sendInterval = blobCfg.SendInterval
		nonceStr = blobCfg.SingleNodeNonce
		saveHashes = true // default
		fromAccountIndex = blobCfg.FromAccountIndex
		toAccountIndex = blobCfg.ToAccountIndex
		fmt.Println("📋 Using legacy blob_test configuration section")
	}

	// Validate configuration
	if blobCount < 1 || blobCount > blob.MaxBlobsPerTransaction {
		return fmt.Errorf("invalid blob count: %d (must be 1-%d)", blobCount, blob.MaxBlobsPerTransaction)
	}

	// Validate node index
	if nodeIndex >= len(cfg.P2P.BootstrapNodes) {
		return fmt.Errorf("invalid node index: %d", nodeIndex)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	nodeEnode := cfg.P2P.BootstrapNodes[nodeIndex]

	fmt.Printf("📍 Target Node: %s (Index: %d)\n", nodeName, nodeIndex)
	fmt.Printf("📍 Node Enode: %s\n", nodeEnode)
	fmt.Printf("🧊 Blobs per transaction: %d\n", blobCount)
	fmt.Printf("📊 Total blob transactions: %d\n", totalBlobTxs)
	fmt.Println()

	// Initialize KZG
	fmt.Println("🔧 Initializing KZG trusted setup...")
	if err := blob.InitKZG(); err != nil {
		return fmt.Errorf("failed to initialize KZG: %w", err)
	}
	fmt.Println("✅ KZG initialized successfully")
	fmt.Println()

	// Create client
	fmt.Println("🔌 Connecting to node...")
	client, err := ethclient.NewClient(cfg, nodeIndex)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	fmt.Printf("✅ Connected to %s\n", nodeName)
	fmt.Println()

	// Get accounts with validation
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured")
	}

	// Validate and set default account indices
	if fromAccountIndex < 0 || fromAccountIndex >= len(cfg.Accounts) {
		if fromAccountIndex != 0 { // Only warn if explicitly set to invalid value
			fmt.Printf("⚠️  Invalid from_account_index %d, using default 0\n", fromAccountIndex)
		}
		fromAccountIndex = 0
	}

	// Default toAccountIndex to 1 if not set, or use modulo to wrap around
	if toAccountIndex <= 0 {
		toAccountIndex = 1 % len(cfg.Accounts)
	} else if toAccountIndex >= len(cfg.Accounts) {
		fmt.Printf("⚠️  Invalid to_account_index %d (max: %d), wrapping around\n", toAccountIndex, len(cfg.Accounts)-1)
		toAccountIndex = toAccountIndex % len(cfg.Accounts)
	}

	fromAccount := cfg.Accounts[fromAccountIndex]
	toAccount := cfg.Accounts[toAccountIndex]

	fmt.Printf("💼 From Account [%d]: %s\n", fromAccountIndex, fromAccount.Address)
	fmt.Printf("💼 To Account [%d]: %s\n", toAccountIndex, toAccount.Address)
	fmt.Println()

	// Parse max fee per blob gas
	maxFeePerBlobGasBig := new(big.Int)
	if maxFeePerBlobGas != "" {
		if _, ok := maxFeePerBlobGasBig.SetString(maxFeePerBlobGas, 10); !ok {
			return fmt.Errorf("invalid max_fee_per_blob_gas: %s", maxFeePerBlobGas)
		}
	} else {
		maxFeePerBlobGasBig = big.NewInt(2000000000) // 2 Gwei default
	}

	// Determine generator type from string
	var genType blob.GeneratorType
	switch generatorType {
	case "random":
		genType = blob.GeneratorRandom
	case "pattern":
		genType = blob.GeneratorPattern
	case "zero":
		genType = blob.GeneratorZero
	case "l2-data":
		genType = blob.GeneratorL2Data
	default:
		genType = blob.GeneratorRandom
	}

	fmt.Printf("🎲 Generator type: %s\n", generatorType)
	fmt.Printf("💰 Max fee per blob gas: %s wei\n", maxFeePerBlobGasBig.String())
	fmt.Println()

	// Resolve nonce (use blob-specific config or default to "auto")
	if nonceStr == "" {
		nonceStr = "auto" // default to auto
	}

	nonce, err := utils.ResolveNonce(client, nonceStr, common.HexToAddress(fromAccount.Address))
	if err != nil {
		return fmt.Errorf("failed to resolve blob nonce: %w", err)
	}
	fmt.Printf("📋 Blob nonce resolved: %s -> %d\n", nonceStr, nonce)
	fmt.Println()

	// Send blob transactions
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Sending Blob Transactions")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	successCount := 0
	failCount := 0
	if totalBlobTxs == 0 {
		totalBlobTxs = 1
	}

	// Collect transaction hashes for saving to file
	var txHashes []common.Hash

	startTime := time.Now()

	for i := 0; i < totalBlobTxs; i++ {
		fmt.Printf("📤 Transaction %d/%d (Nonce: %d)\n", i+1, totalBlobTxs, nonce)

		// Build blob transaction
		builder := transaction.NewBlobTxBuilder(cfg.ChainID).
			WithFrom(fromAccount).
			WithTo(toAccount).
			WithNonce(nonce).
			WithMaxFeePerBlobGas(maxFeePerBlobGasBig)

		// Generate and add blobs
		fmt.Printf("   🧊 Generating %d blob(s)...\n", blobCount)
		for j := 0; j < blobCount; j++ {
			blobSize := blobDataSize
			if blobSize == 0 {
				blobSize = blob.BlobDataSize // 128 KB
			}

			blobData, err := blob.GenerateBlob(genType, blobSize)
			if err != nil {
				fmt.Printf("   ❌ Failed to generate blob %d: %v\n", j, err)
				failCount++
				break
			}

			if err := builder.AddBlobData(blobData); err != nil {
				fmt.Printf("   ❌ Failed to add blob %d: %v\n", j, err)
				failCount++
				break
			}

			fmt.Printf("   ✅ Blob %d: %d bytes\n", j, len(blobData.Raw))
			fmt.Printf("      Hash: %s\n", blobData.VersionedHash.Hex())
		}

		if builder.GetBlobCount() != blobCount {
			fmt.Println("   ⚠️  Blob generation incomplete, skipping transaction")
			continue
		}

		// Build the transaction
		blobTx, err := builder.Build()
		if err != nil {
			fmt.Printf("   ❌ Failed to build transaction: %v\n", err)
			failCount++
			continue
		}

		// Estimate blob gas cost
		blobGas, _ := builder.EstimateBlobGas()
		blobCost, _ := builder.EstimateBlobCost()
		fmt.Printf("   ⛽ Estimated blob gas: %d (cost: %s wei)\n", blobGas, blobCost.String())

		// Send the transaction
		opts := transaction.DefaultSendOptions()
		opts.Verify = true // Skip immediate verification for speed

		txHash, err := transaction.SendBlob(client, blobTx, opts)
		if err != nil {
			fmt.Printf("   ❌ Failed to send: %v\n", err)
			failCount++
		} else {
			fmt.Printf("   ✅ Sent! Hash: %s\n", txHash.Hex())
			txHashes = append(txHashes, txHash)
			successCount++
		}

		nonce++
		fmt.Println()

		// Delay between transactions
		if i < totalBlobTxs-1 && sendInterval > 0 {
			time.Sleep(time.Duration(sendInterval) * time.Millisecond)
		}
	}

	duration := time.Since(startTime)

	// Print summary
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Test Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Printf("✅ Successful: %d\n", successCount)
	fmt.Printf("❌ Failed: %d\n", failCount)
	fmt.Printf("⏱️  Duration: %v\n", duration)
	if successCount > 0 {
		fmt.Printf("📊 Average: %.2f tx/sec\n", float64(successCount)/duration.Seconds())
	}

	// Save transaction hashes to file (if enabled)
	if saveHashes && len(txHashes) > 0 {
		if err := utils.WriteHashesToFile(txHashes, cfg.Paths.TxHashes); err != nil {
			fmt.Printf("⚠️  Warning: Failed to save transaction hashes: %v\n", err)
		} else {
			fmt.Printf("💾 Saved %d transaction hash(es) to %s\n", len(txHashes), cfg.Paths.TxHashes)
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Single Node Test - Completed")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if failCount > 0 {
		return fmt.Errorf("test completed with %d failures", failCount)
	}

	return nil
}
