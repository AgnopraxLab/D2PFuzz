package testing

import (
	"fmt"
	"math/big"
	"time"

	"D2PFuzz/blob"
	"D2PFuzz/config"
	"D2PFuzz/ethclient"
	"D2PFuzz/transaction"
	"D2PFuzz/utils"

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

	// Validate configuration
	blobCfg := cfg.Test.BlobTest
	if blobCfg.BlobCount < 1 || blobCfg.BlobCount > blob.MaxBlobsPerTransaction {
		return fmt.Errorf("invalid blob count: %d (must be 1-%d)", blobCfg.BlobCount, blob.MaxBlobsPerTransaction)
	}

	// Get node configuration
	nodeIndex := blobCfg.SingleNodeIndex
	if nodeIndex >= len(cfg.P2P.BootstrapNodes) {
		return fmt.Errorf("invalid node index: %d", nodeIndex)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	nodeEnode := cfg.P2P.BootstrapNodes[nodeIndex]

	fmt.Printf("📍 Target Node: %s (Index: %d)\n", nodeName, nodeIndex)
	fmt.Printf("📍 Node Enode: %s\n", nodeEnode)
	fmt.Printf("🧊 Blobs per transaction: %d\n", blobCfg.BlobCount)
	fmt.Printf("📊 Total blob transactions: %d\n", blobCfg.TotalBlobTxs)
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

	// Get account
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured")
	}
	fromAccount := cfg.Accounts[0]
	toAccount := cfg.Accounts[1%len(cfg.Accounts)]

	fmt.Printf("💼 From Account: %s\n", fromAccount.Address)
	fmt.Printf("💼 To Account: %s\n", toAccount.Address)
	fmt.Println()

	// Parse max fee per blob gas
	maxFeePerBlobGas := new(big.Int)
	if blobCfg.MaxFeePerBlobGas != "" {
		if _, ok := maxFeePerBlobGas.SetString(blobCfg.MaxFeePerBlobGas, 10); !ok {
			return fmt.Errorf("invalid max_fee_per_blob_gas: %s", blobCfg.MaxFeePerBlobGas)
		}
	} else {
		maxFeePerBlobGas = big.NewInt(1000000000) // 1 Gwei default
	}

	// Determine generator type
	generatorType := blob.GeneratorRandom
	if len(blobCfg.Scenarios) > 0 {
		switch blobCfg.Scenarios[0] {
		case "random":
			generatorType = blob.GeneratorRandom
		case "pattern":
			generatorType = blob.GeneratorPattern
		case "zero":
			generatorType = blob.GeneratorZero
		case "l2-data":
			generatorType = blob.GeneratorL2Data
		}
	}

	fmt.Printf("🎲 Generator type: %s\n", generatorType)
	fmt.Printf("💰 Max fee per blob gas: %s wei\n", maxFeePerBlobGas.String())
	fmt.Println()

	// Resolve nonce (use blob-specific config or default to "auto")
	nonceStr := blobCfg.SingleNodeNonce
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
	totalTxs := blobCfg.TotalBlobTxs
	if totalTxs == 0 {
		totalTxs = 1
	}

	// Collect transaction hashes for saving to file
	var txHashes []common.Hash

	startTime := time.Now()

	for i := 0; i < totalTxs; i++ {
		fmt.Printf("📤 Transaction %d/%d (Nonce: %d)\n", i+1, totalTxs, nonce)

		// Build blob transaction
		builder := transaction.NewBlobTxBuilder(cfg.ChainID).
			WithFrom(fromAccount).
			WithTo(toAccount).
			WithNonce(nonce).
			WithMaxFeePerBlobGas(maxFeePerBlobGas)

		// Generate and add blobs
		fmt.Printf("   🧊 Generating %d blob(s)...\n", blobCfg.BlobCount)
		for j := 0; j < blobCfg.BlobCount; j++ {
			blobSize := blobCfg.BlobDataSize
			if blobSize == 0 {
				blobSize = blob.BlobDataSize // 128 KB
			}

			blobData, err := blob.GenerateBlob(generatorType, blobSize)
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

		if builder.GetBlobCount() != blobCfg.BlobCount {
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
		opts.Verify = false // Skip immediate verification for speed

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
		if i < totalTxs-1 && blobCfg.SendInterval > 0 {
			time.Sleep(time.Duration(blobCfg.SendInterval) * time.Millisecond)
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

	// Save transaction hashes to file
	if len(txHashes) > 0 {
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
