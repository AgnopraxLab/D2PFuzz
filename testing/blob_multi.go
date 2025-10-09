package testing

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"D2PFuzz/blob"
	"D2PFuzz/config"
	"D2PFuzz/ethclient"
	"D2PFuzz/transaction"
	"D2PFuzz/utils"

	"github.com/ethereum/go-ethereum/common"
)

// BlobMultiNodeTest implements multi-node blob transaction testing
type BlobMultiNodeTest struct{}

func (t *BlobMultiNodeTest) Name() string {
	return "blob-multi"
}

func (t *BlobMultiNodeTest) Description() string {
	return "Send blob transactions to multiple nodes and verify propagation"
}

func (t *BlobMultiNodeTest) Run(cfg *config.Config) error {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Transaction Multi-Node Test")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Validate configuration
	blobCfg := cfg.Test.BlobTest
	if blobCfg.BlobCount < 1 || blobCfg.BlobCount > blob.MaxBlobsPerTransaction {
		return fmt.Errorf("invalid blob count: %d (must be 1-%d)", blobCfg.BlobCount, blob.MaxBlobsPerTransaction)
	}

	// Get node indices
	nodeIndices := blobCfg.MultiNodeIndices
	if len(nodeIndices) == 0 {
		// Default: use all nodes
		nodeIndices = make([]int, len(cfg.P2P.BootstrapNodes))
		for i := range nodeIndices {
			nodeIndices[i] = i
		}
	}

	if len(nodeIndices) == 0 {
		return fmt.Errorf("no nodes configured")
	}

	fmt.Printf("📍 Target Nodes: %d nodes\n", len(nodeIndices))
	for _, idx := range nodeIndices {
		if idx >= len(cfg.P2P.BootstrapNodes) {
			return fmt.Errorf("invalid node index: %d", idx)
		}
		fmt.Printf("   - Node %d: %s\n", idx, cfg.GetNodeName(idx))
	}
	fmt.Printf("🧊 Blobs per transaction: %d\n", blobCfg.BlobCount)
	fmt.Printf("📊 Transactions per node: %d\n", blobCfg.TotalBlobTxs/len(nodeIndices))
	fmt.Println()

	// Initialize KZG
	fmt.Println("🔧 Initializing KZG trusted setup...")
	if err := blob.InitKZG(); err != nil {
		return fmt.Errorf("failed to initialize KZG: %w", err)
	}
	fmt.Println("✅ KZG initialized successfully")
	fmt.Println()

	// Get accounts
	if len(cfg.Accounts) == 0 {
		return fmt.Errorf("no accounts configured")
	}

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

	// Statistics tracking
	type NodeStats struct {
		NodeIndex int
		NodeName  string
		Success   int
		Failed    int
		TotalSent int
		Duration  time.Duration
	}

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		nodeStats  = make([]*NodeStats, len(nodeIndices))
		globalFail int
	)

	startTime := time.Now()

	// Send transactions to each node concurrently
	for i, nodeIdx := range nodeIndices {
		wg.Add(1)
		go func(i, nodeIdx int) {
			defer wg.Done()

			stats := &NodeStats{
				NodeIndex: nodeIdx,
				NodeName:  cfg.GetNodeName(nodeIdx),
			}
			nodeStats[i] = stats

			nodeStartTime := time.Now()

			// Create client for this node
			client, err := ethclient.NewClient(cfg, nodeIdx)
			if err != nil {
				fmt.Printf("❌ Node %d (%s): Failed to create client: %v\n", nodeIdx, stats.NodeName, err)
				mu.Lock()
				globalFail++
				mu.Unlock()
				return
			}

			fmt.Printf("✅ Node %d (%s): Connected\n", nodeIdx, stats.NodeName)

			// Calculate transactions for this node
			totalTxs := blobCfg.TotalBlobTxs / len(nodeIndices)
			if totalTxs == 0 {
				totalTxs = 1
			}

			// Get accounts for this node
			accountIdx := i % len(cfg.Accounts)
			fromAccount := cfg.Accounts[accountIdx]
			toAccount := cfg.Accounts[(accountIdx+1)%len(cfg.Accounts)]

			// Resolve nonce for this node
			nonceStr := "auto" // default to auto
			if nodeIdx < len(blobCfg.MultiNodeNonces) && blobCfg.MultiNodeNonces[nodeIdx] != "" {
				nonceStr = blobCfg.MultiNodeNonces[nodeIdx]
			}

			nonce, err := utils.ResolveNonce(client, nonceStr, common.HexToAddress(fromAccount.Address))
			if err != nil {
				fmt.Printf("❌ Node %d (%s): Failed to resolve nonce: %v\n", nodeIdx, stats.NodeName, err)
				mu.Lock()
				globalFail++
				mu.Unlock()
				return
			}

			// Send transactions
			for j := 0; j < totalTxs; j++ {
				// Build blob transaction
				builder := transaction.NewBlobTxBuilder(cfg.ChainID).
					WithFrom(fromAccount).
					WithTo(toAccount).
					WithNonce(nonce).
					WithMaxFeePerBlobGas(maxFeePerBlobGas)

				// Generate and add blobs
				success := true
				for k := 0; k < blobCfg.BlobCount; k++ {
					blobSize := blobCfg.BlobDataSize
					if blobSize == 0 {
						blobSize = blob.BlobDataSize
					}

					blobData, err := blob.GenerateBlob(generatorType, blobSize)
					if err != nil {
						success = false
						break
					}

					if err := builder.AddBlobData(blobData); err != nil {
						success = false
						break
					}
				}

				if !success {
					stats.Failed++
					continue
				}

				// Build and send
				blobTx, err := builder.Build()
				if err != nil {
					stats.Failed++
					continue
				}

				opts := transaction.DefaultSendOptions()
				opts.Verify = false

				_, err = transaction.SendBlob(client, blobTx, opts)
				if err != nil {
					stats.Failed++
				} else {
					stats.Success++
				}

				stats.TotalSent++
				nonce++

				// Delay between transactions
				if j < totalTxs-1 && blobCfg.SendInterval > 0 {
					time.Sleep(time.Duration(blobCfg.SendInterval) * time.Millisecond)
				}
			}

			stats.Duration = time.Since(nodeStartTime)
			fmt.Printf("✅ Node %d (%s): Completed - %d success, %d failed\n",
				nodeIdx, stats.NodeName, stats.Success, stats.Failed)

		}(i, nodeIdx)
	}

	// Wait for all nodes to complete
	wg.Wait()
	totalDuration := time.Since(startTime)

	// Print summary
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Test Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	totalSuccess := 0
	totalFailed := 0

	fmt.Println("Per-Node Statistics:")
	for _, stats := range nodeStats {
		if stats == nil {
			continue
		}
		fmt.Printf("\n  Node %d (%s):\n", stats.NodeIndex, stats.NodeName)
		fmt.Printf("    ✅ Successful: %d\n", stats.Success)
		fmt.Printf("    ❌ Failed: %d\n", stats.Failed)
		fmt.Printf("    📊 Total: %d\n", stats.TotalSent)
		fmt.Printf("    ⏱️  Duration: %v\n", stats.Duration)
		if stats.Success > 0 && stats.Duration > 0 {
			fmt.Printf("    📈 Rate: %.2f tx/sec\n", float64(stats.Success)/stats.Duration.Seconds())
		}

		totalSuccess += stats.Success
		totalFailed += stats.Failed
	}

	fmt.Println()
	fmt.Println("Overall Statistics:")
	fmt.Printf("  ✅ Total Successful: %d\n", totalSuccess)
	fmt.Printf("  ❌ Total Failed: %d\n", totalFailed)
	fmt.Printf("  ⏱️  Total Duration: %v\n", totalDuration)
	if totalSuccess > 0 {
		fmt.Printf("  📊 Overall Rate: %.2f tx/sec\n", float64(totalSuccess)/totalDuration.Seconds())
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Blob Multi-Node Test - Completed")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if totalFailed > 0 {
		return fmt.Errorf("test completed with %d failures", totalFailed)
	}

	return nil
}
