package testing

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	gethclient "github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

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

	// Get test parameters - prefer new config section, fallback to legacy
	var nodeIndex int
	var count int
	var nonceStr string
	var fromAccountIndex int
	var toAccountIndex int
	var saveHashes bool

	if cfg.Test.LargeTxs.TransactionCount > 0 { // New config section detected
		nodeIndex = cfg.Test.LargeTxs.NodeIndex
		count = cfg.Test.LargeTxs.TransactionCount
		nonceStr = cfg.Test.LargeTxs.NonceStart
		fromAccountIndex = cfg.Test.LargeTxs.FromAccountIndex
		toAccountIndex = cfg.Test.LargeTxs.ToAccountIndex
		saveHashes = cfg.Test.LargeTxs.SaveHashes
		fmt.Println("📋 Using new large_transactions configuration section")
	} else { // Fallback to legacy fields
		nodeIndex = cfg.Test.SingleNodeIndex
		count = 10 // Default
		nonceStr = cfg.Test.SingleNodeNonce
		fromAccountIndex = 0
		toAccountIndex = 5
		saveHashes = true
		fmt.Println("📋 Using legacy configuration fields")
	}

	// Validate node index
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		nodeIndex = 0 // Default to first node
		fmt.Printf("⚠ Invalid node index, using default: %d\n", nodeIndex)
	}

	// Validate account indices
	if fromAccountIndex < 0 || fromAccountIndex >= len(config.PredefinedAccounts) {
		return fmt.Errorf("invalid from_account_index: %d", fromAccountIndex)
	}
	if toAccountIndex < 0 || toAccountIndex >= len(config.PredefinedAccounts) {
		return fmt.Errorf("invalid to_account_index: %d", toAccountIndex)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	fmt.Printf("🎯 Starting large transactions testing for %s (Node %d)...\n", nodeName, nodeIndex)
	fmt.Printf("📦 Transactions to send: %d\n", count)
	fmt.Printf("💳 From account: %s (index %d)\n", config.PredefinedAccounts[fromAccountIndex].Address, fromAccountIndex)
	fmt.Printf("📬 To account: %s (index %d)\n", config.PredefinedAccounts[toAccountIndex].Address, toAccountIndex)

	// Create client for nonce resolution
	client, err := ethclient.NewClient(cfg, nodeIndex)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Prepare RPC client for chain queries (block numbers, headers, receipts)
	nodeIP := client.GetNodeIP()
	rpcURL := fmt.Sprintf("http://%s:8545", nodeIP)
	rpcClient, err := gethclient.Dial(rpcURL)
	if err != nil {
		return fmt.Errorf("failed to connect RPC at %s: %w", rpcURL, err)
	}
	defer rpcClient.Close()

	// Resolve nonce (auto or specific value)
	fromAddress := common.HexToAddress(config.PredefinedAccounts[fromAccountIndex].Address)
	nonce, err := utils.ResolveNonce(client, nonceStr, fromAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve nonce: %w", err)
	}
	fmt.Printf("📋 Nonce resolved: %s -> %d\n", nonceStr, nonce)

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

	// Generate large batch of transactions
	var (
		from   = config.PredefinedAccounts[fromAccountIndex].PrivateKey
		txs    []*types.Transaction
		hashes []common.Hash
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	var to common.Address = common.HexToAddress(config.PredefinedAccounts[toAccountIndex].Address)

	fmt.Printf("\n📝 Generating %d transactions...\n", count)

	// Record start block height before sending
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		startBlock, err := rpcClient.BlockNumber(ctx)
		if err != nil {
			return fmt.Errorf("failed to get start block number: %w", err)
		}
		fmt.Printf("📍 Sending at block height: %d\n", startBlock)
	}
	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   cfg.ChainID,
			Nonce:     nonce + uint64(i),
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
	if len(hashes) > 0 {
		fmt.Printf("First transaction hash: %s\n", hashes[0].Hex())
		if len(hashes) > 1 {
			fmt.Printf("Last transaction hash:  %s\n", hashes[len(hashes)-1].Hex())
		}
	}

	// Poll receipts and print periodic tip height
	{
		confirmedAt := make(map[common.Hash]uint64, len(hashes))
		remaining := make(map[common.Hash]struct{}, len(hashes))
		for _, h := range hashes {
			remaining[h] = struct{}{}
		}

		pollInterval := 2 * time.Second
		maxWait := 2 * time.Minute
		deadline := time.Now().Add(maxWait)

		for {
			if len(remaining) == 0 || time.Now().After(deadline) {
				break
			}

			// Print current tip height
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			tip, err := rpcClient.BlockNumber(ctx)
			cancel()
			if err == nil {
				fmt.Printf("🔎 Query tip height: %d (confirmed %d/%d)\n", tip, len(confirmedAt), len(hashes))
			}

			// Check receipts for remaining hashes
			for h := range remaining {
				ctxR, cancelR := context.WithTimeout(context.Background(), 8*time.Second)
				rec, err := rpcClient.TransactionReceipt(ctxR, h)
				cancelR()
				if err == nil && rec != nil && rec.BlockNumber != nil {
					confirmedAt[h] = rec.BlockNumber.Uint64()
					delete(remaining, h)
				}
			}

			time.Sleep(pollInterval)
		}

		// Compute per-block gas utilization if we have any confirmations
		var (
			minBlock    uint64
			maxBlock    uint64
			initialized bool
		)
		for _, b := range confirmedAt {
			if !initialized || b < minBlock {
				minBlock = b
			}
			if !initialized || b > maxBlock {
				maxBlock = b
			}
			initialized = true
		}

		// If none confirmed, we still can show latest tip and exit
		if !initialized {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			tip, _ := rpcClient.BlockNumber(ctx)
			cancel()
			fmt.Printf("⚠ No receipts within wait window. Confirmed 0/%d. Tip: %d\n", len(hashes), tip)
		} else {
			// Determine start block (re-query to be precise around send time window)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			startBlock, err := rpcClient.BlockNumber(ctx)
			cancel()
			if err != nil {
				startBlock = minBlock // fallback
			}

			// For reporting, use the send-time start block previously printed is approximate.
			// Iterate from startBlock to maxBlock to report gas utilization
			fmt.Printf("\n📊 Block gas utilization from %d to %d:\n", startBlock, maxBlock)
			fullThreshold := 0.98
			for b := startBlock; b <= maxBlock; b++ {
				ctxH, cancelH := context.WithTimeout(context.Background(), 6*time.Second)
				header, err := rpcClient.HeaderByNumber(ctxH, new(big.Int).SetUint64(b))
				cancelH()
				if err != nil || header == nil {
					fmt.Printf("  #%d: (failed to fetch header)\n", b)
					continue
				}
				gasUsed := header.GasUsed
				gasLimit := header.GasLimit
				util := float64(gasUsed) / float64(gasLimit)
				fullMark := ""
				if util >= fullThreshold {
					fullMark = " (full)"
				}
				fmt.Printf("  #%d: GasUsed %d / GasLimit %d (%.2f%%%s)\n", b, gasUsed, gasLimit, util*100.0, fullMark)
			}

			// Summarize confirmations
			allConfirmed := len(confirmedAt) == len(hashes)
			if allConfirmed {
				blocksUsed := int64(maxBlock) - int64(startBlock) + 1
				fmt.Printf("\n✅ All %d transactions confirmed by block %d (span: %d blocks)\n", len(hashes), maxBlock, blocksUsed)
			} else {
				fmt.Printf("\nℹ Confirmed %d/%d transactions by block %d\n", len(confirmedAt), len(hashes), maxBlock)
			}
		}
	}

	// Write to file if enabled
	if saveHashes {
		if err := utils.WriteHashesToFile(hashes, cfg.Paths.TxHashes); err != nil {
			fmt.Printf("⚠ Failed to write hashes to file: %v\n", err)
		} else {
			fmt.Printf("📄 Transaction hashes saved to: %s\n", cfg.Paths.TxHashes)
		}
	}

	fmt.Printf("\n=== Large-Transaction Testing Completed ===\n")
	return nil
}
