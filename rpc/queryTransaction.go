package rpc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// QueryDetailedTransactionStatus queries detailed pending/queued status via RPC
func (c *RPCClient) QueryDetailedTransactionStatus(txHash common.Hash) error {
	// Query both methods concurrently for better performance
	type result struct {
		txpoolStatus string
		txStatus     string
		err          error
	}

	results := make(chan result, 2)

	// Query txpool_content
	go func() {
		txpoolStatus, err := c.QueryTxpoolContent(txHash)
		results <- result{txpoolStatus: txpoolStatus, err: err}
	}()

	// Query eth_getTransactionByHash
	go func() {
		txStatus, err := c.QueryTransactionByHash(txHash)
		results <- result{txStatus: txStatus, err: err}
	}()

	// Collect results
	var txpoolStatus, txStatus string
	for i := 0; i < 2; i++ {
		res := <-results
		if res.err != nil {
			return fmt.Errorf("RPC query failed: %v", res.err)
		}
		if res.txpoolStatus != "" {
			txpoolStatus = res.txpoolStatus
		}
		if res.txStatus != "" {
			txStatus = res.txStatus
		}
	}

	// Display comprehensive status analysis
	fmt.Printf("✅ Success\n")
	fmt.Println()
	fmt.Println("📋 Transaction Status:")
	fmt.Printf("🔗 Hash: %s\n", txHash.Hex())

	// Determine overall status
	var overallStatus string
	var statusEmoji string

	if txStatus == "mined" {
		overallStatus = "MINED (packed into block)"
		statusEmoji = "✅"
	} else if txpoolStatus == "queued" {
		overallStatus = "QUEUED (waiting for conditions)"
		statusEmoji = "⏸️"
	} else if txpoolStatus == "pending" || txStatus == "pending" {
		overallStatus = "PENDING (waiting in mempool)"
		statusEmoji = "⏳"
	} else {
		overallStatus = "NOT FOUND"
		statusEmoji = "❌"
	}

	fmt.Printf("%s Status: %s\n", statusEmoji, overallStatus)

	return nil
}

// QueryTxpoolContent queries txpool_content to get pending/queued status
func (c *RPCClient) QueryTxpoolContent(txHash common.Hash) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result map[string]interface{}
	err := c.CallContext(ctx, &result, "txpool_content")
	if err != nil {
		return "", err
	}

	// Parse results - txpool_content uses nonce as key, not transaction hash
	txHashStr := txHash.Hex()

	// Check pending
	if pending, exists := result["pending"]; exists {
		if pendingMap, ok := pending.(map[string]interface{}); ok {
			for _, accountTxs := range pendingMap {
				if txMap, ok := accountTxs.(map[string]interface{}); ok {
					for _, txData := range txMap {
						if txInfo, ok := txData.(map[string]interface{}); ok {
							if txHashInPool, exists := txInfo["hash"]; exists {
								if txHashStrInPool, ok := txHashInPool.(string); ok {
									if strings.EqualFold(txHashStrInPool, txHashStr) {
										return "pending", nil
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Check queued
	if queued, exists := result["queued"]; exists {
		if queuedMap, ok := queued.(map[string]interface{}); ok {
			for _, accountTxs := range queuedMap {
				if txMap, ok := accountTxs.(map[string]interface{}); ok {
					for _, txData := range txMap {
						if txInfo, ok := txData.(map[string]interface{}); ok {
							if txHashInPool, exists := txInfo["hash"]; exists {
								if txHashStrInPool, ok := txHashInPool.(string); ok {
									if strings.EqualFold(txHashStrInPool, txHashStr) {
										return "queued", nil
									}
								}
							}
						}
					}
				}
			}
		}
	}

	fmt.Printf("❌ Transaction NOT FOUND in txpool_content\n")
	return "not_found", nil
}

// QueryTransactionByHash queries eth_getTransactionByHash
func (c *RPCClient) QueryTransactionByHash(txHash common.Hash) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result map[string]interface{}
	err := c.CallContext(ctx, &result, "eth_getTransactionByHash", txHash.Hex())
	if err != nil {
		return "", err
	}

	// Parse results directly (eth_getTransactionByHash returns the data directly, not nested in "result")
	if result == nil {
		return "not_found", nil
	}

	if blockNumber, exists := result["blockNumber"]; exists {
		if blockNumber == nil || blockNumber == "0x" {
			return "pending", nil
		} else {
			return "mined", nil
		}
	}

	return "not_found", nil
}
