package testing

import (
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
)

// TestNewPooledTransactionHashesSoftLimitWithNonceDetailed tests with custom starting nonce and returns detailed results
func TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(cfg *config.Config, nodeIndex int, hashCount int, startNonce uint64) (int, string, error) {
	fmt.Print("  Preparing test... ")

	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to create suite: %v", err)
	}

	// Generate transactions
	var (
		from    = config.PredefinedAccounts[0].PrivateKey
		nonce   = startNonce
		hashes  = make([]common.Hash, hashCount)
		txTypes = make([]byte, hashCount)
		sizes   = make([]uint32, hashCount)
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to generate private key: %v", err)
	}

	fmt.Print("Done\n  Generating transactions... ")
	for i := 0; i < hashCount; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   cfg.ChainID,
			Nonce:     nonce + uint64(i),
			GasTipCap: cfg.DefaultGasTipCap,
			GasFeeCap: cfg.DefaultGasFeeCap,
			Gas:       21000,
		}
		tx := types.NewTx(inner)
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(cfg.ChainID), prik)
		if err != nil {
			return 0, "ERROR", fmt.Errorf("failed to sign tx: %v", err)
		}
		hashes[i] = signedTx.Hash()
		txTypes[i] = signedTx.Type()
		sizes[i] = uint32(signedTx.Size())
	}
	fmt.Print("Done\n  Connecting to peer... ")

	// Connect to node
	conn, err := s.Dial()
	if err != nil {
		return 0, "ERROR", fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return 0, "ERROR", fmt.Errorf("peering failed: %v", err)
	}
	fmt.Print("Done\n  Sending announcement... ")

	// Send announcement
	ann := eth.NewPooledTransactionHashesPacket{
		Types:  txTypes,
		Sizes:  sizes,
		Hashes: hashes,
	}

	startTime := time.Now()
	err = conn.Write(1, eth.NewPooledTransactionHashesMsg, ann)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to write to connection: %v", err)
	}
	fmt.Print("Done\n  Waiting for response... ")

	// Set timeout
	timeout := 30*time.Second + time.Duration(hashCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to set read deadline: %v", err)
	}

	// Wait for node response
	for {
		msg, err := conn.ReadEth()
		if err != nil {
			if err == io.EOF {
				return 0, "DISCONNECT", nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, "TIMEOUT", nil
			}
			return 0, "ERROR", fmt.Errorf("failed to read eth msg: %v", err)
		}

		switch msg := msg.(type) {
		case *eth.GetPooledTransactionsPacket:
			elapsed := time.Since(startTime)
			requestedCount := len(msg.GetPooledTransactionsRequest)
			fmt.Printf("Done (%.2fs)\n", elapsed.Seconds())
			return requestedCount, "SUCCESS", nil

		case *eth.NewPooledTransactionHashesPacket:
			continue
		case *eth.TransactionsPacket:
			continue
		default:
			continue
		}
	}
}

// runQuietTestWithNonce runs a test with custom starting nonce
func runQuietTestWithNonce(cfg *config.Config, nodeIndex int, hashCount int, startNonce uint64) (int, string) {
	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return 0, "ERROR"
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return 0, "ERROR"
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return 0, "ERROR"
	}

	// Generate transactions
	var (
		from    = config.PredefinedAccounts[0].PrivateKey
		nonce   = startNonce
		hashes  = make([]common.Hash, hashCount)
		txTypes = make([]byte, hashCount)
		sizes   = make([]uint32, hashCount)
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return 0, "ERROR"
	}

	for i := 0; i < hashCount; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   cfg.ChainID,
			Nonce:     nonce + uint64(i),
			GasTipCap: cfg.DefaultGasTipCap,
			GasFeeCap: cfg.DefaultGasFeeCap,
			Gas:       21000,
		}
		tx := types.NewTx(inner)
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(cfg.ChainID), prik)
		if err != nil {
			return 0, "ERROR"
		}
		hashes[i] = signedTx.Hash()
		txTypes[i] = signedTx.Type()
		sizes[i] = uint32(signedTx.Size())
	}

	// Connect and send
	conn, err := s.Dial()
	if err != nil {
		return 0, "ERROR"
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return 0, "ERROR"
	}

	ann := eth.NewPooledTransactionHashesPacket{
		Types:  txTypes,
		Sizes:  sizes,
		Hashes: hashes,
	}

	err = conn.Write(1, eth.NewPooledTransactionHashesMsg, ann)
	if err != nil {
		return 0, "ERROR"
	}

	// Dynamic timeout based on transaction count
	timeout := 30*time.Second + time.Duration(hashCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return 0, "ERROR"
	}

	// Wait for response
	for {
		msg, err := conn.ReadEth()
		if err != nil {
			if err == io.EOF {
				return 0, "DISCONNECT"
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, "TIMEOUT"
			}
			return 0, "ERROR"
		}

		switch msg := msg.(type) {
		case *eth.GetPooledTransactionsPacket:
			return len(msg.GetPooledTransactionsRequest), "SUCCESS"
		case *eth.NewPooledTransactionHashesPacket:
			continue
		case *eth.TransactionsPacket:
			continue
		default:
			continue
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestAllClientsSoftLimitImpl implements the test for all clients
func TestAllClientsSoftLimitImpl(cfg *config.Config) error {
	testCases := []struct {
		name  string
		count int
	}{
		{"Normal (50 items)", 50},
		{"Medium (1000 items)", 1000},
		{"At Limit (4096 items)", 4096},
		{"Over Limit (5000 items)", 5000},
		{"Well Over Limit (8192 items)", 8192},
		{"Extreme (10000 items)", 10000},
	}

	for nodeIndex := 0; nodeIndex < cfg.GetNodeCount(); nodeIndex++ {
		if nodeIndex >= len(cfg.P2P.BootstrapNodes) {
			fmt.Printf("Skipping node %d (no node configured)\n", nodeIndex)
			continue
		}

		nodeName := cfg.GetNodeName(nodeIndex)
		fmt.Printf("\n\n╔════════════════════════════════════════╗\n")
		fmt.Printf("║  Testing Client: %-20s ║\n", nodeName)
		fmt.Printf("╚════════════════════════════════════════╝\n")

		for _, tc := range testCases {
			fmt.Printf("\n--- Test Case: %s ---\n", tc.name)
			startNonce := uint64(math.MaxUint64) - uint64(tc.count)
			_, _, err := TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(cfg, nodeIndex, tc.count, startNonce)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			}

			// Wait before next test
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

// TestSoftLimitForReportImpl runs soft limit tests for all clients and generates a concise report
func TestSoftLimitForReportImpl(cfg *config.Config) error {
	// Test scenarios focusing on boundary values
	testCases := cfg.Test.SoftLimitScenarios
	if len(testCases) == 0 {
		testCases = []int{4096, 5000, 8192}
	}

	// Store results: clientName -> [announced]requested
	type TestResult struct {
		announced int
		requested int
		status    string // "PASS", "FAIL", "ERROR", "DISCONNECT"
	}
	results := make(map[string]map[int]TestResult)

	fmt.Println("\nTesting all clients with key scenarios...")
	fmt.Printf("Scenarios: %v\n", testCases)
	fmt.Println(strings.Repeat("=", 80))

	// Test each client
	for nodeIndex := 0; nodeIndex < cfg.GetNodeCount(); nodeIndex++ {
		if nodeIndex >= len(cfg.P2P.BootstrapNodes) {
			fmt.Printf("⚠ Skipping node %d (not configured)\n", nodeIndex)
			continue
		}

		clientName := cfg.GetNodeName(nodeIndex)
		results[clientName] = make(map[int]TestResult)
		fmt.Printf("\n[%s]\n", strings.ToUpper(clientName))

		for _, announced := range testCases {
			fmt.Printf("  Testing %d items... ", announced)

			// Retry mechanism for reliability
			var requested int
			var status string
			maxRetries := 2

			for attempt := 0; attempt <= maxRetries; attempt++ {
				startNonce := uint64(70) + uint64(attempt*10000)
				requested, status = runQuietTestWithNonce(cfg, nodeIndex, announced, startNonce)

				// If successful, break
				if status == "SUCCESS" {
					break
				}

				// If timeout or error, retry
				if attempt < maxRetries && (status == "TIMEOUT" || status == "ERROR") {
					fmt.Printf("retry...")
					time.Sleep(2 * time.Second)
					continue
				}
			}

			results[clientName][announced] = TestResult{
				announced: announced,
				requested: requested,
				status:    status,
			}

			// Print concise result
			percentage := float64(requested) * 100.0 / float64(announced)
			symbol := "✓"
			if requested < announced && announced > 4096 {
				symbol = "⚠"
			}
			if status == "ERROR" || status == "TIMEOUT" || status == "DISCONNECT" {
				symbol = "❌"
			}

			fmt.Printf("%s %d/%d (%.0f%%) [%s]\n", symbol, requested, announced, percentage, status)

			time.Sleep(1 * time.Second)
		}
	}

	// Generate report table
	fmt.Println("\n" + strings.Repeat("=", 88))
	fmt.Println("                    SOFT LIMIT TEST REPORT")
	fmt.Println(strings.Repeat("=", 88))
	fmt.Printf("%-12s | ", "Client")
	for _, tc := range testCases {
		fmt.Printf("%-10s | ", fmt.Sprintf("%d items", tc))
	}
	fmt.Printf("%-25s\n", "Status")
	fmt.Println(strings.Repeat("-", 88))

	passCount := 0
	for nodeIndex := 0; nodeIndex < cfg.GetNodeCount(); nodeIndex++ {
		clientName := cfg.GetNodeName(nodeIndex)
		if _, exists := results[clientName]; !exists {
			continue
		}

		fmt.Printf("%-12s | ", clientName)

		// Check status
		allSuccess := true
		hasLimit := false
		for _, tc := range testCases {
			r := results[clientName][tc]
			fmt.Printf("%4d (%3.0f%%) | ", r.requested, float64(r.requested)*100.0/float64(tc))

			if r.status != "SUCCESS" {
				allSuccess = false
			}
			if tc > 4096 && r.requested == 4096 {
				hasLimit = true
			}
		}

		// Determine status
		status := ""
		if !allSuccess {
			status = "❌ ERROR/TIMEOUT"
		} else if hasLimit {
			status = "✅ PASS"
			passCount++
		} else {
			status = "❌ FAIL (No limit)"
		}

		fmt.Printf("%-25s\n", status)
	}

	fmt.Println(strings.Repeat("=", 88))
	fmt.Printf("\nSummary: %d/%d clients correctly enforce the 4096 soft limit\n",
		passCount, len(results))
	fmt.Println("\nStatus Legend:")
	fmt.Println("  ✅ PASS         - Correctly enforces 4096 soft limit")
	fmt.Println("  ❌ FAIL         - No limit enforced (accepts all)")
	fmt.Println("  ⚠ PARTIAL      - Has custom limit < 4096")
	fmt.Println("  ❌ ERROR       - Test error occurred")

	return nil
}
