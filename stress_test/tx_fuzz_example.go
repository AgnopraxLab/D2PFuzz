package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/fuzzer"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// displayStats shows real-time statistics
func displayStats(txFuzzer *fuzzer.TxFuzzer, ticker <-chan time.Time) {
	for range ticker {
		stats := txFuzzer.GetStats()
		fmt.Printf("\n--- Stats (Runtime: %v) ---\n", time.Since(stats.StartTime).Round(time.Second))
		fmt.Printf("Total Sent: %d | Mined: %d | Failed: %d | Pending: %d\n",
			stats.TotalSent, stats.TotalMined, stats.TotalFailed, stats.TotalPending)
		fmt.Printf("Mutation Used: %d | Random Used: %d\n",
			stats.MutationUsed, stats.RandomUsed)

		if stats.TotalSent > 0 {
			successRate := float64(stats.TotalMined) / float64(stats.TotalSent) * 100
			mutationRate := float64(stats.MutationUsed) / float64(stats.TotalSent) * 100
			fmt.Printf("Success Rate: %.1f%% | Mutation Rate: %.1f%%\n", successRate, mutationRate)
		}
	}
}

// displayFinalStats shows comprehensive final statistics
func displayFinalStats(txFuzzer *fuzzer.TxFuzzer) {
	stats := txFuzzer.GetStats()
	totalRuntime := time.Since(stats.StartTime)

	fmt.Printf("Total Runtime: %v\n", totalRuntime.Round(time.Second))
	fmt.Printf("Total Transactions Sent: %d\n", stats.TotalSent)
	fmt.Printf("Successfully Mined: %d\n", stats.TotalMined)
	fmt.Printf("Failed Transactions: %d\n", stats.TotalFailed)
	fmt.Printf("Still Pending: %d\n", stats.TotalPending)
	fmt.Printf("Mutation Used: %d\n", stats.MutationUsed)
	fmt.Printf("Random Generation Used: %d\n", stats.RandomUsed)

	if stats.TotalSent > 0 {
		successRate := float64(stats.TotalMined) / float64(stats.TotalSent) * 100
		mutationRate := float64(stats.MutationUsed) / float64(stats.TotalSent) * 100
		txPerSecond := float64(stats.TotalSent) / totalRuntime.Seconds()

		fmt.Printf("Success Rate: %.2f%%\n", successRate)
		fmt.Printf("Mutation Rate: %.2f%%\n", mutationRate)
		fmt.Printf("Average TPS: %.2f\n", txPerSecond)
	}
}

// exportTransactionRecords exports detailed transaction records
func exportTransactionRecords(txFuzzer *fuzzer.TxFuzzer, filename string, logger *utils.Logger) error {
	records := txFuzzer.GetTransactionRecords()

	// Create summary data
	summary := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"total_records": len(records),
		"statistics":    txFuzzer.GetStats(),
		"transactions":  records,
	}

	// Export as JSON
	jsonData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	logger.Info("Exported %d transaction records to %s", len(records), filename)
	return nil
}

func main() {
	fmt.Println("=== D2PFuzz Transaction Fuzzing Example ===")

	// Load configuration
	configPath := "./config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := utils.NewLogger(cfg.GetLogPath())
	fmt.Println("cfg.GetLogPath(): ", cfg.GetLogPath())
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()

	// Check if transaction fuzzing is enabled
	if !cfg.IsTxFuzzingEnabled() {
		logger.Info("Transaction fuzzing is disabled in configuration. Please enable it in config.yaml")
		return
	}

	// Get accounts for fuzzing
	accounts := cfg.GetAccountss()
	if len(accounts) == 0 {
		logger.Error("No accounts found in configuration")
		fmt.Println("No accounts found. Please add accounts to config.yaml")
		return
	}

	logger.Info("Found %d accounts for transaction fuzzing", len(accounts))
	fmt.Printf("Using %d accounts for transaction fuzzing\n", len(accounts))

	// Create transaction fuzzing configuration with mutation support
	txCfg := cfg.GetTxFuzzingConfig()

	// Get RPC endpoints from config.yaml
	rpcEndpoints := []string{
		"http://172.16.0.11:8545",
		"http://172.16.0.12:8545",
		"http://172.16.0.13:8545",
		"http://172.16.0.14:8545",
		"http://172.16.0.15:8545",
	}

	// Create multi-node configuration
	multiNodeConfig := &fuzzer.MultiNodeConfig{
		RPCEndpoints: rpcEndpoints,
		LoadDistribution: map[string]float64{
			"http://172.16.0.11:8545": 0.2,
			"http://172.16.0.12:8545": 0.2,
			"http://172.16.0.13:8545": 0.2,
			"http://172.16.0.14:8545": 0.2,
			"http://172.16.0.15:8545": 0.2,
		},
		FailoverEnabled:     true,
		HealthCheckInterval: 30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
	}

	// Create load pattern configuration
	loadPattern := &fuzzer.LoadPattern{
		Type:        "ramp",
		StartTPS:    5,
		PeakTPS:     txCfg.TxPerSecond,
		RampTime:    30 * time.Second,
		SustainTime: 60 * time.Second,
		StepSize:    2,
	}

	fuzzConfig := &fuzzer.TxFuzzConfig{
		RPCEndpoint:     rpcEndpoints[0], // Primary endpoint
		ChainID:         txCfg.ChainID,
		MaxGasPrice:     big.NewInt(txCfg.MaxGasPrice),
		MaxGasLimit:     txCfg.MaxGasLimit,
		TxPerSecond:     txCfg.TxPerSecond,
		FuzzDuration:    time.Duration(txCfg.FuzzDurationSec) * time.Second,
		Seed:            txCfg.Seed,
		UseMutation:     true, // Enable mutation
		MutationRatio:   0.3,  // 30% of transactions use mutation
		EnableTracking:  true, // Enable transaction tracking
		OutputFile:      "output/tx_fuzz_results.json",
		ConfirmBlocks:   3,                              // Wait for 3 confirmation blocks
		SuccessHashFile: "output/success_tx_hashes.txt", // Successful transaction hash file
		FailedHashFile:  "output/failed_tx_hashes.txt",  // Failed transaction hash file
		MultiNode:       multiNodeConfig,                // Multi-node configuration
		LoadPattern:     loadPattern,                    // Load pattern configuration
		EnableMetrics:   true,                           // Enable system metrics
		MetricsInterval: 10 * time.Second,               // Metrics collection interval
	}

	fmt.Printf("Configuration:\n")
	fmt.Printf("  RPC Endpoint: %s\n", fuzzConfig.RPCEndpoint)
	fmt.Printf("  Chain ID: %d\n", fuzzConfig.ChainID)
	fmt.Printf("  Max Gas Price: %s wei\n", fuzzConfig.MaxGasPrice.String())
	fmt.Printf("  Max Gas Limit: %d\n", fuzzConfig.MaxGasLimit)
	fmt.Printf("  Transactions per second: %d\n", fuzzConfig.TxPerSecond)
	fmt.Printf("  Fuzz duration: %v\n", fuzzConfig.FuzzDuration)
	fmt.Printf("  Mutation enabled: %v\n", fuzzConfig.UseMutation)
	fmt.Printf("  Mutation ratio: %.1f%%\n", fuzzConfig.MutationRatio*100)
	fmt.Printf("  Transaction tracking: %v\n", fuzzConfig.EnableTracking)
	fmt.Printf("  Confirmation blocks: %d\n", fuzzConfig.ConfirmBlocks)

	// Create enhanced transaction fuzzer with multi-node support
	txFuzzer, err := fuzzer.NewTxFuzzer(fuzzConfig, accounts, *logger)
	if err != nil {
		log.Fatalf("Failed to create transaction fuzzer: %v", err)
	}
	defer txFuzzer.Close()

	// Setup graceful shutdown with context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, stopping fuzzer...")
		cancel()
	}()

	// Start transaction fuzzing
	fmt.Println("\nStarting enhanced transaction fuzzing with multi-node support...")
	logger.Info("Starting enhanced transaction fuzzing example")

	// Start statistics display goroutine
	statsTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()
	go displayStats(txFuzzer, statsTicker.C)

	// Start the enhanced fuzzing process with context
	go func() {
		err := txFuzzer.StartWithContext(ctx, fuzzConfig)
		if err != nil {
			logger.Error("Transaction fuzzing error: %v", err)
		}
	}()

	fmt.Println("Enhanced transaction fuzzing started. Press Ctrl+C to stop.")

	// Wait for signal or timeout
	select {
	case <-ctx.Done():
		fmt.Println("\nReceived interrupt signal, stopping...")
		logger.Info("Received interrupt signal, stopping transaction fuzzing")
	case <-time.After(fuzzConfig.FuzzDuration):
		fmt.Println("\nFuzzing duration completed")
		logger.Info("Transaction fuzzing duration completed")
		cancel()
	}

	// Stop transaction fuzzing
	txFuzzer.Stop()
	fmt.Println("Enhanced transaction fuzzing stopped.")

	// Display final statistics
	fmt.Println("\n=== Final Statistics ===")
	displayFinalStats(txFuzzer)

	// Export transaction records if enabled
	if fuzzConfig.EnableTracking {
		err = exportTransactionRecords(txFuzzer, fuzzConfig.OutputFile, logger)
		if err != nil {
			logger.Error("Failed to export transaction records: %v", err)
		} else {
			fmt.Printf("Transaction records exported to: %s\n", fuzzConfig.OutputFile)
		}
	}

	// Export success and failed transaction hashes
	if fuzzConfig.SuccessHashFile != "" {
		successHashes := txFuzzer.GetSuccessHashes()
		if len(successHashes) > 0 {
			err = txFuzzer.ExportSuccessHashes(fuzzConfig.SuccessHashFile)
			if err != nil {
				logger.Error("Failed to export success hashes: %v", err)
			} else {
				fmt.Printf("Success transaction hashes (%d) exported to: %s\n", len(successHashes), fuzzConfig.SuccessHashFile)
				logger.Info("Exported %d success transaction hashes to %s", len(successHashes), fuzzConfig.SuccessHashFile)
			}
		} else {
			fmt.Println("No successful transactions to export")
		}
	}

	if fuzzConfig.FailedHashFile != "" {
		failedHashes := txFuzzer.GetFailedHashes()
		if len(failedHashes) > 0 {
			err = txFuzzer.ExportFailedHashes(fuzzConfig.FailedHashFile)
			if err != nil {
				logger.Error("Failed to export failed hashes: %v", err)
			} else {
				fmt.Printf("Failed transaction hashes (%d) exported to: %s\n", len(failedHashes), fuzzConfig.FailedHashFile)
				logger.Info("Exported %d failed transaction hashes to %s", len(failedHashes), fuzzConfig.FailedHashFile)
			}
		} else {
			fmt.Println("No failed transactions to export")
		}
	}

	logger.Info("Transaction fuzzing example completed")
}
