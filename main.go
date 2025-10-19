package main

import (
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/fuzzer"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

func main() {
	// Load configuration first to get report directory
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, err := utils.NewLogger(cfg.GetLogPath())
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("Starting D2PFuzz...")

	// Print loaded configuration
	cfg.PrintConfig()

	// Initialize components based on configuration
	if cfg.IsFuzzingEnabled() {
		logger.Info("Initializing fuzzing engine...")
		logger.Info("Target protocols: %v", cfg.Fuzzing.Protocols)
		logger.Info("Max iterations: %d", cfg.Fuzzing.MaxIterations)
	}

	if cfg.IsMonitoringEnabled() {
		logger.Info("Initializing monitoring system...")
		logger.Info("Metrics port: %d", cfg.Monitoring.MetricsPort)
		logger.Info("Log level: %s", cfg.Monitoring.LogLevel)
	}

	// Initialize transaction fuzzing if enabled
	if cfg.IsTxFuzzingEnabled() {
		logger.Info("Transaction fuzzing is enabled")
		accounts := cfg.GetAccountss()
		if len(accounts) == 0 {
			logger.Warn("No accounts found for transaction fuzzing")
		} else {
			logger.Info("Found %d accounts for transaction fuzzing", len(accounts))

			// Create fuzzer client
			fuzzClient, err := fuzzer.NewFuzzClient(*logger)
			if err != nil {
				logger.Error("Failed to create fuzz client: %v", err)
			} else {
				// Note: FuzzClient doesn't have Close method, cleanup is handled by Stop methods

				// Create transaction fuzzing configuration
				txCfg := cfg.GetTxFuzzingConfig()
				fuzzConfig := &fuzzer.TxFuzzConfig{
					RPCEndpoint:  txCfg.RPCEndpoint,
					ChainID:      txCfg.ChainID,
					MaxGasPrice:  big.NewInt(txCfg.MaxGasPrice),
					MaxGasLimit:  txCfg.MaxGasLimit,
					TxPerSecond:  txCfg.TxPerSecond,
					FuzzDuration: time.Duration(txCfg.FuzzDurationSec) * time.Second,
					Seed:         txCfg.Seed,
				}

				// Start transaction fuzzing
				err = fuzzClient.StartTxFuzzing(fuzzConfig, accounts)
				if err != nil {
					logger.Error("Failed to start transaction fuzzing: %v", err)
				} else {
					logger.Info("Transaction fuzzing started successfully")

					// Set up signal handling for graceful shutdown
					sigChan := make(chan os.Signal, 1)
					signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

					// Wait for signal or timeout
					select {
					case <-sigChan:
						logger.Info("Received interrupt signal, stopping transaction fuzzing")
					case <-time.After(fuzzConfig.FuzzDuration):
						logger.Info("Transaction fuzzing duration completed")
					}

					// Stop transaction fuzzing
					fuzzClient.StopTxFuzzing()
					logger.Info("Transaction fuzzing stopped")
				}
			}
		}
	}

	// Initialize P2P network
	logger.Info("Initializing P2P network...")
	logger.Info("Listen port: %d", cfg.P2P.ListenPort)
	logger.Info("Max peers: %d", cfg.P2P.MaxPeers)
	logger.Info("Bootstrap nodes: %d configured", len(cfg.P2P.BootstrapNodes))

	// Create fuzz client
	fuzzClient, err := fuzzer.NewFuzzClient(*logger)
	if err != nil {
		logger.Fatal("Failed to create fuzz client: %v", err)
	}
	fuzzClient.Start()

	// Create output directories if they don't exist
	logger.Info("Creating output directories...")

	outputPath := cfg.GetOutputPath()
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		logger.Fatal("Failed to create output directory '%s': %v", outputPath, err)
	}
	logger.Info("Output directory created/verified: %s", outputPath)

	reportPath := cfg.GetLogPath()
	if err := os.MkdirAll(reportPath, 0755); err != nil {
		logger.Fatal("Failed to create report directory '%s': %v", reportPath, err)
	}
	logger.Info("Report directory created/verified: %s", reportPath)

}
