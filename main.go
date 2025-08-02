package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"D2PFuzz/config"
	"D2PFuzz/p2p"
	"D2PFuzz/utils"
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

	// Initialize P2P network
	logger.Info("Initializing P2P network...")
	logger.Info("Listen port: %d", cfg.P2P.ListenPort)
	logger.Info("Max peers: %d", cfg.P2P.MaxPeers)
	logger.Info("Bootstrap nodes: %d configured", len(cfg.P2P.BootstrapNodes))

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

	// Initialize P2P manager
	p2pManager, err := p2p.NewManager(&p2p.Config{
		MaxPeers:       cfg.P2P.MaxPeers,
		ListenPort:     cfg.P2P.ListenPort,
		BootstrapNodes: cfg.P2P.BootstrapNodes,
	}, logger)
	if err != nil {
		logger.Fatal("Failed to create P2P manager: %v", err)
	}

	// Start P2P manager if fuzzing is enabled
	if cfg.IsFuzzingEnabled() {
		logger.Info("Starting P2P fuzzing operations...")
		if err := p2pManager.Start(); err != nil {
			logger.Fatal("Failed to start P2P manager: %v", err)
		}
		logger.Info("P2P fuzzing started successfully")
	}

	logger.Info("D2PFuzz initialization completed!")
	logger.Info("Configuration loaded and validated.")
	logger.Info("Ready to start fuzzing operations...")

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Main loop - print stats periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			logger.Info("Received shutdown signal, stopping D2PFuzz...")
			if err := p2pManager.Stop(); err != nil {
				logger.Error("Error stopping P2P manager: %v", err)
			}
			logger.Info("D2PFuzz stopped gracefully")
			return
		case <-ticker.C:
			// Print periodic stats
			stats := p2pManager.GetStats()
			fuzzStats := p2pManager.GetFuzzingStats()
			logger.Info("P2P Stats - Connected: %d/%d peers, Messages sent: %d, received: %d",
				stats["connected_peers"], stats["max_peers"],
				fuzzStats.MessagesSent, fuzzStats.MessagesReceived)
		}
	}
}
