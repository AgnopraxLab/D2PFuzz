package main

import (
	"fmt"
	"log"
	"os"

	"D2PFuzz/config"
)

func main() {
	fmt.Println("Starting D2PFuzz...")

	// Load configuration
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Print loaded configuration
	cfg.PrintConfig()

	// Initialize components based on configuration
	if cfg.IsFuzzingEnabled() {
		fmt.Println("Initializing fuzzing engine...")
		fmt.Printf("Target protocols: %v\n", cfg.Fuzzing.Protocols)
		fmt.Printf("Max iterations: %d\n", cfg.Fuzzing.MaxIterations)
	}

	if cfg.IsMonitoringEnabled() {
		fmt.Println("Initializing monitoring system...")
		fmt.Printf("Metrics port: %d\n", cfg.Monitoring.MetricsPort)
		fmt.Printf("Log level: %s\n", cfg.Monitoring.LogLevel)
	}

	// Initialize P2P network
	fmt.Println("Initializing P2P network...")
	fmt.Printf("Listen port: %d\n", cfg.P2P.ListenPort)
	fmt.Printf("Max peers: %d\n", cfg.P2P.MaxPeers)
	fmt.Printf("Bootstrap nodes: %d configured\n", len(cfg.P2P.BootstrapNodes))

	// Create output directories if they don't exist
	if err := os.MkdirAll(cfg.GetOutputPath(), 0755); err != nil {
		log.Printf("Warning: Failed to create output directory: %v", err)
	}

	if err := os.MkdirAll(cfg.GetReportPath(), 0755); err != nil {
		log.Printf("Warning: Failed to create report directory: %v", err)
	}

	fmt.Println("D2PFuzz initialization completed successfully!")
	fmt.Println("Configuration loaded and validated.")
	fmt.Println("Ready to start fuzzing operations...")
}
