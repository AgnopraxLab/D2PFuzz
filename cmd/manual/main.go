package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/testing"
)

const version = "1.0"

func main() {
	// Command line flags
	configPath := flag.String("config", "./config.yaml", "Path to configuration file (default: ./config.yaml in manual directory)")
	testMode := flag.String("mode", "", "Test mode (overrides config file)")
	listModes := flag.Bool("list", false, "List all available test modes")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("D2PFuzz Manual Testing Tool v%s\n", version)
		return
	}

	// List available test modes
	if *listModes {
		testing.ListAvailableTests()
		return
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	// Determine test mode (command line overrides config file)
	mode := *testMode
	if mode == "" {
		mode = cfg.GetTestMode()
	}

	if mode == "" {
		log.Fatal("No test mode specified. Use -mode flag or set test.mode in config.yaml")
	}

	// Get the test runner
	runner, ok := testing.GetRunner(mode)
	if !ok {
		log.Fatalf("Unknown test mode: %s\n\nAvailable modes:\n", mode)
		testing.ListAvailableTests()
		os.Exit(1)
	}

	// Print banner
	fmt.Println("╔═══════════════════════════════════════════════════════╗")
	fmt.Printf("║  D2PFuzz Manual Testing Tool v%-23s║\n", version)
	fmt.Printf("║  Test Mode: %-42s║\n", runner.Name())
	fmt.Println("╚═══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Run the test
	if err := runner.Run(cfg); err != nil {
		log.Fatalf("Test failed: %v", err)
	}

	fmt.Println("\n✅ Test completed successfully!")
}
