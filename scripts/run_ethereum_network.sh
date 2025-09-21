#!/bin/bash

# Script: Automated Ethereum Network Deployment
# Author: Auto-generated
# Date: $(date)

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

set -e  # Exit on error

# Default configuration file
CONFIG_FILE="config.yaml"

# Function to display usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --config FILE    Specify YAML configuration file (default: config.yaml)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Use default config.yaml"
    echo "  $0 -c network_params.yaml    # Use custom configuration file"
    echo "  $0 --config my-config.yaml   # Use custom configuration file"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'"
            echo ""
            show_usage
            exit 1
            ;;
    esac
done

# Validate configuration file
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file '$CONFIG_FILE' not found!"
    echo "Please ensure the file exists or specify a different configuration file using -c option."
    exit 1
fi

echo "=== Starting Ethereum Network Deployment Script ==="
echo "Using configuration file: $CONFIG_FILE"

# 1. Update Kurtosis
echo "Step 1: Updating Kurtosis..."
sudo apt update
sudo apt install -y kurtosis-cli
echo "Kurtosis update completed"

# 2. Pull latest version from repository
echo "Step 2: Pulling latest code..."
git pull origin main
echo "Code update completed"

# 3. Start Kurtosis engine
echo "Step 3: Starting Kurtosis engine..."
kurtosis engine start

# 4. Clean up old enclave (if exists)
echo "Step 4: Cleaning up old enclave..."
kurtosis enclave rm -f my-testnet 2>/dev/null || echo "No old enclave found, continuing"

# 5. Run Ethereum network and output to output.txt
echo "Step 5: Running Ethereum network..."

# Create output.txt file and write initial information
{
    echo "Start time: $(date)"
    echo "Command executed: kurtosis run --enclave my-testnet github.com/ethpandaops/ethereum-package --args-file $CONFIG_FILE"
    echo ""
} > output.txt

# Run kurtosis command and append output to output.txt
kurtosis run --enclave my-testnet github.com/ethpandaops/ethereum-package --args-file "$CONFIG_FILE" >> output.txt 2>&1

echo "" >> output.txt
echo "End time: $(date)" >> output.txt

echo "Ethereum network deployment completed, output saved to output.txt"

echo "=== Script execution completed ==="
echo "Output file:"
echo "  - output.txt: Complete execution log"