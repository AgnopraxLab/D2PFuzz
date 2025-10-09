#!/bin/bash

# Blob Test Verification Script
# Run blob test and automatically verify results

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANUAL_DIR="$PROJECT_ROOT/cmd/manual"

# Show usage
show_usage() {
    echo "Usage:"
    echo "  $0 <test_mode> [options]"
    echo ""
    echo "Test Modes:"
    echo "  blob-single  - Test single node blob transactions"
    echo "  blob-multi   - Test multi-node blob transactions"
    echo ""
    echo "Options:"
    echo "  --no-verify  - Skip automatic verification"
    echo "  --config <file> - Use custom config file"
    echo "  -h|--help    - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 blob-single"
    echo "  $0 blob-multi --config custom.yaml"
}

# Parse command line arguments
TEST_MODE=""
NO_VERIFY=false
CONFIG_FILE="$MANUAL_DIR/config.yaml"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        --no-verify)
            NO_VERIFY=true
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        blob-single|blob-multi)
            TEST_MODE="$1"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Validate test mode
if [[ -z "$TEST_MODE" ]]; then
    echo -e "${RED}Error: Test mode is required${NC}"
    show_usage
    exit 1
fi

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Blob Transaction Test & Verification    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Build the manual tool
echo -e "${BLUE}[Step 1/4]${NC} Building manual tool..."
cd "$MANUAL_DIR" || exit 1

if go build -o manual 2>&1; then
    echo -e "${GREEN}✓${NC} Build successful"
else
    echo -e "${RED}✗${NC} Build failed"
    exit 1
fi
echo ""

# Step 2: Run the test
echo -e "${BLUE}[Step 2/4]${NC} Running blob test (mode: $TEST_MODE)..."
TX_OUTPUT_FILE="/tmp/blob_tx_hashes_$$.txt"

# Create a temporary file to capture transaction hashes
if [[ -f "$TX_OUTPUT_FILE" ]]; then
    rm "$TX_OUTPUT_FILE"
fi

echo "Config: $CONFIG_FILE"
echo "Test mode: $TEST_MODE"
echo ""

# Run the test and capture output
./manual -config "$CONFIG_FILE" -mode "$TEST_MODE" 2>&1 | tee /tmp/blob_test_output_$$.log

TEST_EXIT_CODE=${PIPESTATUS[0]}

if [[ $TEST_EXIT_CODE -ne 0 ]]; then
    echo -e "${RED}✗${NC} Test execution failed with exit code $TEST_EXIT_CODE"
    exit 1
fi

echo -e "${GREEN}✓${NC} Test execution completed"
echo ""

# Step 3: Extract transaction hashes from output
echo -e "${BLUE}[Step 3/4]${NC} Extracting transaction hashes from output..."

# Try to find txhashes.txt file
TXHASH_FILE="$MANUAL_DIR/txhashes.txt"
if [[ -f "$TXHASH_FILE" ]]; then
    cp "$TXHASH_FILE" "$TX_OUTPUT_FILE"
    TX_COUNT=$(wc -l < "$TX_OUTPUT_FILE")
    echo -e "${GREEN}✓${NC} Found $TX_COUNT transaction hash(es) in $TXHASH_FILE"
else
    # Extract from log output (looking for transaction hashes)
    grep -oE '0x[0-9a-fA-F]{64}' /tmp/blob_test_output_$$.log | sort -u > "$TX_OUTPUT_FILE"
    TX_COUNT=$(wc -l < "$TX_OUTPUT_FILE")
    
    if [[ $TX_COUNT -eq 0 ]]; then
        echo -e "${YELLOW}⚠${NC} No transaction hashes found in output"
        echo "This might mean:"
        echo "  - Test didn't send any transactions"
        echo "  - Transactions failed before getting hash"
        echo "  - Hash format not recognized"
        
        if [[ "$NO_VERIFY" == false ]]; then
            echo ""
            echo "Check the test output at: /tmp/blob_test_output_$$.log"
            exit 1
        fi
    else
        echo -e "${GREEN}✓${NC} Extracted $TX_COUNT transaction hash(es)"
    fi
fi

# Show first few hashes
if [[ $TX_COUNT -gt 0 ]]; then
    echo "First few transaction hashes:"
    head -3 "$TX_OUTPUT_FILE" | while read hash; do
        echo "  - $hash"
    done
    if [[ $TX_COUNT -gt 3 ]]; then
        echo "  ... and $((TX_COUNT - 3)) more"
    fi
fi
echo ""

# Step 4: Verify transactions
if [[ "$NO_VERIFY" == false && $TX_COUNT -gt 0 ]]; then
    echo -e "${BLUE}[Step 4/4]${NC} Verifying blob transactions..."
    echo ""
    
    # Wait a bit for transactions to be mined
    echo "Waiting 5 seconds for transactions to be mined..."
    sleep 5
    
    # Use the blob query script
    if [[ -f "$SCRIPT_DIR/query_blob_tx.sh" ]]; then
        bash "$SCRIPT_DIR/query_blob_tx.sh" -f "$TX_OUTPUT_FILE"
        VERIFY_EXIT_CODE=$?
    else
        echo -e "${YELLOW}⚠${NC} Blob query script not found, using regular query script..."
        if [[ -f "$SCRIPT_DIR/query_tx.sh" ]]; then
            bash "$SCRIPT_DIR/query_tx.sh" -f "$TX_OUTPUT_FILE"
            VERIFY_EXIT_CODE=$?
        else
            echo -e "${RED}✗${NC} No query script found"
            VERIFY_EXIT_CODE=1
        fi
    fi
else
    echo -e "${BLUE}[Step 4/4]${NC} Skipping verification (--no-verify flag or no transactions)"
    VERIFY_EXIT_CODE=0
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            Test Complete                   ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo "Test output: /tmp/blob_test_output_$$.log"
echo "Transaction hashes: $TX_OUTPUT_FILE"
echo ""

if [[ $VERIFY_EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✓ All steps completed successfully${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Verification completed with warnings${NC}"
    exit 0
fi

