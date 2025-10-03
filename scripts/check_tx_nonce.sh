#!/bin/bash

# Script to check transaction nonces and compare with account state
# This helps understand why transactions are in pending vs queued

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Load RPC configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Show usage
show_usage() {
    echo "Usage:"
    echo "  $0 <tx_hash1> [tx_hash2] [tx_hash3] ..."
    echo "  $0 -f <filename>"
    echo ""
    echo "Description:"
    echo "  Analyze transaction nonces and compare with account state to understand"
    echo "  why transactions are in pending vs queued status."
}

# Check parameters
if [[ $# -eq 0 ]]; then
    echo -e "${RED}Error: No transaction hash provided${NC}"
    show_usage
    exit 1
fi

# Get endpoint
ENDPOINT="${RPC_ENDPOINTS[0]}"
if [[ -z "$ENDPOINT" ]]; then
    echo -e "${RED}Error: No RPC endpoint available${NC}"
    exit 1
fi

echo -e "${CYAN}Transaction Nonce Analysis Tool${NC}"
echo "Using endpoint: $ENDPOINT"
echo ""

# Parse transaction hashes
tx_hashes=()
if [[ "$1" == "-f" ]]; then
    # Read from file
    if [[ ! -f "$2" ]]; then
        echo -e "${RED}Error: File $2 does not exist${NC}"
        exit 1
    fi
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            tx_hashes+=("$line")
        fi
    done < "$2"
else
    tx_hashes=("$@")
fi

echo "Analyzing ${#tx_hashes[@]} transactions..."
echo ""

# Get transaction details and group by sender
declare -A account_txs
declare -A account_nonces
declare -A account_current_nonces

for tx_hash in "${tx_hashes[@]}"; do
    # Query transaction
    tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 5 --max-time 10 "$ENDPOINT" 2>/dev/null)
    
    if echo "$tx_response" | grep -q '"result":{'; then
        # Extract sender and nonce
        from=$(echo "$tx_response" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
        nonce=$(echo "$tx_response" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$from" && -n "$nonce" ]]; then
            # Convert nonce to decimal
            nonce_dec=$((16#${nonce#0x}))
            
            # Store transaction info
            account_txs["$from"]+="$tx_hash:$nonce_dec "
            
            # Get current nonce for this account (only once per account)
            if [[ -z "${account_current_nonces[$from]}" ]]; then
                current_nonce_response=$(curl -s -X POST -H "Content-Type: application/json" \
                    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"$from\",\"latest\"],\"id\":1}" \
                    --connect-timeout 5 --max-time 10 "$ENDPOINT" 2>/dev/null)
                
                current_nonce=$(echo "$current_nonce_response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
                if [[ -n "$current_nonce" ]]; then
                    current_nonce_dec=$((16#${current_nonce#0x}))
                    account_current_nonces["$from"]=$current_nonce_dec
                fi
            fi
        fi
    fi
done

echo -e "${CYAN}=== Analysis Results ===${NC}"
echo ""

# Analyze each account
for account in "${!account_txs[@]}"; do
    echo -e "${BLUE}Account: $account${NC}"
    current_nonce=${account_current_nonces[$account]}
    echo -e "  Current nonce (latest): ${GREEN}$current_nonce${NC}"
    echo ""
    
    # Parse and sort nonces
    tx_info="${account_txs[$account]}"
    nonces=()
    
    # Extract nonces and sort them
    for item in $tx_info; do
        nonce_val=$(echo "$item" | cut -d':' -f2)
        nonces+=($nonce_val)
    done
    
    # Sort nonces
    IFS=$'\n' sorted_nonces=($(sort -n <<<"${nonces[*]}"))
    unset IFS
    
    echo "  Transactions (sorted by nonce):"
    
    # Display each transaction with analysis
    prev_nonce=-1
    has_gap=false
    below_current=false
    
    for item in $tx_info; do
        tx_hash=$(echo "$item" | cut -d':' -f1)
        nonce=$(echo "$item" | cut -d':' -f2)
        
        status=""
        issue=""
        
        # Check for issues
        if [[ $nonce -lt $current_nonce ]]; then
            status="${RED}[BELOW CURRENT]${NC}"
            issue="This nonce is already used (nonce < current nonce)"
            below_current=true
        elif [[ $nonce -eq $current_nonce ]]; then
            status="${GREEN}[NEXT VALID]${NC}"
            issue="This is the next valid nonce"
        else
            # Check for gap
            gap=$((nonce - current_nonce))
            if [[ $gap -gt 1 ]]; then
                status="${YELLOW}[NONCE GAP: +$gap]${NC}"
                issue="Gap of $gap from current nonce (should be queued)"
                has_gap=true
            else
                status="${GREEN}[SEQUENTIAL]${NC}"
                issue="Sequential nonce"
            fi
        fi
        
        # Check mempool status
        mempool_status=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
            --connect-timeout 3 --max-time 5 "$ENDPOINT" 2>/dev/null)
        
        actual_status="unknown"
        if echo "$mempool_status" | jq -r '.result.pending' 2>/dev/null | grep -q "$tx_hash"; then
            actual_status="${YELLOW}PENDING${NC}"
        elif echo "$mempool_status" | jq -r '.result.queued' 2>/dev/null | grep -q "$tx_hash"; then
            actual_status="${CYAN}QUEUED${NC}"
        fi
        
        echo -e "    Nonce $nonce: $tx_hash"
        echo -e "      Status: $status | Actual: $actual_status"
        echo -e "      ${issue}"
        echo ""
    done
    
    # Summary
    if [[ $below_current == true ]]; then
        echo -e "  ${RED}⚠ Warning: Some transactions use nonces below current${NC}"
        echo "    These should typically be rejected or replaced"
    fi
    
    if [[ $has_gap == true ]]; then
        echo -e "  ${YELLOW}⚠ Warning: Nonce gaps detected${NC}"
        echo "    Expected: These should be in QUEUED pool"
        echo "    If in PENDING: Client may have different txpool policies"
    fi
    
    echo ""
    echo "---"
    echo ""
done

echo -e "${CYAN}=== Client Behavior Notes ===${NC}"
echo ""
echo "Different Ethereum clients have different transaction pool policies:"
echo ""
echo "• Geth (Go-Ethereum):"
echo "  - Strict nonce ordering"
echo "  - Nonce gaps → QUEUED pool"
echo "  - QUEUED transactions are NOT broadcasted"
echo ""
echo "• Besu:"
echo "  - More permissive transaction pool"
echo "  - May accept future nonces into PENDING"
echo "  - Different validation rules"
echo ""
echo "• Nethermind, Reth, Erigon:"
echo "  - Each has its own txpool implementation"
echo "  - Behavior may vary"
echo ""
echo "This is why the SAME transaction can have different status on different clients!"

