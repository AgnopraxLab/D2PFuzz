#!/bin/bash

# Script to verify that queued transactions are NOT broadcasted to other nodes
# This demonstrates the difference between pending and queued transaction pools

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Load RPC configuration from external file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Show usage information
show_usage() {
    echo "Usage:"
    echo "  $0 <transaction_hash>"
    echo "  $0 -h|--help"
    echo ""
    echo "Description:"
    echo "  Check if a transaction exists on multiple Ethereum nodes to verify"
    echo "  whether it has been broadcasted via P2P network."
    echo ""
    echo "Examples:"
    echo "  $0 0xe4561def9cb9d859660c55d8ad2ce21fbc23308be8cb19da67968e8bc039a217"
    echo ""
    echo "Note:"
    echo "  • QUEUED transactions stay local and are NOT broadcasted"
    echo "  • PENDING transactions are broadcasted to all connected nodes"
}

# Check parameters
if [[ $# -eq 0 ]]; then
    echo -e "${RED}Error: No transaction hash provided${NC}"
    echo ""
    show_usage
    exit 1
fi

# Handle help parameter
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_usage
    exit 0
fi

# Get transaction hash from command line argument
TX_HASH="$1"

# Validate transaction hash format
if [[ ! "$TX_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo -e "${RED}Error: Invalid transaction hash format${NC}"
    echo "Expected: 0x followed by 64 hexadecimal characters"
    echo "Got: $TX_HASH"
    exit 1
fi

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Transaction Broadcast Verification Tool${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Testing transaction: $TX_HASH"
echo ""

# Build node list from NODE_RPC_MAP (loaded from rpc_config.sh)
declare -A NODES
for node_type in "${!NODE_RPC_MAP[@]}"; do
    NODES["$node_type"]="${NODE_RPC_MAP[$node_type]}"
done

# If NODE_RPC_MAP is empty, use RPC_ENDPOINTS array from rpc_config.sh
if [[ ${#NODES[@]} -eq 0 ]]; then
    # Fallback: use endpoints from RPC_ENDPOINTS array
    if [[ ${#RPC_ENDPOINTS[@]} -gt 0 ]]; then
        index=0
        for endpoint in "${RPC_ENDPOINTS[@]}"; do
            NODES["node-$index"]="$endpoint"
            ((index++))
        done
        echo -e "${YELLOW}Warning: NODE_RPC_MAP is empty, using RPC_ENDPOINTS from rpc_config.sh${NC}"
        echo ""
    else
        echo -e "${RED}Error: No RPC endpoints available in rpc_config.sh${NC}"
        exit 1
    fi
fi

check_tx_on_node() {
    local node_name=$1
    local endpoint=$2
    
    echo -e "${BLUE}[$node_name]${NC} Checking $endpoint..."
    
    # Check if transaction exists via eth_getTransactionByHash
    local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
        --connect-timeout 3 --max-time 5 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "  ${RED}✗ Connection failed${NC}"
        return 1
    fi
    
    if echo "$tx_response" | grep -q '"result":null'; then
        echo -e "  ${RED}✗ Transaction NOT found${NC} (not in this node's txpool or blockchain)"
        return 1
    elif echo "$tx_response" | grep -q '"result":{'; then
        local block_number=$(echo "$tx_response" | grep -o '"blockNumber":[^,}]*' | cut -d':' -f2 | tr -d '"')
        
        if [[ "$block_number" == "null" || -z "$block_number" ]]; then
            echo -e "  ${GREEN}✓ Transaction found in mempool${NC}"
            
            # Try to determine if it's in pending or queued pool
            local txpool_response=$(curl -s -X POST -H "Content-Type: application/json" \
                --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
                --connect-timeout 3 --max-time 5 "$endpoint" 2>/dev/null)
            
            if echo "$txpool_response" | jq -r '.result.pending' 2>/dev/null | grep -q "$TX_HASH"; then
                echo -e "  ${YELLOW}  → Status: PENDING${NC} (ready for mining, broadcasted)"
            elif echo "$txpool_response" | jq -r '.result.queued' 2>/dev/null | grep -q "$TX_HASH"; then
                echo -e "  ${CYAN}  → Status: QUEUED${NC} (waiting for conditions, NOT broadcasted)"
            else
                echo -e "  ${YELLOW}  → Status: In mempool${NC} (unable to determine pending/queued)"
            fi
        else
            local block_num_dec=$((16#${block_number#0x}))
            echo -e "  ${GREEN}✓ Transaction mined in block $block_num_dec${NC}"
        fi
        return 0
    else
        echo -e "  ${RED}✗ Unexpected response${NC}"
        return 1
    fi
}

echo -e "${YELLOW}Checking transaction on all nodes...${NC}"
echo ""

found_count=0
total_count=0

for node_name in "${!NODES[@]}"; do
    endpoint="${NODES[$node_name]}"
    ((total_count++))
    
    if check_tx_on_node "$node_name" "$endpoint"; then
        ((found_count++))
    fi
    echo ""
done

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Summary${NC}"
echo -e "${CYAN}========================================${NC}"
echo "Transaction found on: $found_count/$total_count nodes"
echo ""

if [[ $found_count -eq 1 ]]; then
    echo -e "${YELLOW}Result: Transaction exists on only ONE node${NC}"
    echo -e "${YELLOW}This confirms: QUEUED transactions are NOT broadcasted!${NC}"
    echo ""
    echo "Explanation:"
    echo "  • Queued transactions stay in the local txpool of the receiving node"
    echo "  • Only PENDING transactions are broadcasted via P2P network"
    echo "  • A transaction moves from queued → pending when conditions are met"
    echo "    (e.g., nonce gap is filled, gas price is sufficient)"
elif [[ $found_count -gt 1 ]]; then
    echo -e "${GREEN}Result: Transaction found on multiple nodes${NC}"
    echo -e "${GREEN}This means: Transaction is either PENDING or already mined${NC}"
else
    echo -e "${RED}Result: Transaction not found on any accessible node${NC}"
    echo "Possible reasons:"
    echo "  • Transaction has been dropped from all txpools"
    echo "  • Network connectivity issues"
    echo "  • Transaction never existed"
fi

