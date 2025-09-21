#!/bin/bash

# Mempool transaction query script
# Query pending transactions in Ethereum network mempool

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load RPC configuration from external file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Test RPC connection
test_rpc_connection() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

# Query pending transactions (simple method)
query_pending_transactions() {
    local endpoint=$1
    echo -e "${CYAN}📡 Querying node: $endpoint${NC}"
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_pendingTransactions","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗ RPC call failed${NC}"
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        echo -e "${RED}✗ RPC error: $error_msg${NC}"
        return 1
    fi
    
    # Parse results
    local tx_count=$(echo "$response" | jq -r '.result | length' 2>/dev/null)
    
    if [[ "$tx_count" == "null" ]] || [[ -z "$tx_count" ]]; then
        echo -e "${YELLOW}⚠ Unable to parse response or method not supported${NC}"
        return 1
    fi
    
    if [[ "$tx_count" -eq 0 ]]; then
        echo -e "${GREEN}✓ Mempool is empty, no pending transactions${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}📊 Found $tx_count pending transactions:${NC}"
    echo "$response" | jq -r '.result[] | "  🔗 " + .hash + " | From: " + .from + " | To: " + (.to // "[Contract Creation]") + " | Value: " + .value + " Wei | Gas: " + .gas + " | Nonce: " + .nonce' 2>/dev/null
    
    return 0
}

# Query mempool detailed content
query_txpool_content() {
    local endpoint=$1
    echo -e "${CYAN}🔍 Querying mempool detailed content: $endpoint${NC}"
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗ RPC call failed${NC}"
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        echo -e "${RED}✗ RPC error: $error_msg${NC}"
        return 1
    fi
    
    # Parse pending transactions
    local pending_count=$(echo "$response" | jq -r '.result.pending | keys | length' 2>/dev/null)
    local queued_count=$(echo "$response" | jq -r '.result.queued | keys | length' 2>/dev/null)
    
    if [[ "$pending_count" == "null" ]]; then
        echo -e "${YELLOW}⚠ Unable to parse response or method not supported${NC}"
        return 1
    fi
    
    echo -e "${BLUE}📈 Mempool statistics:${NC}"
    echo -e "  📤 Pending transaction accounts: ${pending_count:-0}"
    echo -e "  📥 Queued transaction accounts: ${queued_count:-0}"
    
    # Display pending transaction details
    if [[ "$pending_count" -gt 0 ]]; then
        echo -e "\n${YELLOW}🔄 Pending transaction details:${NC}"
        echo "$response" | jq -r '
            .result.pending | 
            to_entries[] | 
            .key as $addr | 
            .value | 
            to_entries[] | 
            "  📍 Account: " + $addr + " | Nonce: " + .key + 
            "\n    🔗 Hash: " + .value.hash + 
            "\n    📤 From: " + .value.from + 
            "\n    📥 To: " + (.value.to // "[Contract Creation]") + 
            "\n    💰 Value: " + .value.value + " Wei" + 
            "\n    ⛽ Gas Limit: " + .value.gas + 
            "\n    💸 Gas Price: " + (.value.gasPrice // .value.maxFeePerGas // "N/A") + 
            "\n    🔢 Transaction Type: " + (.value.type // "0x0") + 
            "\n    ----------------------------------------"
        ' 2>/dev/null | head -50  # Limit output lines
    fi
    
    # Display queued transaction summary
    if [[ "$queued_count" -gt 0 ]]; then
        echo -e "\n${PURPLE}⏳ Queued transaction summary:${NC}"
        echo "$response" | jq -r '
            .result.queued | 
            to_entries[] | 
            .key as $addr | 
            .value | 
            keys | 
            "  📍 Account: " + $addr + " | Queued transactions: " + (length | tostring)
        ' 2>/dev/null
    fi
    
    return 0
}

# Query mempool status
query_txpool_status() {
    local endpoint=$1
    echo -e "${CYAN}📊 Querying mempool status: $endpoint${NC}"
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗ RPC call failed${NC}"
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        echo -e "${RED}✗ RPC error: $error_msg${NC}"
        return 1
    fi
    
    # Parse status
    local pending=$(echo "$response" | jq -r '.result.pending // "N/A"' 2>/dev/null)
    local queued=$(echo "$response" | jq -r '.result.queued // "N/A"' 2>/dev/null)
    
    echo -e "${GREEN}✓ Mempool status:${NC}"
    echo -e "  🔄 Pending: $pending"
    echo -e "  ⏳ Queued: $queued"
    
    return 0
}

# Main function
main() {
    echo -e "${BLUE}🔍 Ethereum Mempool Transaction Query Tool${NC}"
    echo "================================================================================"
    
    # Test RPC connections
    echo -e "\n${CYAN}🔗 Testing RPC connections...${NC}"
    available_endpoints=()
    
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            echo -e "${GREEN}✅ $endpoint connection successful${NC}"
            available_endpoints+=("$endpoint")
        else
            echo -e "${RED}❌ $endpoint connection failed${NC}"
        fi
    done
    
    if [[ ${#available_endpoints[@]} -eq 0 ]]; then
        echo -e "${RED}❌ Error: No available RPC endpoints${NC}"
        exit 1
    fi
    
    echo -e "\n${GREEN}✅ Found ${#available_endpoints[@]} available RPC endpoints${NC}"
    
    # Query mempool for each available endpoint
    for endpoint in "${available_endpoints[@]}"; do
        echo -e "\n${BLUE}=================================================================================${NC}"
        echo -e "${BLUE}🔍 Querying node: $endpoint${NC}"
        echo -e "${BLUE}=================================================================================${NC}"
        
        # Query mempool status
        query_txpool_status "$endpoint"
        echo ""
        
        # Query pending transactions
        query_pending_transactions "$endpoint"
        echo ""
        
        # Query detailed content
        query_txpool_content "$endpoint"
        
        echo -e "\n${CYAN}⏱️ Waiting 1 second before querying next node...${NC}"
        sleep 1
    done
    
    echo -e "\n${GREEN}✅ Mempool query completed${NC}"
    echo -e "${CYAN}🕒 Query time: $(date)${NC}"
}

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ Error: curl command is required${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}❌ Error: jq command is required${NC}"
    exit 1
fi

# Run main function
main "$@"