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

# Default configuration
OUTPUT_FORMAT="normal"  # normal, txt
OUTPUT_FILE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --format FORMAT    Output format: normal|txt (default: normal)"
            echo "  --output FILE      Output to file instead of stdout"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Normal output to console"
            echo "  $0 --format txt              # Simple txt format to console"
            echo "  $0 --format txt --output hashes.txt  # Save txt format to file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Load RPC configuration from external file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

# Array to store unique transaction hashes for deduplication
declare -A seen_hashes

# Function to check if hash has been seen before
is_hash_seen() {
    local hash=$1
    if [[ -n "${seen_hashes[$hash]}" ]]; then
        return 0  # Hash already seen
    else
        seen_hashes[$hash]=1
        return 1  # Hash is new
    fi
}

# Output function that handles both console and file output
output_line() {
    local line="$1"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "$line" >> "$OUTPUT_FILE"
    else
        echo -e "$line"
    fi
}

# Output function for txt format (no colors, no echo -e)
output_txt() {
    local line="$1"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "$line" >> "$OUTPUT_FILE"
    else
        echo "$line"
    fi
}

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
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${CYAN}📡 Querying node: $endpoint${NC}"
    fi
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_pendingTransactions","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC call failed${NC}"
        fi
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC error: $error_msg${NC}"
        fi
        return 1
    fi
    
    # Parse results
    local tx_count=$(echo "$response" | jq -r '.result | length' 2>/dev/null)
    
    if [[ "$tx_count" == "null" ]] || [[ -z "$tx_count" ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${YELLOW}⚠ Unable to parse response or method not supported${NC}"
        fi
        return 1
    fi
    
    if [[ "$tx_count" -eq 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${GREEN}✓ Mempool is empty, no pending transactions${NC}"
        fi
        return 0
    fi
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${YELLOW}📊 Found $tx_count pending transactions:${NC}"
    fi
    
    # Process transactions with deduplication
    local unique_count=0
    local node_comment="# Node: $endpoint"
    local has_output=false
    
    while IFS= read -r tx_line; do
        local hash=$(echo "$tx_line" | grep -o '0x[a-fA-F0-9]\{64\}')
        if [[ -n "$hash" ]] && ! is_hash_seen "$hash"; then
            if [[ "$OUTPUT_FORMAT" == "txt" ]]; then
                if [[ "$has_output" == "false" ]]; then
                    output_txt "$node_comment"
                    has_output=true
                fi
                output_txt "$hash"
            else
                output_line "$tx_line"
            fi
            ((unique_count++))
        fi
    done < <(echo "$response" | jq -r '.result[] | "  🔗 " + .hash + " | From: " + .from + " | To: " + (.to // "[Contract Creation]") + " | Value: " + .value + " Wei | Gas: " + .gas + " | Nonce: " + .nonce' 2>/dev/null)
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]] && [[ $unique_count -lt $tx_count ]]; then
        output_line "${CYAN}ℹ️  Filtered out $((tx_count - unique_count)) duplicate transactions${NC}"
    fi
    
    return 0
}

# Query mempool detailed content
query_txpool_content() {
    local endpoint=$1
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${CYAN}🔍 Querying mempool detailed content: $endpoint${NC}"
    fi
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC call failed${NC}"
        fi
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC error: $error_msg${NC}"
        fi
        return 1
    fi
    
    # Parse pending transactions
    local pending_count=$(echo "$response" | jq -r '.result.pending | keys | length' 2>/dev/null)
    local queued_count=$(echo "$response" | jq -r '.result.queued | keys | length' 2>/dev/null)
    
    if [[ "$pending_count" == "null" ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${YELLOW}⚠ Unable to parse response or method not supported${NC}"
        fi
        return 1
    fi
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${BLUE}📈 Mempool statistics:${NC}"
        output_line "  📤 Pending transaction accounts: ${pending_count:-0}"
        output_line "  📥 Queued transaction accounts: ${queued_count:-0}"
    fi
    
    # Display pending transaction details
    if [[ "$pending_count" -gt 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "\n${YELLOW}🔄 Pending transaction details:${NC}"
        fi
        
        # Process transactions with deduplication
        local unique_count=0
        local total_processed=0
        local node_comment="# Node: $endpoint"
        local has_output=false
        
        while IFS= read -r tx_line; do
            ((total_processed++))
            local hash=$(echo "$tx_line" | grep -o '0x[a-fA-F0-9]\{64\}')
            if [[ -n "$hash" ]] && ! is_hash_seen "$hash"; then
                if [[ "$OUTPUT_FORMAT" == "txt" ]]; then
                    if [[ "$has_output" == "false" ]]; then
                        output_txt "$node_comment"
                        has_output=true
                    fi
                    output_txt "$hash"
                else
                    output_line "$tx_line"
                fi
                ((unique_count++))
            fi
            # Limit output lines
            if [[ $total_processed -ge 50 ]]; then
                break
            fi
        done < <(echo "$response" | jq -r '
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
        ' 2>/dev/null)
        
        if [[ "$OUTPUT_FORMAT" != "txt" ]] && [[ $unique_count -lt $total_processed ]]; then
            output_line "${CYAN}ℹ️  Filtered out $((total_processed - unique_count)) duplicate transactions from detailed view${NC}"
        fi
    fi
    
    # Display queued transaction summary (only for normal format)
    if [[ "$queued_count" -gt 0 ]] && [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "\n${PURPLE}⏳ Queued transaction summary:${NC}"
        echo "$response" | jq -r '
            .result.queued | 
            to_entries[] | 
            .key as $addr | 
            .value | 
            keys | 
            "  📍 Account: " + $addr + " | Queued transactions: " + (length | tostring)
        ' 2>/dev/null | while IFS= read -r line; do
            output_line "$line"
        done
    fi
    
    # Handle queued transactions for txt format
    if [[ "$queued_count" -gt 0 ]] && [[ "$OUTPUT_FORMAT" == "txt" ]]; then
        local node_comment="# Node: $endpoint"
        local has_output=false
        
        # Extract queued transaction hashes
        while IFS= read -r hash; do
            if [[ -n "$hash" ]] && ! is_hash_seen "$hash"; then
                if [[ "$has_output" == "false" ]]; then
                    output_txt "$node_comment"
                    has_output=true
                fi
                output_txt "$hash"
            fi
        done < <(echo "$response" | jq -r '
            .result.queued | 
            to_entries[] | 
            .value | 
            to_entries[] | 
            .value.hash
        ' 2>/dev/null)
    fi
    
    return 0
}

# Query mempool status
query_txpool_status() {
    local endpoint=$1
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${CYAN}📊 Querying mempool status: $endpoint${NC}"
    fi
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC call failed${NC}"
        fi
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            output_line "${RED}✗ RPC error: $error_msg${NC}"
        fi
        return 1
    fi
    
    # Parse status
    local pending=$(echo "$response" | jq -r '.result.pending // "N/A"' 2>/dev/null)
    local queued=$(echo "$response" | jq -r '.result.queued // "N/A"' 2>/dev/null)
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        output_line "${GREEN}✓ Mempool status:${NC}"
        output_line "  🔄 Pending: $pending"
        output_line "  ⏳ Queued: $queued"
    fi
    
    return 0
}

# Main function
main() {
    echo -e "${BLUE}🔍 Ethereum Mempool Transaction Query Tool${NC}"
    echo "================================================================================"
    
    # Initialize deduplication array for each run
    declare -gA seen_hashes
    
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