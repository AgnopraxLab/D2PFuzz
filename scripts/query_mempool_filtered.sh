#!/bin/bash

# Mempool transaction query script (with filtering functionality)
# Query pending transactions in Ethereum network mempool, supports filtering by address, amount and other conditions

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Import RPC configuration
source "$SCRIPT_DIR/rpc_config.sh"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default parameters
FILTER_ADDRESS=""
MIN_VALUE=""
MAX_VALUE=""
SHOW_DETAILS=false
OUTPUT_FORMAT="txt"
SAVE_TO_FILE=""

# Show help information
show_help() {
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "${BLUE}🔍 Ethereum Mempool Transaction Query Tool (with Filtering)${NC}"
    fi
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -a, --address ADDR     Filter transactions for specified address (sender or receiver)"
    echo "  --min-value VALUE      Minimum transaction amount (Wei)"
    echo "  --max-value VALUE      Maximum transaction amount (Wei)"
    echo "  -d, --details          Show detailed transaction information"
    echo "  -f, --format FORMAT    Output format (txt|json|csv)"
    echo "  -o, --output FILE      Save results to file"
    echo "  -h, --help             Show this help information"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Query all mempool transactions"
    echo "  $0 -a 0x123...abc                   # Query transactions related to specified address"
    echo "  $0 --min-value 1000000000000000000  # Query transactions with amount greater than 1 ETH"
    echo "  $0 -d -f json -o mempool.json       # Save detailed information in JSON format"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--address)
                FILTER_ADDRESS="$2"
                shift 2
                ;;
            --min-value)
                MIN_VALUE="$2"
                shift 2
                ;;
            --max-value)
                MAX_VALUE="$2"
                shift 2
                ;;
            -d|--details)
                SHOW_DETAILS=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                SAVE_TO_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
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

# Convert hexadecimal to decimal
hex_to_dec() {
    local hex_value=$1
    if [[ "$hex_value" == "0x"* ]]; then
        echo $((hex_value))
    else
        echo "$hex_value"
    fi
}

# Check if transaction matches filter conditions
matches_filter() {
    local tx_json=$1
    local from=$(echo "$tx_json" | jq -r '.from // ""' | tr '[:upper:]' '[:lower:]')
    local to=$(echo "$tx_json" | jq -r '.to // ""' | tr '[:upper:]' '[:lower:]')
    local value=$(echo "$tx_json" | jq -r '.value // "0x0"')
    
    # Address filtering
    if [[ -n "$FILTER_ADDRESS" ]]; then
        local filter_addr=$(echo "$FILTER_ADDRESS" | tr '[:upper:]' '[:lower:]')
        if [[ "$from" != "$filter_addr" ]] && [[ "$to" != "$filter_addr" ]]; then
            return 1
        fi
    fi
    
    # Amount filtering
    if [[ -n "$MIN_VALUE" ]] || [[ -n "$MAX_VALUE" ]]; then
        local value_dec=$(hex_to_dec "$value")
        
        if [[ -n "$MIN_VALUE" ]] && [[ $value_dec -lt $MIN_VALUE ]]; then
            return 1
        fi
        
        if [[ -n "$MAX_VALUE" ]] && [[ $value_dec -gt $MAX_VALUE ]]; then
            return 1
        fi
    fi
    
    return 0
}

# Format transaction output
format_transaction() {
    local tx_json=$1
    local format=$2
    
    local hash=$(echo "$tx_json" | jq -r '.hash // "N/A"')
    local from=$(echo "$tx_json" | jq -r '.from // "N/A"')
    local to=$(echo "$tx_json" | jq -r '.to // "[Contract Creation]"')
    local value=$(echo "$tx_json" | jq -r '.value // "0x0"')
    local gas=$(echo "$tx_json" | jq -r '.gas // "N/A"')
    local gasPrice=$(echo "$tx_json" | jq -r '.gasPrice // .maxFeePerGas // "N/A"')
    local nonce=$(echo "$tx_json" | jq -r '.nonce // "N/A"')
    local txType=$(echo "$tx_json" | jq -r '.type // "0x0"')
    
    case $format in
        "json")
            echo "$tx_json"
            ;;
        "csv")
            echo "$hash,$from,$to,$value,$gas,$gasPrice,$nonce,$txType"
            ;;
        "txt"|*)
            # Output in tx_hashes.txt style format - just the hash
            echo "$hash"
            ;;
    esac
}

# Query and filter mempool transactions
query_and_filter_mempool() {
    local endpoint=$1
    local total_found=0
    local filtered_count=0
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "${CYAN}🔍 Querying node: $endpoint${NC}"
    fi
    
    # Query txpool_content
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "${RED}✗ RPC call failed${NC}"
        fi
        return 1
    fi
    
    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "${RED}✗ RPC error: $error_msg${NC}"
        fi
        return 1
    fi
    
    # Parse pending transactions
    local pending_count=$(echo "$response" | jq -r '.result.pending | keys | length' 2>/dev/null)
    local queued_count=$(echo "$response" | jq -r '.result.queued | keys | length' 2>/dev/null)
    
    if [[ "$pending_count" == "null" ]]; then
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "${YELLOW}⚠ Unable to parse response or method not supported${NC}"
        fi
        return 1
    fi
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "${BLUE}📈 Mempool Statistics:${NC}"
        echo -e "  📤 Pending transaction accounts: ${pending_count:-0}"
        echo -e "  📥 Queued transaction accounts: ${queued_count:-0}"
    fi
    
    # Output CSV header
    if [[ "$OUTPUT_FORMAT" == "csv" ]] && [[ -z "$csv_header_printed" ]]; then
        if [[ -n "$SAVE_TO_FILE" ]]; then
            echo "Hash,From,To,Value,Gas,GasPrice,Nonce,Type" >> "$SAVE_TO_FILE"
        else
            echo "Hash,From,To,Value,Gas,GasPrice,Nonce,Type"
        fi
        csv_header_printed=true
    fi
    
    # Process pending transactions
    if [[ "$pending_count" -gt 0 ]]; then
        # Add node type comment for txt format
        if [[ "$OUTPUT_FORMAT" == "txt" ]]; then
            local node_type=$(get_node_type_from_endpoint "$endpoint")
            if [[ -n "$node_type" ]]; then
                if [[ -n "$SAVE_TO_FILE" ]]; then
                    echo "# $node_type" >> "$SAVE_TO_FILE"
                else
                    echo "# $node_type"
                fi
            fi
        else
            echo -e "\n${YELLOW}🔄 Pending Transactions (with filters applied):${NC}"
        fi
        
        # Extract all pending transactions
        local pending_txs=$(echo "$response" | jq -c '.result.pending | to_entries[] | .value | to_entries[] | .value' 2>/dev/null)
        
        while IFS= read -r tx; do
            if [[ -n "$tx" ]]; then
                total_found=$((total_found + 1))
                
                if matches_filter "$tx"; then
                    filtered_count=$((filtered_count + 1))
                    
                    local formatted_output=$(format_transaction "$tx" "$OUTPUT_FORMAT")
                    
                    if [[ -n "$SAVE_TO_FILE" ]]; then
                        echo "$formatted_output" >> "$SAVE_TO_FILE"
                    else
                        echo "$formatted_output"
                    fi
                fi
            fi
        done <<< "$pending_txs"
    fi
    
    # Process queued transactions
    if [[ "$queued_count" -gt 0 ]]; then
        # For txt format, queued transactions are included under the same node comment
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "\n${PURPLE}⏳ Queued Transactions (with filters applied):${NC}"
        fi
        
        # Extract all queued transactions
        local queued_txs=$(echo "$response" | jq -c '.result.queued | to_entries[] | .value | to_entries[] | .value' 2>/dev/null)
        
        while IFS= read -r tx; do
            if [[ -n "$tx" ]]; then
                total_found=$((total_found + 1))
                
                if matches_filter "$tx"; then
                    filtered_count=$((filtered_count + 1))
                    
                    local formatted_output=$(format_transaction "$tx" "$OUTPUT_FORMAT")
                    
                    if [[ -n "$SAVE_TO_FILE" ]]; then
                        echo "$formatted_output" >> "$SAVE_TO_FILE"
                    else
                        echo "$formatted_output"
                    fi
                fi
            fi
        done <<< "$queued_txs"
    fi
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "\n${GREEN}📊 Node $endpoint Statistics:${NC}"
        echo -e "  🔍 Total transactions: $total_found"
        echo -e "  ✅ Matching filters: $filtered_count"
    fi
    
    return 0
}

# Main function
main() {
    echo -e "${BLUE}🔍 Ethereum Mempool Transaction Query Tool (with Filtering)${NC}"
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo "================================================================================"
    fi
    
    # Show filter conditions
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        if [[ -n "$FILTER_ADDRESS" ]] || [[ -n "$MIN_VALUE" ]] || [[ -n "$MAX_VALUE" ]]; then
            echo -e "\n${CYAN}🔧 Applied Filter Conditions:${NC}"
            [[ -n "$FILTER_ADDRESS" ]] && echo -e "  📍 Address filter: $FILTER_ADDRESS"
            [[ -n "$MIN_VALUE" ]] && echo -e "  💰 Minimum amount: $MIN_VALUE Wei"
            [[ -n "$MAX_VALUE" ]] && echo -e "  💰 Maximum amount: $MAX_VALUE Wei"
            echo -e "  📋 Output format: $OUTPUT_FORMAT"
            [[ -n "$SAVE_TO_FILE" ]] && echo -e "  💾 Save to file: $SAVE_TO_FILE"
        fi
        
        # Test RPC connections
        echo -e "\n${CYAN}🔗 Testing RPC connections...${NC}"
    fi
    
    available_endpoints=()
    
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
                echo -e "${GREEN}✅ $endpoint connection successful${NC}"
            fi
            available_endpoints+=("$endpoint")
        else
            if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
                echo -e "${RED}❌ $endpoint connection failed${NC}"
            fi
        fi
    done
    
    if [[ ${#available_endpoints[@]} -eq 0 ]]; then
        echo -e "${RED}❌ Error: No available RPC endpoints${NC}"
        exit 1
    fi
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "\n${GREEN}✅ Found ${#available_endpoints[@]} available RPC endpoints${NC}"
    fi
    
    # Clear output file
    if [[ -n "$SAVE_TO_FILE" ]]; then
        > "$SAVE_TO_FILE"
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "${CYAN}📝 Output will be saved to: $SAVE_TO_FILE${NC}"
        fi
    fi
    
    # Query mempool for each available endpoint
    local total_filtered=0
    for endpoint in "${available_endpoints[@]}"; do
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "\n${BLUE}=================================================================================${NC}"
            echo -e "${BLUE}🔍 Querying node: $endpoint${NC}"
            echo -e "${BLUE}=================================================================================${NC}"
        fi
        
        query_and_filter_mempool "$endpoint"
        
        if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
            echo -e "\n${CYAN}⏱️ Waiting 1 second before querying next node...${NC}"
        fi
        sleep 1
    done
    
    if [[ "$OUTPUT_FORMAT" != "txt" ]]; then
        echo -e "\n${GREEN}✅ Mempool query completed${NC}"
        echo -e "${CYAN}🕒 Query time: $(date)${NC}"
        
        if [[ -n "$SAVE_TO_FILE" ]]; then
            echo -e "${GREEN}💾 Results saved to: $SAVE_TO_FILE${NC}"
        fi
    fi
}

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ Error: curl command needs to be installed${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}❌ Error: jq command needs to be installed${NC}"
    exit 1
fi

# Parse arguments and run main function
parse_args "$@"
main