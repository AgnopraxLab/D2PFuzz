#!/bin/bash

# Ethereum transaction details query script (Bash version)
# Query detailed transaction information by transaction hash

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source RPC configuration
if [[ -f "${SCRIPT_DIR}/rpc_config.sh" ]]; then
    source "${SCRIPT_DIR}/rpc_config.sh"
else
    echo "Error: rpc_config.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

# RPC_ENDPOINTS is now loaded from rpc_config.sh

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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

# Find available RPC endpoint
find_available_rpc() {
    echo -e "${CYAN}🔍 Testing RPC connections...${NC}" >&2
    
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            echo -e "${GREEN}✅ Using RPC endpoint: $endpoint${NC}" >&2
            echo "$endpoint"
            return 0
        else
            echo -e "${RED}❌ $endpoint connection failed${NC}" >&2
        fi
    done
    
    return 1
}

# Hexadecimal to decimal conversion
hex_to_dec() {
    local hex_value=$1
    if [[ -z "$hex_value" || "$hex_value" == "null" ]]; then
        echo "0"
    else
        echo $((16#${hex_value#0x}))
    fi
}

# Wei to Ether conversion
wei_to_ether() {
    local wei_hex=$1
    if [[ -z "$wei_hex" || "$wei_hex" == "0x0" || "$wei_hex" == "null" ]]; then
        echo "0.000000"
    else
        local wei_dec=$(hex_to_dec "$wei_hex")
        # Use bc for precise calculation
        if command -v bc >/dev/null 2>&1; then
            echo "scale=6; $wei_dec / 1000000000000000000" | bc
        else
            # If bc is not available, use awk
            awk "BEGIN {printf \"%.6f\", $wei_dec / 1000000000000000000}"
        fi
    fi
}

# Format gas price
format_gas_price() {
    local gas_price_hex=$1
    if [[ -z "$gas_price_hex" || "$gas_price_hex" == "null" ]]; then
        echo "0 Gwei (0 Wei)"
    else
        local gas_price_wei=$(hex_to_dec "$gas_price_hex")
        if command -v bc >/dev/null 2>&1; then
            local gas_price_gwei=$(echo "scale=2; $gas_price_wei / 1000000000" | bc)
            echo "$gas_price_gwei Gwei ($gas_price_wei Wei)"
        else
            local gas_price_gwei=$(awk "BEGIN {printf \"%.2f\", $gas_price_wei / 1000000000}")
            echo "$gas_price_gwei Gwei ($gas_price_wei Wei)"
        fi
    fi
}

# Format timestamp
format_timestamp() {
    local timestamp_hex=$1
    if [[ -z "$timestamp_hex" || "$timestamp_hex" == "null" ]]; then
        echo "Unknown"
    else
        local timestamp=$(hex_to_dec "$timestamp_hex")
        local formatted_date=$(date -d "@$timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "Format failed")
        echo "$formatted_date ($timestamp)"
    fi
}

# Add thousand separators
format_number() {
    local number=$1
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --grouping "$number" 2>/dev/null || echo "$number"
    else
        # Simple thousand separator implementation
        echo "$number" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
    fi
}

# Query transaction details
query_transaction_details() {
    local tx_hash=$1
    local endpoint=$2
    
    echo -e "\n$(printf '=%.0s' {1..80})"
    echo -e "${BLUE}Transaction Details Query: $tx_hash${NC}"
    echo -e "$(printf '=%.0s' {1..80})"
    
    # Get transaction information
    echo -e "\n${CYAN}🔍 Querying transaction information...${NC}"
    local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]] || ! echo "$tx_response" | grep -q '"result"'; then
        echo -e "${RED}❌ Transaction query failed or transaction does not exist${NC}"
        return 1
    fi
    
    # Check if transaction exists
    if echo "$tx_response" | grep -q '"result":null'; then
        echo -e "${RED}❌ Transaction does not exist${NC}"
        return 1
    fi
    
    # Parse transaction information
    local block_hash=$(echo "$tx_response" | grep -o '"blockHash":"[^"]*"' | cut -d'"' -f4)
    local block_number=$(echo "$tx_response" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
    local tx_index=$(echo "$tx_response" | grep -o '"transactionIndex":"[^"]*"' | cut -d'"' -f4)
    local from_addr=$(echo "$tx_response" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
    local to_addr=$(echo "$tx_response" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
    local value=$(echo "$tx_response" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
    local nonce=$(echo "$tx_response" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)
    local gas_limit=$(echo "$tx_response" | grep -o '"gas":"[^"]*"' | cut -d'"' -f4)
    local gas_price=$(echo "$tx_response" | grep -o '"gasPrice":"[^"]*"' | cut -d'"' -f4)
    local input_data=$(echo "$tx_response" | grep -o '"input":"[^"]*"' | cut -d'"' -f4)
    
    # Basic transaction information
    echo -e "\n${GREEN}📋 Basic Transaction Information:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "Transaction Hash: $tx_hash"
    echo "Block Hash: ${block_hash:-N/A}"
    if [[ -n "$block_number" && "$block_number" != "null" ]]; then
        echo "Block Number: $(format_number $(hex_to_dec "$block_number"))"
    else
        echo "Block Number: Pending confirmation"
    fi
    echo "Transaction Index: ${tx_index:+$(hex_to_dec "$tx_index")}"
    echo "From: ${from_addr:-N/A}"
    echo "To: ${to_addr:-Contract creation}"
    echo "Transfer Amount: $(wei_to_ether "$value") ETH"
    echo "Nonce: ${nonce:+$(hex_to_dec "$nonce")}"
    
    # Gas information
    echo -e "\n${YELLOW}⛽ Gas Information:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    if [[ -n "$gas_limit" ]]; then
        echo "Gas Limit: $(format_number $(hex_to_dec "$gas_limit")) Gas"
    fi
    if [[ -n "$gas_price" ]]; then
        echo "Gas Price: $(format_gas_price "$gas_price")"
    fi
    
    # Input data
    echo -e "\n${PURPLE}📝 Input Data:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    if [[ -z "$input_data" || "$input_data" == "0x" ]]; then
        echo "No input data (simple transfer)"
    else
        local data_length=${#input_data}
        local byte_length=$(( (data_length - 2) / 2 ))
        echo "Data Length: $data_length characters ($byte_length bytes)"
        if [[ $data_length -gt 100 ]]; then
            echo "Data Preview: ${input_data:0:100}..."
        else
            echo "Complete Data: $input_data"
        fi
        
        # Function selector
        if [[ $data_length -ge 10 ]]; then
            echo "Function Selector: ${input_data:0:10}"
        fi
    fi
    
    # Get transaction receipt
    echo -e "\n${CYAN}🧾 Querying transaction receipt...${NC}"
    local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$receipt_response" | grep -q '"result"' && ! echo "$receipt_response" | grep -q '"result":null'; then
        # Parse receipt information
        local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        local gas_used=$(echo "$receipt_response" | grep -o '"gasUsed":"[^"]*"' | cut -d'"' -f4)
        local cumulative_gas=$(echo "$receipt_response" | grep -o '"cumulativeGasUsed":"[^"]*"' | cut -d'"' -f4)
        local logs_count=$(echo "$receipt_response" | grep -o '"logs":\[' | wc -l)
        
        echo -e "\n${GREEN}📊 Transaction Execution Result:${NC}"
        echo "-" | tr ' ' '-' | head -c 50; echo
        
        if [[ "$status" == "0x1" ]]; then
            echo -e "${GREEN}✅ Transaction executed successfully${NC}"
        elif [[ "$status" == "0x0" ]]; then
            echo -e "${RED}❌ Transaction execution failed${NC}"
        else
            echo "Status: $status"
        fi
        
        if [[ -n "$gas_used" ]]; then
            echo "Actual Gas Used: $(format_number $(hex_to_dec "$gas_used")) Gas"
            
            # Calculate gas efficiency
            if [[ -n "$gas_limit" ]]; then
                local gas_limit_dec=$(hex_to_dec "$gas_limit")
                local gas_used_dec=$(hex_to_dec "$gas_used")
                if command -v bc >/dev/null 2>&1; then
                    local efficiency=$(echo "scale=2; $gas_used_dec * 100 / $gas_limit_dec" | bc)
                    echo "Gas Efficiency: $efficiency% ($(format_number $gas_used_dec)/$(format_number $gas_limit_dec))"
                fi
            fi
            
            # Calculate transaction fee
            if [[ -n "$gas_price" ]]; then
                local gas_price_dec=$(hex_to_dec "$gas_price")
                local gas_used_dec=$(hex_to_dec "$gas_used")
                local tx_fee_wei=$((gas_price_dec * gas_used_dec))
                local tx_fee_eth=$(wei_to_ether $(printf "0x%x" $tx_fee_wei))
                echo "Transaction Fee: $tx_fee_eth ETH ($(format_number $tx_fee_wei) Wei)"
            fi
        fi
        
        if [[ -n "$cumulative_gas" ]]; then
            echo "Block Cumulative Gas: $(format_number $(hex_to_dec "$cumulative_gas")) Gas"
        fi
        
        # Event logs count
        local actual_logs_count=$(echo "$receipt_response" | grep -o '"address":' | wc -l)
        echo "Event Logs: $actual_logs_count events"
    fi
    
    # Get block information
    if [[ -n "$block_hash" && "$block_hash" != "null" ]]; then
        echo -e "\n${CYAN}🧱 Querying block information...${NC}"
        local block_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByHash\",\"params\":[\"$block_hash\",false],\"id\":1}" \
            --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$block_response" | grep -q '"result"' && ! echo "$block_response" | grep -q '"result":null'; then
            # Parse block information
            local block_num=$(echo "$block_response" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
            local parent_hash=$(echo "$block_response" | grep -o '"parentHash":"[^"]*"' | cut -d'"' -f4)
            local miner=$(echo "$block_response" | grep -o '"miner":"[^"]*"' | cut -d'"' -f4)
            local timestamp=$(echo "$block_response" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4)
            local block_size=$(echo "$block_response" | grep -o '"size":"[^"]*"' | cut -d'"' -f4)
            local block_gas_limit=$(echo "$block_response" | grep -o '"gasLimit":"[^"]*"' | cut -d'"' -f4)
            local block_gas_used=$(echo "$block_response" | grep -o '"gasUsed":"[^"]*"' | cut -d'"' -f4)
            local tx_count=$(echo "$block_response" | grep -o '"transactions":\[' | wc -l)
            
            echo -e "\n${BLUE}🏗️ Block Information:${NC}"
            echo "-" | tr ' ' '-' | head -c 50; echo
            echo "Block Number: $(format_number $(hex_to_dec "$block_num"))"
            echo "Block Hash: $block_hash"
            echo "Parent Block Hash: ${parent_hash:-N/A}"
            echo "Miner/Validator: ${miner:-N/A}"
            echo "Timestamp: $(format_timestamp "$timestamp")"
            if [[ -n "$block_size" ]]; then
                echo "Block Size: $(format_number $(hex_to_dec "$block_size")) bytes"
            fi
            if [[ -n "$block_gas_limit" ]]; then
                echo "Block Gas Limit: $(format_number $(hex_to_dec "$block_gas_limit")) Gas"
            fi
            if [[ -n "$block_gas_used" ]]; then
                echo "Block Gas Used: $(format_number $(hex_to_dec "$block_gas_used")) Gas"
                
                # Calculate block gas utilization
                if [[ -n "$block_gas_limit" ]] && command -v bc >/dev/null 2>&1; then
                    local gas_limit_dec=$(hex_to_dec "$block_gas_limit")
                    local gas_used_dec=$(hex_to_dec "$block_gas_used")
                    local utilization=$(echo "scale=2; $gas_used_dec * 100 / $gas_limit_dec" | bc)
                    echo "Block Gas Utilization: $utilization%"
                fi
            fi
            
            # Transaction count (needs more accurate calculation)
            local actual_tx_count=$(echo "$block_response" | grep -o '"0x[a-fA-F0-9]\{64\}"' | wc -l)
            echo "Transaction Count: $actual_tx_count"
        fi
    fi
    
    # Address balance information
    echo -e "\n${GREEN}💰 Address Balance Information:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    
    if [[ -n "$from_addr" ]]; then
        local from_balance_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$from_addr\",\"latest\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$from_balance_response" | grep -q '"result"'; then
            local from_balance=$(echo "$from_balance_response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
            echo "Sender Balance: $(wei_to_ether "$from_balance") ETH ($from_addr)"
        fi
    fi
    
    if [[ -n "$to_addr" && "$to_addr" != "$from_addr" ]]; then
        local to_balance_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$to_addr\",\"latest\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$to_balance_response" | grep -q '"result"'; then
            local to_balance=$(echo "$to_balance_response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
            echo "Receiver Balance: $(wei_to_ether "$to_balance") ETH ($to_addr)"
        fi
    fi
    
    echo -e "\n$(printf '=%.0s' {1..80})"
    echo -e "${GREEN}✅ Query completed${NC}"
}

# Main function
main() {
    echo -e "${BLUE}🔍 Ethereum Transaction Details Query Tool (Bash Version)${NC}"
    echo "=" | tr ' ' '=' | head -c 80; echo
    
    # Check parameters
    if [[ $# -ne 1 ]]; then
        echo "Usage:"
        echo "  $0 <transaction_hash>"
        echo ""
        echo "Example:"
        echo "  $0 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        exit 1
    fi
    
    local tx_hash=$1
    
    # Validate transaction hash format
    if [[ ! "$tx_hash" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        echo -e "${RED}❌ Error: Invalid transaction hash format${NC}"
        echo "Transaction hash should be 66 characters long, hexadecimal string starting with 0x"
        exit 1
    fi
    
    # Find available RPC endpoint
    local endpoint
    endpoint=$(find_available_rpc)
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}❌ Error: No available RPC endpoint${NC}"
        exit 1
    fi
    
    # Query transaction details
    query_transaction_details "$tx_hash" "$endpoint"
}

# Execute main function
main "$@"