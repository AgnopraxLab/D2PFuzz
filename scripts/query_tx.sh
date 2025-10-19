#!/bin/bash

# Simple transaction query script (Bash version)
# Use curl to directly call RPC interface for transaction queries

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

# Query block information to get base fee per gas
query_block_info() {
    local block_number=$1
    local endpoint=$2
    
    # Query block information
    local block_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"$block_number\",false],\"id\":1}" \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$block_response" | grep -q '"result":{'; then
        # Extract base fee per gas (EIP-1559)
        local base_fee=$(echo "$block_response" | grep -o '"baseFeePerGas":"[^"]*"' | cut -d'"' -f4)
        if [[ -n "$base_fee" && "$base_fee" != "null" ]]; then
            # Convert hex to decimal and format as Gwei
            local base_fee_dec=$((16#${base_fee#0x}))
            local base_fee_gwei=$(echo "scale=9; $base_fee_dec / 1000000000" | bc -l 2>/dev/null || echo "N/A")
            echo "$base_fee_gwei"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

# Show usage information
show_usage() {
    echo "Usage:"
    echo "  $0 <tx_hash1> [tx_hash2] [tx_hash3] ..."
    echo "  $0 -f <filename>  # Read transaction hashes from file"
    echo "  $0 -h|--help     # Show this help message"
    echo ""
    echo "Transaction Status Categories:"
    echo "  ✓ Confirmed  - Transaction successfully mined and confirmed"
    echo "  ⏳ Pending   - Transaction in mempool, ready for mining"
    echo "  ⏸️ Queued    - Transaction in mempool, waiting for conditions"
    echo "  ✗ Failed     - Transaction mined but execution failed"
    echo "  ❌ Not Found - Transaction hash not found"
    echo ""
    echo "Examples:"
    echo "  $0 0x1234567890abcdef..."
    echo "  $0 -f sample_tx_hashes.txt"
    echo "  $0 --help"
}

# Check if transaction is in mempool (pending or queued)
check_mempool_status() {
    local tx_hash=$1
    local endpoint=$2
    
    # Query txpool_content to check if transaction is in pending or queued
    local txpool_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && ! echo "$txpool_response" | grep -q '"error"'; then
        # Check if transaction is in pending pool
        if echo "$txpool_response" | grep -q "\"$tx_hash\""; then
            # Check if it's in pending or queued
            if echo "$txpool_response" | jq -r '.result.pending' 2>/dev/null | grep -q "\"$tx_hash\""; then
                echo "pending"
                return 0
            elif echo "$txpool_response" | jq -r '.result.queued' 2>/dev/null | grep -q "\"$tx_hash\""; then
                echo "queued"
                return 0
            fi
        fi
    fi
    
    # Fallback: if txpool_content is not available, assume it's pending
    echo "pending"
    return 0
}

# Query single transaction
query_transaction() {
    local tx_hash=$1
    local endpoint=$2
    
    # Query transaction information
    local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗${NC} $tx_hash - RPC call failed"
        return 1
    fi
    
    # Check if transaction exists
    if echo "$tx_response" | grep -q '"result":null'; then
        echo -e "${RED}✗${NC} $tx_hash - Transaction not found"
        return 1
    elif echo "$tx_response" | grep -q '"result":{'; then
        # Extract block number
        local block_number=$(echo "$tx_response" | grep -o '"blockNumber":[^,}]*' | cut -d':' -f2)
        
        if [[ "$block_number" == "null" || -z "$block_number" ]]; then
            # Transaction is in mempool, check if it's pending or queued
            local mempool_status=$(check_mempool_status "$tx_hash" "$endpoint")
            if [[ "$mempool_status" == "queued" ]]; then
                echo -e "${YELLOW}⏳${NC} $tx_hash - Transaction queued (waiting for conditions)"
            else
                echo -e "${YELLOW}◐${NC} $tx_hash - Transaction pending (ready for mining)"
            fi
        else
            # Query transaction receipt to get status
            local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
                --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
                --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
            
            local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local block_num_dec=$((16#${block_number#0x}))
            
            # Query block information to get base fee per gas
            local base_fee_gwei=$(query_block_info "$block_number" "$endpoint")
            local base_fee_info=""
            if [[ "$base_fee_gwei" != "N/A" ]]; then
                base_fee_info=" | Base Fee: ${base_fee_gwei} Gwei"
            fi
            
            if [[ "$status" == "0x1" ]]; then
                echo -e "${GREEN}✓${NC} $tx_hash - Transaction successful (Block: $block_num_dec${base_fee_info})"
            elif [[ "$status" == "0x0" ]]; then
                echo -e "${RED}✗${NC} $tx_hash - Transaction failed (Block: $block_num_dec${base_fee_info})"
            else
                echo -e "${GREEN}✓${NC} $tx_hash - Transaction confirmed (Block: $block_num_dec${base_fee_info})"
            fi
        fi
        return 0
    else
        echo -e "${RED}✗${NC} $tx_hash - Response format error"
        return 1
    fi
}

# Main function
main() {
    echo -e "${BLUE}Ethereum Transaction Query Tool (Bash Version)${NC}"
    echo "=" | tr ' ' '=' | head -c 50; echo
    
    # Check parameters
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    # Handle help parameter
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_usage
        exit 0
    fi
    
    # Test RPC connections
    echo "Testing RPC connections..."
    available_endpoints=()
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            echo -e "${GREEN}✓${NC} $endpoint connection successful"
            available_endpoints+=("$endpoint")
        else
            echo -e "${RED}✗${NC} $endpoint connection failed"
        fi
    done
    
    if [[ ${#available_endpoints[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No available RPC endpoints${NC}"
        exit 1
    fi
    
    echo -e "\nUsing ${#available_endpoints[@]} available RPC endpoints for queries...\n"
    
    # Prepare transaction hash list with node information
    tx_hashes=()
    tx_nodes=()  # Array to store corresponding node types
    if [[ "$1" == "-f" ]]; then
        # Read from file
        if [[ ! -f "$2" ]]; then
            echo -e "${RED}Error: File $2 does not exist${NC}"
            exit 1
        fi
        
        current_node=""
        while IFS= read -r line; do
            # Check if line is a node type comment
            if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*([a-zA-Z0-9_-]+)[[:space:]]*$ ]]; then
                current_node="${BASH_REMATCH[1]}"
                echo "Found node type: $current_node"
            # Skip empty lines and other comment lines
            elif [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                tx_hashes+=("$line")
                tx_nodes+=("$current_node")
            fi
        done < "$2"
        
        echo "Read ${#tx_hashes[@]} transaction hashes from file $2"
        if [[ -n "$current_node" ]]; then
            echo "Detected multi-node transaction format"
        fi
    else
        # Read from command line arguments
        tx_hashes=("$@")
        # For command line arguments, use default round-robin assignment
        for ((i=0; i<${#tx_hashes[@]}; i++)); do
            tx_nodes+=("")
        done
    fi
    
    if [[ ${#tx_hashes[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No transaction hashes found to query${NC}"
        exit 1
    fi
    
    # Query statistics and grouping arrays
    local total=${#tx_hashes[@]}
    local success=0
    local failed=0
    local existing_txs=()
    local non_existing_txs=()
    local confirmed_txs=()
    local pending_txs=()
    local queued_txs=()
    local failed_txs=()
    
    echo -e "Preparing to query $total transaction hashes...\n"
    
    # Execute queries and collect results
    for i in "${!tx_hashes[@]}"; do
        local tx_hash="${tx_hashes[$i]}"
        local tx_node="${tx_nodes[$i]}"
        
        # Determine which endpoint to use
        local endpoint=""
        local node_info=""
        
        if [[ -n "$tx_node" && -n "${NODE_RPC_MAP[$tx_node]}" ]]; then
            # Use node-specific RPC endpoint
            endpoint="${NODE_RPC_MAP[$tx_node]}"
            node_info="[$tx_node] "
        else
            # Use round-robin assignment for backward compatibility
            local endpoint_index=$((i % ${#available_endpoints[@]}))
            endpoint="${available_endpoints[$endpoint_index]}"
            node_info=""
        fi
        
        # Query transaction information
        local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -ne 0 ]]; then
            non_existing_txs+=("${node_info}$tx_hash - RPC call failed")
            ((failed++))
        elif echo "$tx_response" | grep -q '"result":null'; then
            non_existing_txs+=("${node_info}$tx_hash - Transaction not found")
            ((failed++))
        elif echo "$tx_response" | grep -q '"result":{'; then
            # Extract block number
            local block_number=$(echo "$tx_response" | grep -o '"blockNumber":[^,}]*' | cut -d':' -f2 | tr -d '"')
            
            if [[ "$block_number" == "null" || -z "$block_number" ]]; then
                # Transaction is in mempool, check if it's pending or queued
                local mempool_status=$(check_mempool_status "$tx_hash" "$endpoint")
                if [[ "$mempool_status" == "queued" ]]; then
                    queued_txs+=("${node_info}$tx_hash - Transaction queued (waiting for conditions)")
                else
                    pending_txs+=("${node_info}$tx_hash - Transaction pending (ready for mining)")
                fi
                existing_txs+=("${node_info}$tx_hash")
            else
                # Query transaction receipt to get status
                local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
                    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
                    --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
                
                local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                local block_num_dec=$((16#${block_number#0x}))
                
                # Query block information to get base fee per gas
                local base_fee_gwei=$(query_block_info "$block_number" "$endpoint")
                local base_fee_info=""
                if [[ "$base_fee_gwei" != "N/A" ]]; then
                    base_fee_info=" | Base Fee: ${base_fee_gwei} Gwei"
                fi
                
                if [[ "$status" == "0x1" ]]; then
                    confirmed_txs+=("${node_info}$tx_hash - Transaction successful (Block: $block_num_dec${base_fee_info})")
                elif [[ "$status" == "0x0" ]]; then
                    failed_txs+=("${node_info}$tx_hash - Transaction failed (Block: $block_num_dec${base_fee_info})")
                else
                    confirmed_txs+=("${node_info}$tx_hash - Transaction confirmed (Block: $block_num_dec${base_fee_info})")
                fi
                existing_txs+=("${node_info}$tx_hash")
            fi
            ((success++))
        else
            non_existing_txs+=("${node_info}$tx_hash - Response format error")
            ((failed++))
        fi
        
        # Add small delay to avoid too frequent requests
        sleep 0.1
    done
    
    # Display query results by groups
    echo ""
    echo "=== Query Results (Grouped by Status) ==="
    
    # Display existing transactions
    if [[ ${#existing_txs[@]} -gt 0 ]]; then
        echo -e "${GREEN}✓ Existing Transactions (${#existing_txs[@]} total):${NC}"
        echo "----------------------------------------"
        
        # Display successful transactions
        if [[ ${#confirmed_txs[@]} -gt 0 ]]; then
            echo -e "${GREEN}  Confirmed Transactions:${NC}"
            for tx in "${confirmed_txs[@]}"; do
                echo -e "    ${GREEN}✓${NC} $tx"
            done
            echo ""
        fi
        
        # Display pending transactions
        if [[ ${#pending_txs[@]} -gt 0 ]]; then
            echo -e "${YELLOW}  Pending Transactions:${NC}"
            for tx in "${pending_txs[@]}"; do
                echo -e "    ${YELLOW}◐${NC} $tx"
            done
            echo ""
        fi
        
        # Display queued transactions
        if [[ ${#queued_txs[@]} -gt 0 ]]; then
            echo -e "${BLUE}  Queued Transactions:${NC}"
            for tx in "${queued_txs[@]}"; do
                echo -e "    ${BLUE}⏳${NC} $tx"
            done
            echo ""
        fi
        
        # Display failed transactions
        if [[ ${#failed_txs[@]} -gt 0 ]]; then
            echo -e "${RED}  Failed Transactions:${NC}"
            for tx in "${failed_txs[@]}"; do
                echo -e "    ${RED}✗${NC} $tx"
            done
            echo ""
        fi
    fi
    
    # Display non-existing transactions
    if [[ ${#non_existing_txs[@]} -gt 0 ]]; then
        echo -e "${RED}✗ Non-existing Transactions (${#non_existing_txs[@]} total):${NC}"
        echo "----------------------------------------"
        for tx in "${non_existing_txs[@]}"; do
            echo -e "    ${RED}✗${NC} $tx"
        done
        echo ""
    fi
    
    # Print statistical results
    echo "=== Query Results Statistics ==="
    echo "Total queries: $total"
    echo -e "Existing transactions: ${GREEN}${#existing_txs[@]}${NC}"
    echo -e "  - Confirmed: ${GREEN}${#confirmed_txs[@]}${NC}"
    echo -e "  - Pending: ${YELLOW}${#pending_txs[@]}${NC}"
    echo -e "  - Queued: ${BLUE}${#queued_txs[@]}${NC}"
    echo -e "  - Failed: ${RED}${#failed_txs[@]}${NC}"
    echo -e "Non-existing transactions: ${RED}${#non_existing_txs[@]}${NC}"
    if [[ $total -gt 0 ]]; then
        local success_rate=$((success * 100 / total))
        echo "Success rate: ${success_rate}%"
    fi
    
    # Print node-specific statistics if multi-node format detected
    local has_node_info=false
    for node in "${tx_nodes[@]}"; do
        if [[ -n "$node" ]]; then
            has_node_info=true
            break
        fi
    done
    
    if [[ "$has_node_info" == true ]]; then
        echo ""
        echo "=== Node-specific Statistics ==="
        declare -A node_stats
        declare -A node_success
        
        for i in "${!tx_hashes[@]}"; do
            local node="${tx_nodes[$i]}"
            if [[ -n "$node" ]]; then
                ((node_stats["$node"]++))
            fi
        done
        
        # Count successful transactions per node
        for tx in "${existing_txs[@]}"; do
            if [[ "$tx" =~ ^\[([^\]]+)\] ]]; then
                local node="${BASH_REMATCH[1]}"
                ((node_success["$node"]++))
            fi
        done
        
        for node in "${!node_stats[@]}"; do
            local total_node=${node_stats["$node"]}
            local success_node=${node_success["$node"]:-0}
            local rate_node=$((success_node * 100 / total_node))
            echo -e "${BLUE}$node${NC}: $success_node/$total_node (${rate_node}%)"
        done
    fi
}

# Execute main function
main "$@"