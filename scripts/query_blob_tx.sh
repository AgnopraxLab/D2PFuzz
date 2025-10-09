#!/bin/bash

# Blob Transaction Query Script
# Query blob transaction details including blob data status

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

# Beacon API endpoint (default to localhost)
BEACON_ENDPOINT="${BEACON_ENDPOINT:-http://localhost:4000}"

# Show usage information
show_usage() {
    echo "Usage:"
    echo "  $0 <tx_hash1> [tx_hash2] [tx_hash3] ..."
    echo "  $0 -f <filename>  # Read transaction hashes from file"
    echo "  $0 -h|--help     # Show this help message"
    echo ""
    echo "Blob Transaction Status:"
    echo "  ✓ Confirmed with Blobs  - Transaction mined, blobs stored in beacon chain"
    echo "  ✓ Confirmed (No Blobs)  - Type-3 tx mined, but blob data not found"
    echo "  ⏳ Pending              - Transaction in mempool"
    echo "  ✗ Failed                - Transaction mined but execution failed"
    echo "  ❌ Not Found            - Transaction hash not found"
    echo ""
    echo "Examples:"
    echo "  $0 0x1234567890abcdef..."
    echo "  $0 -f blob_tx_hashes.txt"
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

# Query blob data from beacon chain
query_blob_sidecars() {
    local block_id=$1
    local response=$(curl -s "${BEACON_ENDPOINT}/eth/v1/beacon/blob_sidecars/${block_id}" \
        --connect-timeout 5 --max-time 10 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"data"'; then
        echo "$response"
        return 0
    else
        return 1
    fi
}

# Check if transaction has blob versioned hashes
check_blob_tx_type() {
    local tx_data=$1
    
    # Check if transaction type is 0x3 (blob transaction)
    local tx_type=$(echo "$tx_data" | grep -o '"type":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [[ "$tx_type" == "0x3" ]]; then
        return 0
    fi
    
    # Also check for blobVersionedHashes field
    if echo "$tx_data" | grep -q '"blobVersionedHashes"'; then
        return 0
    fi
    
    return 1
}

# Query single blob transaction
query_blob_transaction() {
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
        echo -e "${RED}❌${NC} $tx_hash - Transaction not found"
        return 1
    elif echo "$tx_response" | grep -q '"result":{'; then
        local tx_data=$(echo "$tx_response" | grep -o '"result":{[^}]*}' || echo "$tx_response")
        
        # Check if it's a blob transaction
        if ! check_blob_tx_type "$tx_data"; then
            echo -e "${YELLOW}⚠${NC} $tx_hash - Not a blob transaction (Type-3)"
            return 1
        fi
        
        # Extract block number and blob hashes
        local block_number=$(echo "$tx_data" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
        local blob_hashes=$(echo "$tx_data" | grep -o '"blobVersionedHashes":\[[^\]]*\]' | sed 's/"blobVersionedHashes"://')
        local blob_count=$(echo "$blob_hashes" | grep -o '0x[0-9a-fA-F]*' | wc -l)
        
        if [[ "$block_number" == "null" || -z "$block_number" ]]; then
            echo -e "${YELLOW}⏳${NC} $tx_hash - Blob transaction pending (Blobs: $blob_count)"
            if [[ $blob_count -gt 0 ]]; then
                echo "     Blob Hashes:"
                echo "$blob_hashes" | grep -o '0x[0-9a-fA-F]*' | head -5 | while read hash; do
                    echo "       - $hash"
                done
            fi
        else
            # Query transaction receipt to get status
            local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
                --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
                --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
            
            local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local block_num_dec=$((16#${block_number#0x}))
            local gas_used=$(echo "$receipt_response" | grep -o '"gasUsed":"[^"]*"' | cut -d'"' -f4)
            local gas_used_dec=$((16#${gas_used#0x}))
            
            # Extract blob gas used (EIP-4844)
            local blob_gas_used=$(echo "$receipt_response" | grep -o '"blobGasUsed":"[^"]*"' | cut -d'"' -f4)
            local blob_gas_price=$(echo "$receipt_response" | grep -o '"blobGasPrice":"[^"]*"' | cut -d'"' -f4)
            
            local blob_info=""
            if [[ -n "$blob_gas_used" && "$blob_gas_used" != "null" ]]; then
                local blob_gas_dec=$((16#${blob_gas_used#0x}))
                blob_info=" | Blob Gas: $blob_gas_dec"
                
                if [[ -n "$blob_gas_price" && "$blob_gas_price" != "null" ]]; then
                    local blob_price_dec=$((16#${blob_gas_price#0x}))
                    local blob_price_gwei=$(echo "scale=2; $blob_price_dec / 1000000000" | bc -l 2>/dev/null || echo "N/A")
                    blob_info="$blob_info | Blob Price: ${blob_price_gwei} Gwei"
                fi
            fi
            
            if [[ "$status" == "0x1" ]]; then
                echo -e "${GREEN}✓${NC} $tx_hash - Blob transaction successful"
                echo "     Block: $block_num_dec | Gas: $gas_used_dec${blob_info}"
                echo "     Blob Count: $blob_count"
                
                if [[ $blob_count -gt 0 ]]; then
                    echo "     Blob Versioned Hashes:"
                    echo "$blob_hashes" | grep -o '0x[0-9a-fA-F]*' | while read hash; do
                        echo "       - $hash"
                    done
                    
                    # Try to query blob sidecars from beacon chain
                    echo "     Querying blob sidecars from beacon chain..."
                    local beacon_response=$(query_blob_sidecars "$block_num_dec")
                    if [[ $? -eq 0 ]]; then
                        local sidecar_count=$(echo "$beacon_response" | grep -o '"index":"[^"]*"' | wc -l)
                        echo -e "     ${GREEN}✓${NC} Found $sidecar_count blob sidecar(s) in beacon chain"
                    else
                        echo -e "     ${YELLOW}⚠${NC} Blob sidecars not found in beacon chain (may not be available yet)"
                    fi
                fi
            elif [[ "$status" == "0x0" ]]; then
                echo -e "${RED}✗${NC} $tx_hash - Blob transaction failed (Block: $block_num_dec)"
            else
                echo -e "${GREEN}✓${NC} $tx_hash - Blob transaction confirmed (Block: $block_num_dec)"
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
    echo -e "${CYAN}Blob Transaction Query Tool${NC}"
    echo "==========================================="
    
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
    
    echo -e "\nUsing ${#available_endpoints[@]} available RPC endpoint(s)...\n"
    
    # Prepare transaction hash list
    tx_hashes=()
    if [[ "$1" == "-f" ]]; then
        # Read from file
        if [[ ! -f "$2" ]]; then
            echo -e "${RED}Error: File $2 does not exist${NC}"
            exit 1
        fi
        
        while IFS= read -r line; do
            # Skip empty lines and comments
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                tx_hashes+=("$line")
            fi
        done < "$2"
        
        echo "Read ${#tx_hashes[@]} transaction hashes from file $2"
    else
        # Read from command line arguments
        tx_hashes=("$@")
    fi
    
    if [[ ${#tx_hashes[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No transaction hashes found to query${NC}"
        exit 1
    fi
    
    echo -e "Querying ${#tx_hashes[@]} transaction hash(es)...\n"
    
    # Execute queries
    local success=0
    local failed=0
    for i in "${!tx_hashes[@]}"; do
        local tx_hash="${tx_hashes[$i]}"
        local endpoint_index=$((i % ${#available_endpoints[@]}))
        local endpoint="${available_endpoints[$endpoint_index]}"
        
        if query_blob_transaction "$tx_hash" "$endpoint"; then
            ((success++))
        else
            ((failed++))
        fi
        echo ""
        
        # Add small delay to avoid too frequent requests
        sleep 0.2
    done
    
    # Print statistics
    echo "==========================================="
    echo "Query Statistics:"
    echo "Total: ${#tx_hashes[@]}"
    echo -e "Success: ${GREEN}$success${NC}"
    echo -e "Failed: ${RED}$failed${NC}"
}

# Execute main function
main "$@"

