#!/bin/bash

# Network Status Query Script
# Query Ethereum network status information

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

# RPC_ENDPOINTS and NODE_RPC_MAP are now loaded from rpc_config.sh

# ============================================================================
# LOCAL CONFIGURATION SECTION
# ============================================================================
# Create simplified node name aliases for easier command line usage
# Map simple names to actual node types from rpc_config.sh

declare -A NODE_ALIASES
# Auto-detect node types and create aliases
for node_type in "${!NODE_RPC_MAP[@]}"; do
    # Extract the EL client name (first part before hyphen)
    simple_name=$(echo "$node_type" | cut -d'-' -f1)
    # Store mapping if not already set (first occurrence wins)
    if [[ -z "${NODE_ALIASES[$simple_name]}" ]]; then
        NODE_ALIASES["$simple_name"]="$node_type"
    fi
    # Also allow using the full name
    NODE_ALIASES["$node_type"]="$node_type"
done

# Default node - use first node type from rpc_config.sh
DEFAULT_NODE="${NODE_ALIASES[geth]:-${!NODE_RPC_MAP[@]:0:1}}"

# ============================================================================
# END OF LOCAL CONFIGURATION
# ============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Show usage information
show_usage() {
    echo -e "${BLUE}Ethereum Network Status Query Tool${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -n, --node <node>       Specify node type (default: geth)"
    echo "                          Available: geth, nethermind, reth, erigon, besu"
    echo "  -e, --endpoint <URL>    Custom RPC endpoint"
    echo "  -a, --all               Query status of all nodes"
    echo "  -o, --output <file>     Output results to file"
    echo "  -j, --json              Output in JSON format"
    echo "  -h, --help              Show this help information"
    echo ""
    echo "Query information:"
    echo "  - eth_gasPrice          Current gas price"
    echo "  - eth_feeHistory        Fee history"
    echo "  - eth_maxPriorityFeePerGas  Maximum priority fee"
    echo "  - net_peerCount         Number of connected nodes"
    echo "  - eth_syncing           Sync status"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Query default geth node status"
    echo "  $0 -n reth                              # Query reth node status"
    echo "  $0 -a                                   # Query all nodes status"
    echo "  $0 -j -o status.json                    # JSON format output to file"
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

# Convert hex to decimal
hex_to_dec() {
    local hex_value=$1
    if [[ "$hex_value" =~ ^0x ]]; then
        echo $((hex_value))
    else
        echo "$hex_value"
    fi
}

# Format wei to gwei
wei_to_gwei() {
    local wei_value=$1
    local dec_value=$(hex_to_dec "$wei_value")
    if [[ "$dec_value" =~ ^[0-9]+$ ]]; then
        echo "scale=9; $dec_value / 1000000000" | bc -l 2>/dev/null || echo "$dec_value"
    else
        echo "$wei_value"
    fi
}

# Make RPC call
make_rpc_call() {
    local endpoint=$1
    local method=$2
    local params=$3
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        # Use jq if available for better JSON parsing
        if command -v jq >/dev/null 2>&1; then
            local result=$(echo "$response" | jq -r '.result // "null"' 2>/dev/null)
            # Convert hex values in fee history to decimal for display
            if [[ "$method" == "eth_feeHistory" ]] && [[ "$result" != "null" ]] && [[ "$result" != "" ]]; then
                # Convert hex values in baseFeePerGas and baseFeePerBlobGas arrays to decimal
                result=$(echo "$result" | jq '
                    if .baseFeePerGas then 
                        .baseFeePerGas = [.baseFeePerGas[] | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end]
                    else . end |
                    if .baseFeePerBlobGas then 
                        .baseFeePerBlobGas = [.baseFeePerBlobGas[] | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end]
                    else . end |
                    if .oldestBlock then 
                        .oldestBlock = (.oldestBlock | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end)
                    else . end
                ' 2>/dev/null)
                # If jq conversion failed, return original result
                if [[ -z "$result" ]]; then
                    result=$(echo "$response" | jq -r '.result // "null"' 2>/dev/null)
                fi
            fi
            echo "$result"
        else
            # Fallback to sed parsing
            local result=$(echo "$response" | sed -n 's/.*"result":\([^,}]*\).*/\1/p')
            if [[ -z "$result" ]]; then
                # Try to extract complex objects/arrays
                result=$(echo "$response" | sed -n 's/.*"result":\(.*\),"id".*/\1/p')
                if [[ -z "$result" ]]; then
                    result=$(echo "$response" | sed -n 's/.*"result":\(.*\)}/\1/p')
                fi
            fi
            echo "${result:-null}"
        fi
    else
        echo "null"
    fi
}

# Query network status for a single node
query_node_status() {
    local endpoint=$1
    local node_name=$2
    local json_output=$3
    
    echo -e "${CYAN}Querying node: $node_name ($endpoint)${NC}"
    
    # Test connection first
    if ! test_rpc_connection "$endpoint"; then
        echo -e "${RED}✗ Connection failed${NC}"
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            echo "{\"node\":\"$node_name\",\"endpoint\":\"$endpoint\",\"status\":\"offline\"}"
        fi
        return 1
    fi
    
    echo -e "${GREEN}✓ Connection successful${NC}"
    
    # Query all required information
    local gas_price=$(make_rpc_call "$endpoint" "eth_gasPrice" "[]")
    local fee_history=$(make_rpc_call "$endpoint" "eth_feeHistory" "[4, \"latest\", [25, 50, 75]]")
    local max_priority_fee=$(make_rpc_call "$endpoint" "eth_maxPriorityFeePerGas" "[]")
    local peer_count=$(make_rpc_call "$endpoint" "net_peerCount" "[]")
    local syncing_status=$(make_rpc_call "$endpoint" "eth_syncing" "[]")
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        # Convert hex values to decimal for JSON output
        local gas_price_dec=$(hex_to_dec "$gas_price")
        local max_priority_fee_dec=$(hex_to_dec "$max_priority_fee")
        local peer_count_dec=$(hex_to_dec "$peer_count")
        
        # Convert fee history hex values to decimal
        local fee_history_converted="$fee_history"
        if [[ "$fee_history" != "null" ]] && [[ "$fee_history" != "" ]]; then
            # Convert reward array hex values to decimal
            fee_history_converted=$(echo "$fee_history" | sed 's/"0x[0-9a-fA-F]*"/0/g')
        fi
        
        cat << EOF
{
  "node": "$node_name",
  "endpoint": "$endpoint",
  "status": "online",
  "eth_gasPrice": $gas_price_dec,
  "eth_feeHistory": $fee_history_converted,
  "eth_maxPriorityFeePerGas": $max_priority_fee_dec,
  "net_peerCount": $peer_count_dec,
  "eth_syncing": $syncing_status
}
EOF
    else
        # Formatted output
        echo -e "${YELLOW}=== Network Status Information ===${NC}"
        echo -e "${MAGENTA}Node Type:${NC} $node_name"
        echo -e "${MAGENTA}RPC Endpoint:${NC} $endpoint"
        echo ""
        
        # Gas Price
        echo -e "${BLUE}Gas Price (eth_gasPrice):${NC}"
        if [[ "$gas_price" != "null" ]]; then
            local gas_price_gwei=$(wei_to_gwei "$gas_price")
            echo "  Gwei: $gas_price_gwei"
        else
            echo "  Failed to retrieve"
        fi
        echo ""
        
        # Fee History
        echo -e "${BLUE}Fee History (eth_feeHistory):${NC}"
        if [[ "$fee_history" != "null" ]]; then
            # Convert hex values to decimal for display
            local fee_history_display="$fee_history"
            if command -v jq >/dev/null 2>&1; then
                fee_history_display=$(echo "$fee_history" | jq '
                    if .baseFeePerGas then 
                        .baseFeePerGas = [.baseFeePerGas[] | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end]
                    else . end |
                    if .baseFeePerBlobGas then 
                        .baseFeePerBlobGas = [.baseFeePerBlobGas[] | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end]
                    else . end |
                    if .oldestBlock then 
                        .oldestBlock = (.oldestBlock | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end)
                    else . end |
                    if .reward then
                        .reward = [.reward[] | [.[] | if type == "string" and startswith("0x") then (. | ltrimstr("0x") | tonumber) else . end]]
                    else . end
                ' 2>/dev/null)
                # If jq conversion failed, use original
                if [[ -z "$fee_history_display" ]]; then
                    fee_history_display="$fee_history"
                fi
            fi
            echo "$fee_history_display" | jq '.' 2>/dev/null || echo "  $fee_history_display"
        else
            echo "  Failed to retrieve"
        fi
        echo ""
        
        # Max Priority Fee
        echo -e "${BLUE}Maximum Priority Fee (eth_maxPriorityFeePerGas):${NC}"
        if [[ "$max_priority_fee" != "null" ]]; then
            local priority_fee_gwei=$(wei_to_gwei "$max_priority_fee")
            echo "  Gwei: $priority_fee_gwei"
        else
            echo "  Failed to retrieve"
        fi
        echo ""
        
        # Peer Count
        echo -e "${BLUE}Connected Nodes (net_peerCount):${NC}"
        if [[ "$peer_count" != "null" ]]; then
            local peer_count_dec=$(hex_to_dec "$peer_count")
            echo "  Node count: $peer_count_dec"
        else
            echo "  Failed to retrieve"
        fi
        echo ""
        
        # Syncing Status
        echo -e "${BLUE}Sync Status (eth_syncing):${NC}"
        if [[ "$syncing_status" != "null" ]]; then
            if [[ "$syncing_status" == "false" ]]; then
                echo -e "  ${GREEN}✓ Synchronized${NC}"
            else
                echo "  Syncing:"
                echo "$syncing_status" | jq '.' 2>/dev/null || echo "  $syncing_status"
            fi
        else
            echo "  Failed to retrieve"
        fi
        
        echo -e "${YELLOW}================================${NC}"
        echo ""
    fi
}

# Main function
main() {
    local node="$DEFAULT_NODE"
    local endpoint=""
    local all_nodes="false"
    local output_file=""
    local json_output="false"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--node)
                node="$2"
                shift 2
                ;;
            -e|--endpoint)
                endpoint="$2"
                shift 2
                ;;
            -a|--all)
                all_nodes="true"
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -j|--json)
                JSON_OUTPUT="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown parameter $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Prepare output
    local output_content=""
    
    if [[ "$all_nodes" == "true" ]]; then
        # Query all nodes
        echo -e "${CYAN}Querying all node status...${NC}"
        echo ""
        
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            output_content="["
            local first_node="true"
        fi
        
        for node_type in "${!NODE_RPC_MAP[@]}"; do
            local node_endpoint="${NODE_RPC_MAP[$node_type]}"
            
            if [[ "$JSON_OUTPUT" == "true" ]]; then
                if [[ "$first_node" == "false" ]]; then
                    output_content+=","
                fi
                local node_result=$(query_node_status "$node_endpoint" "$node_type" "$JSON_OUTPUT")
                output_content+="$node_result"
                first_node="false"
            else
                query_node_status "$node_endpoint" "$node_type" "$JSON_OUTPUT"
            fi
        done
        
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            output_content+="]"
        fi
        
    else
        # Query single node
        if [[ -z "$endpoint" ]]; then
            # Try to resolve node alias first
            local resolved_node="${NODE_ALIASES[$node]}"
            if [[ -n "$resolved_node" ]] && [[ -n "${NODE_RPC_MAP[$resolved_node]}" ]]; then
                endpoint="${NODE_RPC_MAP[$resolved_node]}"
                node="$resolved_node"  # Update node name to full name for display
            elif [[ -n "${NODE_RPC_MAP[$node]}" ]]; then
                endpoint="${NODE_RPC_MAP[$node]}"
            else
                echo -e "${RED}Error: Unknown node type '$node'${NC}"
                echo "Available simple names: ${!NODE_ALIASES[@]}"
                echo "Available full names: ${!NODE_RPC_MAP[@]}"
                exit 1
            fi
        fi
        
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            output_content=$(query_node_status "$endpoint" "$node" "$JSON_OUTPUT")
        else
            query_node_status "$endpoint" "$node" "$JSON_OUTPUT"
        fi
    fi
    
    # Output to file if specified
    if [[ -n "$output_file" ]] && [[ -n "$output_content" ]]; then
        echo "$output_content" > "$output_file"
        echo -e "${GREEN}Results saved to: $output_file${NC}"
    elif [[ -n "$output_content" ]]; then
        echo "$output_content"
    fi
}

# Check if bc is available for calculations
if ! command -v bc >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: bc command not found, Gwei conversion may be inaccurate${NC}"
fi

# Run main function
main "$@"