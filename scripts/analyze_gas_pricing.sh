#!/bin/bash

# Ethereum Client Gas Price Analysis Script
# Analyze gas price strategies and transaction requirements for various clients

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

# ============================================================================
# LOCAL CONFIGURATION SECTION
# ============================================================================
# This section defines local mappings and configurations specific to this script.
# Modify these values to customize node numbering and display names.

# Node number assignment mapping
# Format: [node_type_from_rpc_config]="node_number"
declare -A NODE_NUMBER_MAP=(
    ["geth-lighthouse"]="12"
    ["nethermind-teku"]="14"
    ["besu-prysm"]="15"
    ["besu-lodestar"]="16"
    ["geth-nimbus"]="13"
)

# Node display name mapping (optional customization)
# If not defined here, will use the node type from rpc_config.sh
declare -A NODE_DISPLAY_NAMES=(
    ["geth-lighthouse"]="Geth-Lighthouse"
    ["nethermind-teku"]="Nethermind-Teku"
    ["besu-prysm"]="Besu-Prysm"
    ["besu-lodestar"]="Besu-Lodestar"
    ["geth-nimbus"]="Geth-Nimbus"
)

# Available node numbers for iteration (sorted array)
NODE_NUMBERS=(12 13 14 15 16)

# Client configuration notes (optional)
# Define gas price configuration notes for each client type
declare -A CLIENT_CONFIG_NOTES=(
    ["geth-lighthouse"]="Geth: --miner.gasprice=1 (1 wei, only in kurtosis network)"
    ["nethermind-teku"]="Nethermind: Uses low gas price strategy similar to Geth"
    ["besu-prysm"]="Besu: --min-gas-price=1000000000 (1 Gwei)"
    ["besu-lodestar"]="Besu: --min-gas-price=1000000000 (1 Gwei)"
    ["geth-nimbus"]="Geth: --miner.gasprice=1 (1 wei, only in kurtosis network)"
)

# Transaction parameter recommendations
# Define different gas price strategies
CONSERVATIVE_TIP_CAP="1500000000"  # 1.5 Gwei
CONSERVATIVE_FEE_CAP="3000000000"  # 3 Gwei
AGGRESSIVE_TIP_CAP="10000000"      # 0.01 Gwei
AGGRESSIVE_FEE_CAP="50000000"      # 0.05 Gwei
MINIMUM_TIP_CAP="1000000000"       # 1 Gwei
MINIMUM_FEE_CAP="2000000000"       # 2 Gwei
STANDARD_GAS="21000"

# Strategy descriptions (can be customized based on your node types)
CONSERVATIVE_CLIENTS="all clients"
AGGRESSIVE_CLIENTS="low gas price clients (Geth, Nethermind)"
MINIMUM_CLIENTS="strict gas price clients (Besu)"

# ============================================================================
# END OF LOCAL CONFIGURATION
# ============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Build NODE_ENDPOINTS and NODE_NAMES from configuration
declare -A NODE_ENDPOINTS
declare -A NODE_NAMES

for node_type in "${!NODE_RPC_MAP[@]}"; do
    node_num="${NODE_NUMBER_MAP[$node_type]}"
    if [[ -n "$node_num" ]]; then
        NODE_ENDPOINTS[$node_num]="${NODE_RPC_MAP[$node_type]}"
        # Use display name if defined, otherwise use node type
        if [[ -n "${NODE_DISPLAY_NAMES[$node_type]}" ]]; then
            NODE_NAMES[$node_num]="${NODE_DISPLAY_NAMES[$node_type]}"
        else
            NODE_NAMES[$node_num]="$node_type"
        fi
    fi
done

# Utility functions
hex_to_dec() {
    printf "%d" "$1" 2>/dev/null || echo "0"
}

format_number() {
    printf "%'d" "$1" 2>/dev/null || echo "$1"
}

wei_to_gwei() {
    local wei=$1
    if command -v bc >/dev/null 2>&1; then
        echo "scale=9; $wei / 1000000000" | bc
    else
        echo "$(($wei / 1000000000))"
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

# Get client version
get_client_version() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        echo "$response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4
    else
        echo "N/A"
    fi
}

# Get gas price
get_gas_price() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        echo "$response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4
    else
        echo "0x0"
    fi
}

# Get base fee
get_base_fee() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        echo "$response" | grep -o '"baseFeePerGas":"[^"]*"' | cut -d'"' -f4
    else
        echo "0x0"
    fi
}

# Get mempool status
get_mempool_status() {
    local endpoint=$1
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        local pending=$(echo "$response" | grep -o '"pending":{[^}]*}' | grep -o '{[^}]*}' | wc -c)
        local queued=$(echo "$response" | grep -o '"queued":{[^}]*}' | grep -o '{[^}]*}' | wc -c)
        echo "pending: $pending, queued: $queued"
    else
        echo "N/A"
    fi
}

# Main analysis function
analyze_all_clients() {
    echo -e "${BLUE}=== Ethereum Client Gas Price Comprehensive Analysis ===${NC}"
    echo ""
    
    # 1. Client version check
    echo -e "${CYAN}1. Client Version Information:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    for node in "${NODE_NUMBERS[@]}"; do
        local endpoint="${NODE_ENDPOINTS[$node]}"
        local name="${NODE_NAMES[$node]}"
        
        if test_rpc_connection "$endpoint"; then
            local version=$(get_client_version "$endpoint")
            echo -e "${GREEN}✓${NC} Node $node ($name): $version"
        else
            echo -e "${RED}✗${NC} Node $node ($name): Connection failed"
        fi
    done
    echo ""
    
    # 2. Comprehensive gas price comparison
    echo -e "${CYAN}2. Comprehensive Gas Price Analysis:${NC}"
    echo "-" | tr ' ' '-' | head -c 100; echo
    printf "%-10s %-20s %-18s %-18s %-18s\n" "Node" "Client" "GasPrice(Gwei)" "BaseFee(Gwei)" "BaseFee(Hex)"
    echo "-" | tr ' ' '-' | head -c 100; echo
    
    for node in "${NODE_NUMBERS[@]}"; do
        local endpoint="${NODE_ENDPOINTS[$node]}"
        local name="${NODE_NAMES[$node]}"
        
        if test_rpc_connection "$endpoint"; then
            # Get gas price
            local gas_price_hex=$(get_gas_price "$endpoint")
            local gas_price_dec=$(hex_to_dec "$gas_price_hex")
            local gas_price_gwei=$(wei_to_gwei "$gas_price_dec")
            
            # Get base fee
            local base_fee_hex=$(get_base_fee "$endpoint")
            local base_fee_dec=$(hex_to_dec "$base_fee_hex")
            local base_fee_gwei=$(wei_to_gwei "$base_fee_dec")
            
            printf "%-10s %-20s %-18s %-18s %-18s\n" \
                "Node $node" \
                "$name" \
                "${gas_price_gwei}" \
                "${base_fee_gwei}" \
                "$base_fee_hex"
        else
            printf "%-10s %-20s %-18s %-18s %-18s\n" \
                "Node $node" \
                "$name" \
                "N/A" \
                "N/A" \
                "Connection failed"
        fi
    done
    echo ""
    
    # 3. Mempool status
    echo -e "${CYAN}3. Mempool Status Check:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    for node in "${NODE_NUMBERS[@]}"; do
        local endpoint="${NODE_ENDPOINTS[$node]}"
        local name="${NODE_NAMES[$node]}"
        
        if test_rpc_connection "$endpoint"; then
            local mempool_status=$(get_mempool_status "$endpoint")
            echo "Node $node ($name): $mempool_status"
        else
            echo "Node $node ($name): Connection failed"
        fi
    done
    echo ""
    
    # 4. Configuration analysis summary
    echo -e "${CYAN}4. Client Configuration Analysis:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "Minimum gas price settings derived from configuration file analysis:"
    
    # Display configuration notes for each configured node type
    local displayed_notes=()
    for node_type in "${!NODE_RPC_MAP[@]}"; do
        if [[ -n "${CLIENT_CONFIG_NOTES[$node_type]}" ]]; then
            # Check if this note was already displayed (to avoid duplicates)
            local note="${CLIENT_CONFIG_NOTES[$node_type]}"
            local already_shown=0
            for shown in "${displayed_notes[@]}"; do
                if [[ "$shown" == "$note" ]]; then
                    already_shown=1
                    break
                fi
            done
            
            if [[ $already_shown -eq 0 ]]; then
                echo "• $note"
                displayed_notes+=("$note")
            fi
        fi
    done
    
    # If no notes were configured, show a default message
    if [[ ${#displayed_notes[@]} -eq 0 ]]; then
        echo "• No specific configuration notes available"
    fi
    echo ""
    
    # 5. EIP-1559 transaction recommendations
    echo -e "${CYAN}5. EIP-1559 Transaction Parameter Recommendations:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "Based on analysis results, recommended transaction parameters:"
    echo ""
    echo -e "${GREEN}Conservative Strategy (suitable for ${CONSERVATIVE_CLIENTS}):${NC}"
    echo "GasTipCap: big.NewInt(${CONSERVATIVE_TIP_CAP})  // $(wei_to_gwei ${CONSERVATIVE_TIP_CAP}) Gwei"
    echo "GasFeeCap:  big.NewInt(${CONSERVATIVE_FEE_CAP})  // $(wei_to_gwei ${CONSERVATIVE_FEE_CAP}) Gwei"
    echo "Gas:       ${STANDARD_GAS}"
    echo ""
    echo -e "${YELLOW}Aggressive Strategy (suitable for ${AGGRESSIVE_CLIENTS}):${NC}"
    echo "GasTipCap: big.NewInt(${AGGRESSIVE_TIP_CAP})     // $(wei_to_gwei ${AGGRESSIVE_TIP_CAP}) Gwei"
    echo "GasFeeCap:  big.NewInt(${AGGRESSIVE_FEE_CAP})    // $(wei_to_gwei ${AGGRESSIVE_FEE_CAP}) Gwei"
    echo "Gas:       ${STANDARD_GAS}"
    echo ""
    echo -e "${PURPLE}Minimum Requirements (suitable for ${MINIMUM_CLIENTS}):${NC}"
    echo "GasTipCap: big.NewInt(${MINIMUM_TIP_CAP})   // $(wei_to_gwei ${MINIMUM_TIP_CAP}) Gwei"
    echo "GasFeeCap:  big.NewInt(${MINIMUM_FEE_CAP})  // $(wei_to_gwei ${MINIMUM_FEE_CAP}) Gwei"
    echo "Gas:       ${STANDARD_GAS}"
    echo ""
    
    # 6. Troubleshooting recommendations
    echo -e "${CYAN}6. Troubleshooting Recommendations:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "If transactions still fail, please check:"
    echo "• Whether account balance is sufficient to pay gas fees"
    echo "• Whether nonce value is correct"
    echo "• Whether network congestion is causing base fee increases"
    echo "• Whether correct chain ID is used"
    echo "• Whether transaction signature is correct"
    echo ""
    
    echo -e "${GREEN}=== Analysis Complete ===${NC}"
}

# Quick check for specific node
quick_check() {
    local node=$1
    
    if [[ -z "$node" ]]; then
        echo "Usage: $0 quick <node_number>"
        echo -n "Available node numbers: "
        for num in "${NODE_NUMBERS[@]}"; do
            echo -n "$num(${NODE_NAMES[$num]}) "
        done
        echo ""
        return 1
    fi
    
    local endpoint="${NODE_ENDPOINTS[$node]}"
    local name="${NODE_NAMES[$node]}"
    
    if [[ -z "$endpoint" ]]; then
        echo "Invalid node number: $node"
        return 1
    fi
    
    echo -e "${BLUE}=== Quick Check Node $node ($name) ===${NC}"
    
    if test_rpc_connection "$endpoint"; then
        local version=$(get_client_version "$endpoint")
        local gas_price_hex=$(get_gas_price "$endpoint")
        local gas_price_dec=$(hex_to_dec "$gas_price_hex")
        local gas_price_gwei=$(wei_to_gwei "$gas_price_dec")
        local base_fee_hex=$(get_base_fee "$endpoint")
        local base_fee_dec=$(hex_to_dec "$base_fee_hex")
        local base_fee_gwei=$(wei_to_gwei "$base_fee_dec")
        
        echo "Client version: $version"
        echo "Gas price (eth_gasPrice): $gas_price_hex = $(format_number $gas_price_dec) wei = ${gas_price_gwei} Gwei"
        echo "Base fee (baseFeePerGas): $base_fee_hex = $(format_number $base_fee_dec) wei = ${base_fee_gwei} Gwei"
        echo "Mempool status: $(get_mempool_status "$endpoint")"
    else
        echo -e "${RED}Connection failed${NC}"
    fi
}

# Main program
main() {
    case "${1:-full}" in
        "full")
            analyze_all_clients
            ;;
        "quick")
            quick_check "$2"
            ;;
        "help"|"-h"|"--help")
            echo "Ethereum Client Gas Price Analysis Script"
            echo ""
            echo "Usage:"
            echo "  $0 [command] [parameters]"
            echo ""
            echo "Commands:"
            echo "  full          Complete analysis of all clients (default)"
            echo "  quick <node>  Quick check of specific node"
            echo "  help          Show this help information"
            echo ""
            echo "Available node numbers:"
            for node_num in "${NODE_NUMBERS[@]}"; do
                echo "  $node_num - ${NODE_NAMES[$node_num]}"
            done
            ;;
        *)
            echo "Unknown command: $1"
            echo "Use '$0 help' to view help information"
            exit 1
            ;;
    esac
}

# Execute main program
main "$@"