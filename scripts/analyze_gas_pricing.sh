#!/bin/bash

# Ethereum Client Gas Price Analysis Script
# Analyze gas price strategies and transaction requirements for various clients

# Set character encoding to UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Node endpoint configuration
declare -A NODE_ENDPOINTS=(
    [11]="http://172.16.0.11:8545"  # Geth
    [12]="http://172.16.0.12:8545"  # Erigon
    [13]="http://172.16.0.13:8545"  # Besu
    [14]="http://172.16.0.14:8545"  # Nethermind
    [15]="http://172.16.0.15:8545"  # Reth
)

declare -A NODE_NAMES=(
    [11]="Geth"
    [12]="Erigon"
    [13]="Besu"
    [14]="Nethermind"
    [15]="Reth"
)

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
    for node in 11 12 13 14 15; do
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
    
    # 2. Gas price comparison
    echo -e "${CYAN}2. Gas Price Comparison Analysis:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    printf "%-12s %-15s %-20s %-15s\n" "Node" "Client" "Gas Price(hex)" "Gas Price(Gwei)"
    echo "-" | tr ' ' '-' | head -c 70; echo
    
    for node in 11 12 13 14 15; do
        local endpoint="${NODE_ENDPOINTS[$node]}"
        local name="${NODE_NAMES[$node]}"
        
        if test_rpc_connection "$endpoint"; then
            local gas_price_hex=$(get_gas_price "$endpoint")
            local gas_price_dec=$(hex_to_dec "$gas_price_hex")
            local gas_price_gwei=$(wei_to_gwei "$gas_price_dec")
            
            printf "%-12s %-15s %-20s %-15s\n" "Node $node" "$name" "$gas_price_hex" "${gas_price_gwei} Gwei"
        else
            printf "%-12s %-15s %-20s %-15s\n" "Node $node" "$name" "Connection failed" "N/A"
        fi
    done
    echo ""
    
    # 3. Base fee check
    echo -e "${CYAN}3. Network Base Fee (baseFeePerGas):${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    for node in 11 12 13 14 15; do
        local endpoint="${NODE_ENDPOINTS[$node]}"
        local name="${NODE_NAMES[$node]}"
        
        if test_rpc_connection "$endpoint"; then
            local base_fee_hex=$(get_base_fee "$endpoint")
            local base_fee_dec=$(hex_to_dec "$base_fee_hex")
            echo "Node $node ($name): $base_fee_hex = $(format_number $base_fee_dec) wei"
        else
            echo "Node $node ($name): Connection failed"
        fi
    done
    echo ""
    
    # 4. Mempool status
    echo -e "${CYAN}4. Mempool Status Check:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    for node in 11 12 13 14 15; do
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
    
    # 5. Configuration analysis summary
    echo -e "${CYAN}5. Client Configuration Analysis:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "Minimum gas price settings derived from configuration file analysis:"
    echo "• Besu: --min-gas-price=1000000000 (1 Gwei)"
    echo "• Geth: --miner.gasprice=1 (1 wei, only in kurtosis network)"
    echo "• Reth: No explicit minimum gas price configuration found"
    echo "• Erigon: Uses dynamic gas price strategy"
    echo "• Nethermind: Uses similar low gas price strategy as Geth"
    echo ""
    
    # 6. EIP-1559 transaction recommendations
    echo -e "${CYAN}6. EIP-1559 Transaction Parameter Recommendations:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "Based on analysis results, recommended transaction parameters:"
    echo ""
    echo -e "${GREEN}Conservative Strategy (suitable for all clients):${NC}"
    echo "GasTipCap: big.NewInt(1500000000)  // 1.5 Gwei"
    echo "GasFeeCap:  big.NewInt(3000000000)  // 3 Gwei"
    echo "Gas:       21000"
    echo ""
    echo -e "${YELLOW}Aggressive Strategy (suitable for Geth/Nethermind):${NC}"
    echo "GasTipCap: big.NewInt(10000000)     // 0.01 Gwei"
    echo "GasFeeCap:  big.NewInt(50000000)    // 0.05 Gwei"
    echo "Gas:       21000"
    echo ""
    echo -e "${PURPLE}Minimum Requirements for Reth:${NC}"
    echo "GasTipCap: big.NewInt(1000000000)   // 1 Gwei"
    echo "GasFeeCap:  big.NewInt(2000000000)  // 2 Gwei"
    echo "Gas:       21000"
    echo ""
    
    # 7. Troubleshooting recommendations
    echo -e "${CYAN}7. Troubleshooting Recommendations:${NC}"
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
        echo "Node numbers: 11(Geth), 12(Erigon), 13(Besu), 14(Nethermind), 15(Reth)"
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
        
        echo "Client version: $version"
        echo "Gas price: $gas_price_hex = $(format_number $gas_price_dec) wei = ${gas_price_gwei} Gwei"
        echo "Base fee: $base_fee_hex = $(format_number $base_fee_dec) wei"
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
            echo "Node numbers:"
            echo "  11 - Geth"
            echo "  12 - Erigon"
            echo "  13 - Besu"
            echo "  14 - Nethermind"
            echo "  15 - Reth"
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