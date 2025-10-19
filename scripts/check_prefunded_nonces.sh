#!/bin/bash

# Query nonce values of prefunded accounts

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source RPC configuration
if [[ -f "${SCRIPT_DIR}/rpc_config.sh" ]]; then
    source "${SCRIPT_DIR}/rpc_config.sh"
else
    echo "Error: rpc_config.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

# Use first RPC endpoint by default, or allow override via command line argument
RPC_URL="${1:-${RPC_ENDPOINTS[0]}}"

# Test RPC connection
test_connection() {
    local response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        --connect-timeout 5 --max-time 10 "$RPC_URL" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq first."
    echo "Ubuntu/Debian: sudo apt-get install jq"
    echo "MacOS: brew install jq"
    exit 1
fi

# Test connection before proceeding
echo "Testing connection to $RPC_URL..."
if ! test_connection; then
    echo "Error: Cannot connect to RPC endpoint $RPC_URL"
    echo ""
    echo "Available endpoints from rpc_config.sh:"
    for i in "${!RPC_ENDPOINTS[@]}"; do
        echo "  [$i] ${RPC_ENDPOINTS[$i]}"
    done
    echo ""
    echo "Usage: $0 [rpc_url]"
    echo "Example: $0 http://172.16.0.13:8545"
    exit 1
fi
echo "Connection successful!"
echo ""

# Prefunded account addresses array
ACCOUNTS=(
    "0x8943545177806ED17B9F23F0a21ee5948eCaa776"
    "0xE25583099BA105D9ec0A67f5Ae86D90e50036425"
    "0x614561D2d143621E126e87831AEF287678B442b8"
    "0xf93Ee4Cf8c6c40b329b0c0626F28333c132CF241"
    "0x802dCbE1B1A97554B4F50DB5119E37E8e7336417"
    "0xAe95d8DA9244C37CaC0a3e16BA966a8e852Bb6D6"
    "0x2c57d1CFC6d5f8E4182a56b4cf75421472eBAEa4"
    "0x741bFE4802cE1C4b5b00F9Df2F5f179A1C89171A"
    "0xc3913d4D8bAb4914328651C2EAE817C8b78E1f4c"
    "0x65D08a056c17Ae13370565B04cF77D2AfA1cB9FA"
    "0x3e95dFbBaF6B348396E6674C7871546dCC568e56"
    "0x5918b2e647464d4743601a865753e64C8059Dc4F"
    "0x589A698b7b7dA0Bec545177D3963A2741105C7C9"
    "0x4d1CB4eB7969f8806E2CaAc0cbbB71f88C8ec413"
    "0xF5504cE2BcC52614F121aff9b93b2001d92715CA"
    "0xF61E98E7D47aB884C244E39E031978E33162ff4b"
    "0xf1424826861ffbbD25405F5145B5E50d0F1bFc90"
    "0xfDCe42116f541fc8f7b0776e2B30832bD5621C85"
    "0xD9211042f35968820A3407ac3d80C725f8F75c14"
    "0xD8F3183DEF51A987222D845be228e0Bbb932C222"
    "0xafF0CA253b97e54440965855cec0A8a2E2399896"
)

echo "=== Prefunded Account Nonce Query ==="
echo "Using RPC endpoint: $RPC_URL"
echo ""
echo "Account Address                            | Nonce (Decimal) | Nonce (Hex)     | Balance (Wei)"
echo "-------------------------------------------|-----------------|-----------------|------------------"

success_count=0
error_count=0

for account in "${ACCOUNTS[@]}"; do
    # Query nonce value
    nonce_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["'$account'", "latest"],"id":1}' \
        --connect-timeout 5 --max-time 10 $RPC_URL 2>/dev/null)
    nonce_hex=$(echo "$nonce_response" | jq -r '.result' 2>/dev/null)
    
    # Query balance
    balance_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["'$account'", "latest"],"id":1}' \
        --connect-timeout 5 --max-time 10 $RPC_URL 2>/dev/null)
    balance_hex=$(echo "$balance_response" | jq -r '.result' 2>/dev/null)

    # Convert to decimal (use Python to handle large numbers to avoid bash integer overflow)
    if [ "$nonce_hex" != "null" ] && [ "$nonce_hex" != "" ] && [ "$nonce_hex" != "None" ]; then
        nonce_dec=$((16#${nonce_hex#0x}))
        # Use Python to correctly handle large numbers
        balance_dec=$(python3 -c "print(int('$balance_hex', 16))" 2>/dev/null || echo "Calculation Error")
        printf "%-42s | %-15s | %-15s | %s\n" "$account" "$nonce_dec" "$nonce_hex" "$balance_dec"
        ((success_count++))
    else
        printf "%-42s | %-15s | %-15s | %s\n" "$account" "ERROR" "ERROR" "RPC Query Failed"
        ((error_count++))
    fi
done

echo ""
echo "=== Query Summary ==="
echo "Total accounts: ${#ACCOUNTS[@]}"
echo "Successful queries: $success_count"
echo "Failed queries: $error_count"
echo ""
echo "Notes:"
echo "- Nonce = 0: Account has not sent any transactions"
echo "- Nonce > 0: Account has sent corresponding number of transactions"
echo "- Balance is displayed in Wei units (1 ETH = 10^18 Wei)"
echo ""
if [ $error_count -gt 0 ]; then
    echo "⚠ Some queries failed. You can try using a different RPC endpoint:"
    echo "Usage: $0 [rpc_url]"
    echo "Example: $0 http://172.16.0.13:8545"
fi