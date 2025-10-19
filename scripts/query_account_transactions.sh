#!/bin/bash

# Query all transaction details for specified account address

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source RPC configuration
if [[ -f "${SCRIPT_DIR}/rpc_config.sh" ]]; then
    source "${SCRIPT_DIR}/rpc_config.sh"
else
    echo "Error: rpc_config.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

# Default account and RPC URL (can be overridden by command line arguments)
ACCOUNT="${1:-0x4d1CB4eB7969f8806E2CaAc0cbbB71f88C8ec413}"
RPC_URL="${2:-${RPC_ENDPOINTS[0]}}"

echo "=== Complete Analysis for Account $ACCOUNT ==="
echo "RPC Endpoint: $RPC_URL"
echo ""
echo "Usage: $0 [account_address] [rpc_url]"
echo "Using default account if not specified: 0x4d1CB4eB7969f8806E2CaAc0cbbB71f88C8ec413"
echo "Using default RPC from rpc_config.sh if not specified: ${RPC_ENDPOINTS[0]}"
echo ""

# 1. Basic information query
echo "=== 1. Account Basic Information ==="

# Get current block height
LATEST_BLOCK_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    $RPC_URL | jq -r '.result')
LATEST_BLOCK=$((16#${LATEST_BLOCK_HEX#0x}))
echo "Current block height: $LATEST_BLOCK ($LATEST_BLOCK_HEX)"

# Get account current nonce
NONCE_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["'$ACCOUNT'", "latest"],"id":1}' \
    $RPC_URL | jq -r '.result')
NONCE=$((16#${NONCE_HEX#0x}))
echo "Account nonce: $NONCE (sent $NONCE transactions)"

# Get account balance
BALANCE_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["'$ACCOUNT'", "latest"],"id":1}' \
    $RPC_URL | jq -r '.result')

# Handle negative balance (bash cannot directly handle large numbers, use bc)
if [[ $BALANCE_HEX == 0x* ]]; then
    BALANCE_WEI=$(echo "ibase=16; ${BALANCE_HEX#0x}" | bc 2>/dev/null || echo "Calculation error")
else
    BALANCE_WEI="Unable to parse"
fi

echo "Account balance: $BALANCE_HEX ($BALANCE_WEI Wei)"
echo ""

# 2. Genesis configuration information
echo "=== 2. Genesis Configuration Information ==="
echo "Configuration in genesis.json:"
grep -A 3 -B 1 "$ACCOUNT" genesis_data/genesis.json 2>/dev/null || echo "Not found in genesis.json"
echo ""
echo "Configuration in mnemonics.yaml:"
grep -A 5 -B 2 "$ACCOUNT" genesis_data/mnemonics.yaml 2>/dev/null || echo "Not found in mnemonics.yaml"
echo ""

# 3. Transaction history search
echo "=== 3. Transaction History Search ==="

if [ $NONCE -eq 0 ]; then
    echo "This account has not sent any transactions yet (nonce = 0)"
    echo "Searching for transactions from other accounts to this account..."
else
    echo "This account has sent $NONCE transactions, searching transaction records..."
fi
echo ""

# Search strategy: more comprehensive segmented search
FOUND_TRANSACTIONS=0

# If nonce > 0, there are sent transactions, need more comprehensive search
if [ $NONCE -gt 0 ]; then
    # Dynamically generate search segments, avoid invalid ranges
    SEARCH_SEGMENTS=()
    
    # Basic search segments
    base_segments=("1:200" "201:400" "401:600" "601:800" "801:1000" "1001:1200" "1201:1400")
    
    for segment in "${base_segments[@]}"; do
        START_SEG=$(echo $segment | cut -d':' -f1)
        END_SEG=$(echo $segment | cut -d':' -f2)
        
        # Only add valid search segments
        if [ $START_SEG -le $LATEST_BLOCK ]; then
            if [ $END_SEG -gt $LATEST_BLOCK ]; then
                # If end block exceeds latest block, adjust to latest block
                SEARCH_SEGMENTS+=("$START_SEG:$LATEST_BLOCK")
            else
                SEARCH_SEGMENTS+=("$segment")
            fi
        fi
    done
    
    # If latest block exceeds 1400, add remaining range
    if [ $LATEST_BLOCK -gt 1400 ]; then
        SEARCH_SEGMENTS+=("1401:$LATEST_BLOCK")
    fi
else
    # If nonce=0, only search blocks that might have received transactions
    SEARCH_SEGMENTS=(
        "1:500"      # Early blocks
        "501:1000"   # Middle blocks
        "$((LATEST_BLOCK-500)):$LATEST_BLOCK"  # Recent blocks
    )
fi

# Reverse the search order to start from the latest blocks
REVERSED_SEGMENTS=()
for ((i=${#SEARCH_SEGMENTS[@]}-1; i>=0; i--)); do
    REVERSED_SEGMENTS+=("${SEARCH_SEGMENTS[$i]}")
done

for segment in "${REVERSED_SEGMENTS[@]}"; do
    START_BLOCK=$(echo $segment | cut -d':' -f1)
    END_BLOCK=$(echo $segment | cut -d':' -f2)
    
    echo "Searching block segment: $END_BLOCK to $START_BLOCK (newest first)"
    
    # Search from newest to oldest within each segment
    for ((block=$END_BLOCK; block>=START_BLOCK; block--)); do
        block_hex=$(printf "0x%x" $block)
        
        # Get block data
        block_data=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'$block_hex'", true],"id":1}' \
            $RPC_URL 2>/dev/null)
        
        if [ $? -eq 0 ] && [ ! -z "$block_data" ]; then
            # Check if block data is valid
            result_check=$(echo "$block_data" | jq -r '.result' 2>/dev/null)
            if [ "$result_check" != "null" ] && [ ! -z "$result_check" ]; then
                # Check if there are transactions involving this account - use safer method
                has_transactions=$(echo "$block_data" | jq -r '.result.transactions | length' 2>/dev/null)
                
                if [ "$has_transactions" != "null" ] && [ "$has_transactions" -gt 0 ]; then
                    # Check each transaction individually
                    for ((tx_idx=0; tx_idx<$has_transactions; tx_idx++)); do
                        tx_from=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].from" 2>/dev/null)
                        tx_to=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].to" 2>/dev/null)
                        
                        # Convert to lowercase for comparison
                        tx_from_lower=$(echo "$tx_from" | tr '[:upper:]' '[:lower:]')
                        tx_to_lower=$(echo "$tx_to" | tr '[:upper:]' '[:lower:]')
                        account_lower=$(echo "$ACCOUNT" | tr '[:upper:]' '[:lower:]')
                        
                        if [ "$tx_from_lower" = "$account_lower" ] || [ "$tx_to_lower" = "$account_lower" ]; then
                            echo "" 
                            echo "📍 Found related transaction in block $block:"
                            
                            # Get complete transaction information
                            tx_hash=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].hash" 2>/dev/null)
                            tx_value=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].value" 2>/dev/null)
                            tx_gas=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].gas" 2>/dev/null)
                            tx_gasPrice=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].gasPrice" 2>/dev/null)
                            tx_nonce=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].nonce" 2>/dev/null)
                            tx_index=$(echo "$block_data" | jq -r ".result.transactions[$tx_idx].transactionIndex" 2>/dev/null)
                            
                            echo "  🔗 Transaction Hash: $tx_hash"
                            echo "  📤 From: $tx_from"
                            echo "  📥 To: ${tx_to:-[Contract Creation]}"
                            echo "  💰 Transfer Amount: $tx_value Wei"
                            echo "  ⛽ Gas Limit: $tx_gas"
                            echo "  💸 Gas Price: ${tx_gasPrice:-N/A}"
                            echo "  🔢 Nonce: $tx_nonce"
                            echo "  📊 Transaction Index: ${tx_index:-N/A}"
                            echo "  ----------------------------------------"
                            FOUND_TRANSACTIONS=$((FOUND_TRANSACTIONS + 1))
                            
                            # Get transaction receipt to check execution status
                            if [ ! -z "$tx_hash" ] && [ "$tx_hash" != "null" ]; then
                                receipt=$(curl -s -X POST -H "Content-Type: application/json" \
                                    --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'$tx_hash'"],"id":1}' \
                                    $RPC_URL | jq -r '.result' 2>/dev/null)
                                
                                if [ ! -z "$receipt" ] && [ "$receipt" != "null" ]; then
                                    status=$(echo "$receipt" | jq -r '.status // "unknown"')
                                    gas_used=$(echo "$receipt" | jq -r '.gasUsed // "unknown"')
                                    echo "  ✅ Execution Status: $status (1=success, 0=failed)"
                                    echo "  ⛽ Actual Gas Used: $gas_used"
                                    echo "  ----------------------------------------"
                                fi
                            fi
                            
                            # Limit display count
                            if [ $FOUND_TRANSACTIONS -ge 10 ]; then
                                echo "  Showing first 10 transactions, adjust script parameters to see more."
                                break 3
                            fi
                        fi
                    done
                fi
            fi
        fi
        
        # Show progress
        if [ $((block % 50)) -eq 0 ]; then
            echo "  Searched up to block $block..."
        fi
    done
    
    echo "Block segment $END_BLOCK-$START_BLOCK search completed"
    echo ""
done

echo "=== 4. Search Results Summary ==="
echo "Total found $FOUND_TRANSACTIONS related transactions"

if [ $FOUND_TRANSACTIONS -eq 0 ]; then
    echo ""
    echo "⚠️  No transaction records found, possible reasons:"
    echo "   1. Transactions occurred in unsearched block ranges"
    echo "   2. Account only has balance allocation in genesis block, no actual transactions"
    echo "   3. Need to search larger block ranges"
    echo ""
    echo "💡 Suggestions:"
    echo "   - Use blockchain explorer to view complete history"
    echo "   - Expand search range or use dedicated indexing services"
    echo "   - Check for internal transactions (contract calls)"
else
    echo ""
    echo "✅ Successfully found transaction records for this account"
    echo "📊 Account activity statistics:"
    echo "   - Sent transactions: $NONCE"
    echo "   - Found related transactions: $FOUND_TRANSACTIONS"
    echo "   - Current balance: $BALANCE_HEX"
fi

echo ""
echo "🔍 Query completed - $(date)"