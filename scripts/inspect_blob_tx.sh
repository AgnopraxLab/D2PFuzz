#!/bin/bash

# Inspect Blob Transaction - 查看 Blob 交易的详细信息
# 这个脚本会显示交易哈希和 Blob Versioned Hashes 的关系

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Load RPC configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/rpc_config.sh"

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <transaction_hash>"
    echo ""
    echo "Example:"
    echo "  $0 0xa241e68c46c69547e0cd91bc9f47449d3920a16e495723618583a4aea71a6109"
    exit 1
fi

TX_HASH="$1"
ENDPOINT="${RPC_ENDPOINTS[0]}"

echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      Blob Transaction Detailed Inspector              ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Query transaction
echo -e "${BLUE}🔍 Querying transaction...${NC}"
TX_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
    "$ENDPOINT")

if ! echo "$TX_RESPONSE" | grep -q '"result":{'; then
    echo -e "${RED}❌ Transaction not found or RPC error${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Transaction found${NC}"
echo ""

# Extract transaction details
TX_TYPE=$(echo "$TX_RESPONSE" | jq -r '.result.type')
BLOCK_NUMBER=$(echo "$TX_RESPONSE" | jq -r '.result.blockNumber')
FROM=$(echo "$TX_RESPONSE" | jq -r '.result.from')
TO=$(echo "$TX_RESPONSE" | jq -r '.result.to')
NONCE=$(echo "$TX_RESPONSE" | jq -r '.result.nonce')
GAS=$(echo "$TX_RESPONSE" | jq -r '.result.gas')
VALUE=$(echo "$TX_RESPONSE" | jq -r '.result.value')

echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Transaction Hash (交易哈希)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}$TX_HASH${NC}"
echo ""
echo "📋 This is the unique identifier for the entire transaction"
echo "   用途：查询交易、验证交易、追踪交易状态"
echo ""

# Transaction details
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Transaction Details (交易详情)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "Type:        ${YELLOW}$TX_TYPE${NC}"

if [[ "$TX_TYPE" == "0x3" ]]; then
    echo -e "             ${GREEN}✅ Type-3 (Blob Transaction)${NC}"
else
    echo -e "             ${RED}⚠️  Not a blob transaction${NC}"
fi

if [[ "$BLOCK_NUMBER" != "null" ]]; then
    BLOCK_NUM_DEC=$((16#${BLOCK_NUMBER#0x}))
    echo -e "Block:       ${GREEN}$BLOCK_NUM_DEC${NC} ($BLOCK_NUMBER)"
else
    echo -e "Block:       ${YELLOW}Pending${NC}"
fi

echo "From:        $FROM"
echo "To:          $TO"

NONCE_DEC=$((16#${NONCE#0x}))
echo "Nonce:       $NONCE_DEC ($NONCE)"

GAS_DEC=$((16#${GAS#0x}))
echo "Gas:         $GAS_DEC"

VALUE_DEC=$((16#${VALUE#0x}))
echo "Value:       $VALUE_DEC wei"
echo ""

# Extract blob versioned hashes
if [[ "$TX_TYPE" == "0x3" ]]; then
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Blob Versioned Hashes (Blob 版本化哈希)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    BLOB_HASHES=$(echo "$TX_RESPONSE" | jq -r '.result.blobVersionedHashes[]?' 2>/dev/null)
    
    if [[ -n "$BLOB_HASHES" ]]; then
        BLOB_COUNT=0
        while IFS= read -r blob_hash; do
            if [[ -n "$blob_hash" && "$blob_hash" != "null" ]]; then
                echo -e "${MAGENTA}Blob $BLOB_COUNT:${NC}"
                echo -e "  Hash: ${GREEN}$blob_hash${NC}"
                echo ""
                echo "  📋 This hash represents a single blob (128KB data)"
                echo "     • Generated from KZG Commitment"
                echo "     • First byte is always 0x01 (version)"
                echo "     • Used to verify blob data integrity"
                echo "     • Blob data stored on Beacon Chain"
                echo ""
                ((BLOB_COUNT++))
            fi
        done <<< "$BLOB_HASHES"
        
        echo -e "${BLUE}Total Blobs: $BLOB_COUNT${NC}"
        
        # Calculate blob gas
        BLOB_GAS=$((BLOB_COUNT * 131072))
        echo -e "${BLUE}Blob Gas: $BLOB_GAS${NC} (每个 Blob: 131072)"
    else
        echo -e "${YELLOW}⚠️  No blob hashes found${NC}"
    fi
    echo ""
    
    # Query receipt for blob gas details
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Blob Gas Information (Blob Gas 信息)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    
    RECEIPT_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
        "$ENDPOINT")
    
    BLOB_GAS_USED=$(echo "$RECEIPT_RESPONSE" | jq -r '.result.blobGasUsed')
    BLOB_GAS_PRICE=$(echo "$RECEIPT_RESPONSE" | jq -r '.result.blobGasPrice')
    
    if [[ -n "$BLOB_GAS_USED" && "$BLOB_GAS_USED" != "null" ]]; then
        BLOB_GAS_USED_DEC=$((16#${BLOB_GAS_USED#0x}))
        echo -e "Blob Gas Used:  ${GREEN}$BLOB_GAS_USED_DEC${NC}"
    fi
    
    if [[ -n "$BLOB_GAS_PRICE" && "$BLOB_GAS_PRICE" != "null" ]]; then
        BLOB_GAS_PRICE_DEC=$((16#${BLOB_GAS_PRICE#0x}))
        BLOB_PRICE_GWEI=$(echo "scale=2; $BLOB_GAS_PRICE_DEC / 1000000000" | bc -l 2>/dev/null || echo "N/A")
        echo -e "Blob Gas Price: ${GREEN}$BLOB_PRICE_GWEI Gwei${NC} ($BLOB_GAS_PRICE_DEC wei)"
        
        if [[ -n "$BLOB_GAS_USED" && "$BLOB_GAS_USED" != "null" ]]; then
            TOTAL_BLOB_FEE=$((BLOB_GAS_USED_DEC * BLOB_GAS_PRICE_DEC))
            TOTAL_FEE_ETH=$(echo "scale=18; $TOTAL_BLOB_FEE / 1000000000000000000" | bc -l 2>/dev/null || echo "N/A")
            echo -e "Total Blob Fee: ${GREEN}$TOTAL_FEE_ETH ETH${NC} ($TOTAL_BLOB_FEE wei)"
        fi
    fi
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Summary (总结)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "🎁 交易哈希 (Transaction Hash):"
echo "   • 整个交易的唯一标识符"
echo "   • 包含所有交易字段（from, to, nonce, gas, value）"
echo "   • 包含 Blob Versioned Hashes 列表"
echo ""
echo "📦 Blob Versioned Hash:"
echo "   • 每个 Blob 数据的唯一标识符"
echo "   • 由 KZG Commitment 的 SHA256 哈希生成"
echo "   • 存储在交易中（不是完整的 Blob 数据）"
echo "   • 用于验证 Blob 数据的完整性"
echo ""
echo "📄 Blob 数据本身:"
echo "   • 实际的 128KB 数据"
echo "   • 存储在 Beacon Chain（共识层）"
echo "   • 不存储在执行层，节省空间"
echo "   • 约 30-90 天后会被清理"
echo ""

