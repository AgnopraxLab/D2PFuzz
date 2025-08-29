#!/bin/bash

# 查询指定账户地址的所有交易细节
ACCOUNT="0x8943545177806ED17B9F23F0a21ee5948eCaa776"
RPC_URL="http://127.0.0.1:32791"

echo "=== 账户 $ACCOUNT 完整分析 ==="
echo "RPC端点: $RPC_URL"
echo ""

# 1. 基本信息查询
echo "=== 1. 账户基本信息 ==="

# 获取当前区块高度
LATEST_BLOCK_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    $RPC_URL | jq -r '.result')
LATEST_BLOCK=$((16#${LATEST_BLOCK_HEX#0x}))
echo "当前区块高度: $LATEST_BLOCK ($LATEST_BLOCK_HEX)"

# 获取账户当前nonce
NONCE_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["'$ACCOUNT'", "latest"],"id":1}' \
    $RPC_URL | jq -r '.result')
NONCE=$((16#${NONCE_HEX#0x}))
echo "账户nonce: $NONCE (已发送 $NONCE 笔交易)"

# 获取账户余额
BALANCE_HEX=$(curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["'$ACCOUNT'", "latest"],"id":1}' \
    $RPC_URL | jq -r '.result')

# 处理负数余额（bash不能直接处理大数，使用bc）
if [[ $BALANCE_HEX == 0x* ]]; then
    BALANCE_WEI=$(echo "ibase=16; ${BALANCE_HEX#0x}" | bc 2>/dev/null || echo "计算错误")
else
    BALANCE_WEI="无法解析"
fi

echo "账户余额: $BALANCE_HEX ($BALANCE_WEI Wei)"
echo ""

# 2. 创世配置信息
echo "=== 2. 创世配置信息 ==="
echo "在genesis.json中的配置:"
grep -A 3 -B 1 "$ACCOUNT" genesis_data/genesis.json 2>/dev/null || echo "未在genesis.json中找到"
echo ""
echo "在mnemonics.yaml中的配置:"
grep -A 5 -B 2 "$ACCOUNT" genesis_data/mnemonics.yaml 2>/dev/null || echo "未在mnemonics.yaml中找到"
echo ""

# 3. 交易历史搜索
echo "=== 3. 交易历史搜索 ==="

if [ $NONCE -eq 0 ]; then
    echo "该账户尚未发送任何交易（nonce = 0）"
    echo "正在搜索是否有其他账户向该账户发送交易..."
else
    echo "该账户已发送 $NONCE 笔交易，正在搜索交易记录..."
fi
echo ""

# 搜索策略：分段搜索以提高效率
FOUND_TRANSACTIONS=0
SEARCH_SEGMENTS=(
    "1:500"      # 早期区块
    "501:1000"   # 中期区块
    "$((LATEST_BLOCK-500)):$LATEST_BLOCK"  # 最近区块
)

for segment in "${SEARCH_SEGMENTS[@]}"; do
    START_BLOCK=$(echo $segment | cut -d':' -f1)
    END_BLOCK=$(echo $segment | cut -d':' -f2)
    
    echo "搜索区块段: $START_BLOCK 到 $END_BLOCK"
    
    for ((block=$START_BLOCK; block<=END_BLOCK; block++)); do
        block_hex=$(printf "0x%x" $block)
        
        # 获取区块数据
        block_data=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["'$block_hex'", true],"id":1}' \
            $RPC_URL 2>/dev/null)
        
        if [ $? -eq 0 ] && [ ! -z "$block_data" ]; then
            # 检查是否有交易涉及该账户
            account_txs=$(echo "$block_data" | jq -r '.result.transactions[]? | select(.from == "'$ACCOUNT'" or .to == "'$ACCOUNT'")' 2>/dev/null)
            
            if [ ! -z "$account_txs" ]; then
                echo "" 
                echo "📍 在区块 $block 中找到相关交易:"
                echo "$account_txs" | jq -r '
                    "  🔗 交易哈希: " + .hash + 
                    "\n  📤 发送方: " + .from + 
                    "\n  📥 接收方: " + (.to // "[合约创建]") + 
                    "\n  💰 转账金额: " + .value + " Wei" + 
                    "\n  ⛽ Gas限制: " + .gas + 
                    "\n  💸 Gas价格: " + (.gasPrice // "N/A") + 
                    "\n  🔢 Nonce: " + .nonce + 
                    "\n  📊 交易索引: " + (.transactionIndex // "N/A") + 
                    "\n"
                ' 2>/dev/null
                echo "  ----------------------------------------"
                FOUND_TRANSACTIONS=$((FOUND_TRANSACTIONS + 1))
                
                # 获取交易收据以查看执行状态
                tx_hash=$(echo "$account_txs" | jq -r '.hash' | head -1)
                if [ ! -z "$tx_hash" ] && [ "$tx_hash" != "null" ]; then
                    receipt=$(curl -s -X POST -H "Content-Type: application/json" \
                        --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["'$tx_hash'"],"id":1}' \
                        $RPC_URL | jq -r '.result' 2>/dev/null)
                    
                    if [ ! -z "$receipt" ] && [ "$receipt" != "null" ]; then
                        status=$(echo "$receipt" | jq -r '.status // "unknown"')
                        gas_used=$(echo "$receipt" | jq -r '.gasUsed // "unknown"')
                        echo "  ✅ 执行状态: $status (1=成功, 0=失败)"
                        echo "  ⛽ 实际Gas消耗: $gas_used"
                        echo "  ----------------------------------------"
                    fi
                fi
                
                # 限制显示数量
                if [ $FOUND_TRANSACTIONS -ge 10 ]; then
                    echo "  已显示前10笔交易，如需查看更多请调整脚本参数。"
                    break 2
                fi
            fi
        fi
        
        # 显示进度
        if [ $((block % 50)) -eq 0 ]; then
            echo "  已搜索到区块 $block..."
        fi
    done
    
    echo "区块段 $START_BLOCK-$END_BLOCK 搜索完成"
    echo ""
done

echo "=== 4. 搜索结果总结 ==="
echo "总共找到 $FOUND_TRANSACTIONS 笔相关交易"

if [ $FOUND_TRANSACTIONS -eq 0 ]; then
    echo ""
    echo "⚠️  未找到任何交易记录，可能的原因:"
    echo "   1. 交易发生在未搜索的区块范围内"
    echo "   2. 账户只在创世区块中有余额分配，未进行过实际交易"
    echo "   3. 需要搜索更大的区块范围"
    echo ""
    echo "💡 建议:"
    echo "   - 使用区块链浏览器查看完整历史"
    echo "   - 扩大搜索范围或使用专门的索引服务"
    echo "   - 检查是否有内部交易（合约调用）"
else
    echo ""
    echo "✅ 成功找到该账户的交易记录"
    echo "📊 账户活动统计:"
    echo "   - 发送交易数: $NONCE"
    echo "   - 找到的相关交易: $FOUND_TRANSACTIONS"
    echo "   - 当前余额: $BALANCE_HEX"
fi

echo ""
echo "🔍 查询完成 - $(date)"