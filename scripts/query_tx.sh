#!/bin/bash

# 简单的交易查询脚本 (Bash版本)
# 使用curl直接调用RPC接口查询交易

# 设置字符编码为 UTF-8
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8

# RPC端点列表（从output.txt提取）
RPC_ENDPOINTS=(
    "http://127.0.0.1:32769"  # el-1-geth-lighthouse
    "http://127.0.0.1:32788"  # el-2-nethermind-lighthouse
    "http://127.0.0.1:32783"  # el-3-reth-lighthouse
    "http://127.0.0.1:32778"  # el-4-besu-lighthouse
    "http://127.0.0.1:32774"  # el-5-erigon-lighthouse
)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试RPC连接
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

# 查询单个交易
query_transaction() {
    local tx_hash=$1
    local endpoint=$2
    
    # 查询交易信息
    local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}✗${NC} $tx_hash - RPC调用失败"
        return 1
    fi
    
    # 检查交易是否存在
    if echo "$tx_response" | grep -q '"result":null'; then
        echo -e "${RED}✗${NC} $tx_hash - 交易不存在"
        return 1
    elif echo "$tx_response" | grep -q '"result":{'; then
        # 提取区块号
        local block_number=$(echo "$tx_response" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
        
        if [[ "$block_number" == "null" || -z "$block_number" ]]; then
            echo -e "${YELLOW}◐${NC} $tx_hash - 交易存在但未确认 (在内存池中)"
        else
            # 查询交易收据获取状态
            local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
                --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
                --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
            
            local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
            local block_num_dec=$((16#${block_number#0x}))
            
            if [[ "$status" == "0x1" ]]; then
                echo -e "${GREEN}✓${NC} $tx_hash - 交易成功 (区块: $block_num_dec)"
            elif [[ "$status" == "0x0" ]]; then
                echo -e "${RED}✗${NC} $tx_hash - 交易失败 (区块: $block_num_dec)"
            else
                echo -e "${GREEN}✓${NC} $tx_hash - 交易已确认 (区块: $block_num_dec)"
            fi
        fi
        return 0
    else
        echo -e "${RED}✗${NC} $tx_hash - 响应格式错误"
        return 1
    fi
}

# 主函数
main() {
    echo -e "${BLUE}以太坊交易查询工具 (Bash版本)${NC}"
    echo "=" | tr ' ' '=' | head -c 50; echo
    
    # 检查参数
    if [[ $# -eq 0 ]]; then
        echo "使用方法:"
        echo "  $0 <交易哈希1> [交易哈希2] [交易哈希3] ..."
        echo "  $0 -f <文件名>  # 从文件读取交易哈希"
        echo ""
        echo "示例:"
        echo "  $0 0x1234567890abcdef..."
        echo "  $0 -f sample_tx_hashes.txt"
        exit 1
    fi
    
    # 测试RPC连接
    echo "测试RPC连接..."
    available_endpoints=()
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            echo -e "${GREEN}✓${NC} $endpoint 连接成功"
            available_endpoints+=("$endpoint")
        else
            echo -e "${RED}✗${NC} $endpoint 连接失败"
        fi
    done
    
    if [[ ${#available_endpoints[@]} -eq 0 ]]; then
        echo -e "${RED}错误: 没有可用的RPC端点${NC}"
        exit 1
    fi
    
    echo -e "\n使用 ${#available_endpoints[@]} 个可用的RPC端点进行查询...\n"
    
    # 准备交易哈希列表
    tx_hashes=()
    if [[ "$1" == "-f" ]]; then
        # 从文件读取
        if [[ ! -f "$2" ]]; then
            echo -e "${RED}错误: 文件 $2 不存在${NC}"
            exit 1
        fi
        
        while IFS= read -r line; do
            # 跳过空行和注释行
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                tx_hashes+=("$line")
            fi
        done < "$2"
        
        echo "从文件 $2 读取了 ${#tx_hashes[@]} 个交易哈希"
    else
        # 从命令行参数读取
        tx_hashes=("$@")
    fi
    
    if [[ ${#tx_hashes[@]} -eq 0 ]]; then
        echo -e "${RED}错误: 没有找到要查询的交易哈希${NC}"
        exit 1
    fi
    
    # 查询统计和分组数组
    local total=${#tx_hashes[@]}
    local success=0
    local failed=0
    local existing_txs=()
    local non_existing_txs=()
    local confirmed_txs=()
    local pending_txs=()
    local failed_txs=()
    
    echo -e "准备查询 $total 个交易哈希...\n"
    
    # 执行查询并收集结果
    for i in "${!tx_hashes[@]}"; do
        local tx_hash="${tx_hashes[$i]}"
        local endpoint_index=$((i % ${#available_endpoints[@]}))
        local endpoint="${available_endpoints[$endpoint_index]}"
        
        # 查询交易信息
        local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -ne 0 ]]; then
            non_existing_txs+=("$tx_hash - RPC调用失败")
            ((failed++))
        elif echo "$tx_response" | grep -q '"result":null'; then
            non_existing_txs+=("$tx_hash - 交易不存在")
            ((failed++))
        elif echo "$tx_response" | grep -q '"result":{'; then
            # 提取区块号
            local block_number=$(echo "$tx_response" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
            
            if [[ "$block_number" == "null" || -z "$block_number" ]]; then
                pending_txs+=("$tx_hash - 交易存在但未确认 (在内存池中)")
                existing_txs+=("$tx_hash")
            else
                # 查询交易收据获取状态
                local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
                    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
                    --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
                
                local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
                local block_num_dec=$((16#${block_number#0x}))
                
                if [[ "$status" == "0x1" ]]; then
                    confirmed_txs+=("$tx_hash - 交易成功 (区块: $block_num_dec)")
                elif [[ "$status" == "0x0" ]]; then
                    failed_txs+=("$tx_hash - 交易失败 (区块: $block_num_dec)")
                else
                    confirmed_txs+=("$tx_hash - 交易已确认 (区块: $block_num_dec)")
                fi
                existing_txs+=("$tx_hash")
            fi
            ((success++))
        else
            non_existing_txs+=("$tx_hash - 响应格式错误")
            ((failed++))
        fi
        
        # 添加小延迟避免过于频繁的请求
        sleep 0.1
    done
    
    # 分组显示查询结果
    echo ""
    echo "=== 查询结果 (按状态分组) ==="
    
    # 显示存在的交易
    if [[ ${#existing_txs[@]} -gt 0 ]]; then
        echo -e "${GREEN}✓ 存在的交易 (${#existing_txs[@]} 个):${NC}"
        echo "----------------------------------------"
        
        # 显示成功的交易
        if [[ ${#confirmed_txs[@]} -gt 0 ]]; then
            echo -e "${GREEN}  已确认交易:${NC}"
            for tx in "${confirmed_txs[@]}"; do
                echo -e "    ${GREEN}✓${NC} $tx"
            done
            echo ""
        fi
        
        # 显示待确认的交易
        if [[ ${#pending_txs[@]} -gt 0 ]]; then
            echo -e "${YELLOW}  待确认交易:${NC}"
            for tx in "${pending_txs[@]}"; do
                echo -e "    ${YELLOW}◐${NC} $tx"
            done
            echo ""
        fi
        
        # 显示失败的交易
        if [[ ${#failed_txs[@]} -gt 0 ]]; then
            echo -e "${RED}  失败的交易:${NC}"
            for tx in "${failed_txs[@]}"; do
                echo -e "    ${RED}✗${NC} $tx"
            done
            echo ""
        fi
    fi
    
    # 显示不存在的交易
    if [[ ${#non_existing_txs[@]} -gt 0 ]]; then
        echo -e "${RED}✗ 不存在的交易 (${#non_existing_txs[@]} 个):${NC}"
        echo "----------------------------------------"
        for tx in "${non_existing_txs[@]}"; do
            echo -e "    ${RED}✗${NC} $tx"
        done
        echo ""
    fi
    
    # 打印统计结果
    echo "=== 查询结果统计 ==="
    echo "总查询数量: $total"
    echo -e "存在交易: ${GREEN}${#existing_txs[@]}${NC}"
    echo -e "  - 已确认: ${GREEN}${#confirmed_txs[@]}${NC}"
    echo -e "  - 待确认: ${YELLOW}${#pending_txs[@]}${NC}"
    echo -e "  - 失败: ${RED}${#failed_txs[@]}${NC}"
    echo -e "不存在交易: ${RED}${#non_existing_txs[@]}${NC}"
    if [[ $total -gt 0 ]]; then
        local success_rate=$((success * 100 / total))
        echo "成功率: ${success_rate}%"
    fi
}

# 执行主函数
main "$@"