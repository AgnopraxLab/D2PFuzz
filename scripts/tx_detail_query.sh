#!/bin/bash

# 以太坊交易详情查询脚本 (Bash版本)
# 通过交易哈希查询交易的详细信息

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
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
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

# 查找可用的RPC端点
find_available_rpc() {
    echo -e "${CYAN}🔍 测试RPC连接...${NC}"
    
    for endpoint in "${RPC_ENDPOINTS[@]}"; do
        if test_rpc_connection "$endpoint"; then
            echo -e "${GREEN}✅ 使用RPC端点: $endpoint${NC}"
            echo "$endpoint"
            return 0
        else
            echo -e "${RED}❌ $endpoint 连接失败${NC}"
        fi
    done
    
    return 1
}

# 十六进制转十进制
hex_to_dec() {
    local hex_value=$1
    if [[ -z "$hex_value" || "$hex_value" == "null" ]]; then
        echo "0"
    else
        echo $((16#${hex_value#0x}))
    fi
}

# Wei转Ether
wei_to_ether() {
    local wei_hex=$1
    if [[ -z "$wei_hex" || "$wei_hex" == "0x0" || "$wei_hex" == "null" ]]; then
        echo "0.000000"
    else
        local wei_dec=$(hex_to_dec "$wei_hex")
        # 使用bc进行精确计算
        if command -v bc >/dev/null 2>&1; then
            echo "scale=6; $wei_dec / 1000000000000000000" | bc
        else
            # 如果没有bc，使用awk
            awk "BEGIN {printf \"%.6f\", $wei_dec / 1000000000000000000}"
        fi
    fi
}

# 格式化Gas价格
format_gas_price() {
    local gas_price_hex=$1
    if [[ -z "$gas_price_hex" || "$gas_price_hex" == "null" ]]; then
        echo "0 Gwei (0 Wei)"
    else
        local gas_price_wei=$(hex_to_dec "$gas_price_hex")
        if command -v bc >/dev/null 2>&1; then
            local gas_price_gwei=$(echo "scale=2; $gas_price_wei / 1000000000" | bc)
            echo "$gas_price_gwei Gwei ($gas_price_wei Wei)"
        else
            local gas_price_gwei=$(awk "BEGIN {printf \"%.2f\", $gas_price_wei / 1000000000}")
            echo "$gas_price_gwei Gwei ($gas_price_wei Wei)"
        fi
    fi
}

# 格式化时间戳
format_timestamp() {
    local timestamp_hex=$1
    if [[ -z "$timestamp_hex" || "$timestamp_hex" == "null" ]]; then
        echo "未知"
    else
        local timestamp=$(hex_to_dec "$timestamp_hex")
        local formatted_date=$(date -d "@$timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "格式化失败")
        echo "$formatted_date ($timestamp)"
    fi
}

# 添加千位分隔符
format_number() {
    local number=$1
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --grouping "$number" 2>/dev/null || echo "$number"
    else
        # 简单的千位分隔符实现
        echo "$number" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
    fi
}

# 查询交易详情
query_transaction_details() {
    local tx_hash=$1
    local endpoint=$2
    
    echo -e "\n${'='*80}"
    echo -e "${BLUE}交易详情查询: $tx_hash${NC}"
    echo -e "${'='*80}"
    
    # 获取交易信息
    echo -e "\n${CYAN}🔍 正在查询交易信息...${NC}"
    local tx_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -ne 0 ]] || ! echo "$tx_response" | grep -q '"result"'; then
        echo -e "${RED}❌ 交易查询失败或交易不存在${NC}"
        return 1
    fi
    
    # 检查交易是否存在
    if echo "$tx_response" | grep -q '"result":null'; then
        echo -e "${RED}❌ 交易不存在${NC}"
        return 1
    fi
    
    # 解析交易信息
    local block_hash=$(echo "$tx_response" | grep -o '"blockHash":"[^"]*"' | cut -d'"' -f4)
    local block_number=$(echo "$tx_response" | grep -o '"blockNumber":"[^"]*"' | cut -d'"' -f4)
    local tx_index=$(echo "$tx_response" | grep -o '"transactionIndex":"[^"]*"' | cut -d'"' -f4)
    local from_addr=$(echo "$tx_response" | grep -o '"from":"[^"]*"' | cut -d'"' -f4)
    local to_addr=$(echo "$tx_response" | grep -o '"to":"[^"]*"' | cut -d'"' -f4)
    local value=$(echo "$tx_response" | grep -o '"value":"[^"]*"' | cut -d'"' -f4)
    local nonce=$(echo "$tx_response" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)
    local gas_limit=$(echo "$tx_response" | grep -o '"gas":"[^"]*"' | cut -d'"' -f4)
    local gas_price=$(echo "$tx_response" | grep -o '"gasPrice":"[^"]*"' | cut -d'"' -f4)
    local input_data=$(echo "$tx_response" | grep -o '"input":"[^"]*"' | cut -d'"' -f4)
    
    # 基本交易信息
    echo -e "\n${GREEN}📋 基本交易信息:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    echo "交易哈希: $tx_hash"
    echo "区块哈希: ${block_hash:-N/A}"
    if [[ -n "$block_number" && "$block_number" != "null" ]]; then
        echo "区块号: $(format_number $(hex_to_dec "$block_number"))"
    else
        echo "区块号: 待确认"
    fi
    echo "交易索引: ${tx_index:+$(hex_to_dec "$tx_index")}"
    echo "发送方: ${from_addr:-N/A}"
    echo "接收方: ${to_addr:-合约创建}"
    echo "转账金额: $(wei_to_ether "$value") ETH"
    echo "Nonce: ${nonce:+$(hex_to_dec "$nonce")}"
    
    # Gas信息
    echo -e "\n${YELLOW}⛽ Gas信息:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    if [[ -n "$gas_limit" ]]; then
        echo "Gas限制: $(format_number $(hex_to_dec "$gas_limit")) Gas"
    fi
    if [[ -n "$gas_price" ]]; then
        echo "Gas价格: $(format_gas_price "$gas_price")"
    fi
    
    # 输入数据
    echo -e "\n${PURPLE}📝 输入数据:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    if [[ -z "$input_data" || "$input_data" == "0x" ]]; then
        echo "无输入数据 (简单转账)"
    else
        local data_length=${#input_data}
        local byte_length=$(( (data_length - 2) / 2 ))
        echo "数据长度: $data_length 字符 ($byte_length 字节)"
        if [[ $data_length -gt 100 ]]; then
            echo "数据预览: ${input_data:0:100}..."
        else
            echo "完整数据: $input_data"
        fi
        
        # 函数选择器
        if [[ $data_length -ge 10 ]]; then
            echo "函数选择器: ${input_data:0:10}"
        fi
    fi
    
    # 获取交易收据
    echo -e "\n${CYAN}🧾 正在查询交易收据...${NC}"
    local receipt_response=$(curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$tx_hash\"],\"id\":1}" \
        --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
    
    if [[ $? -eq 0 ]] && echo "$receipt_response" | grep -q '"result"' && ! echo "$receipt_response" | grep -q '"result":null'; then
        # 解析收据信息
        local status=$(echo "$receipt_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        local gas_used=$(echo "$receipt_response" | grep -o '"gasUsed":"[^"]*"' | cut -d'"' -f4)
        local cumulative_gas=$(echo "$receipt_response" | grep -o '"cumulativeGasUsed":"[^"]*"' | cut -d'"' -f4)
        local logs_count=$(echo "$receipt_response" | grep -o '"logs":\[' | wc -l)
        
        echo -e "\n${GREEN}📊 交易执行结果:${NC}"
        echo "-" | tr ' ' '-' | head -c 50; echo
        
        if [[ "$status" == "0x1" ]]; then
            echo -e "${GREEN}✅ 交易执行成功${NC}"
        elif [[ "$status" == "0x0" ]]; then
            echo -e "${RED}❌ 交易执行失败${NC}"
        else
            echo "状态: $status"
        fi
        
        if [[ -n "$gas_used" ]]; then
            echo "实际Gas使用: $(format_number $(hex_to_dec "$gas_used")) Gas"
            
            # 计算Gas效率
            if [[ -n "$gas_limit" ]]; then
                local gas_limit_dec=$(hex_to_dec "$gas_limit")
                local gas_used_dec=$(hex_to_dec "$gas_used")
                if command -v bc >/dev/null 2>&1; then
                    local efficiency=$(echo "scale=2; $gas_used_dec * 100 / $gas_limit_dec" | bc)
                    echo "Gas效率: $efficiency% ($(format_number $gas_used_dec)/$(format_number $gas_limit_dec))"
                fi
            fi
            
            # 计算交易费用
            if [[ -n "$gas_price" ]]; then
                local gas_price_dec=$(hex_to_dec "$gas_price")
                local gas_used_dec=$(hex_to_dec "$gas_used")
                local tx_fee_wei=$((gas_price_dec * gas_used_dec))
                local tx_fee_eth=$(wei_to_ether $(printf "0x%x" $tx_fee_wei))
                echo "交易费用: $tx_fee_eth ETH ($(format_number $tx_fee_wei) Wei)"
            fi
        fi
        
        if [[ -n "$cumulative_gas" ]]; then
            echo "区块累积Gas: $(format_number $(hex_to_dec "$cumulative_gas")) Gas"
        fi
        
        # 事件日志数量
        local actual_logs_count=$(echo "$receipt_response" | grep -o '"address":' | wc -l)
        echo "事件日志: $actual_logs_count 个事件"
    fi
    
    # 获取区块信息
    if [[ -n "$block_hash" && "$block_hash" != "null" ]]; then
        echo -e "\n${CYAN}🧱 正在查询区块信息...${NC}"
        local block_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByHash\",\"params\":[\"$block_hash\",false],\"id\":1}" \
            --connect-timeout 10 --max-time 15 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$block_response" | grep -q '"result"' && ! echo "$block_response" | grep -q '"result":null'; then
            # 解析区块信息
            local block_num=$(echo "$block_response" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
            local parent_hash=$(echo "$block_response" | grep -o '"parentHash":"[^"]*"' | cut -d'"' -f4)
            local miner=$(echo "$block_response" | grep -o '"miner":"[^"]*"' | cut -d'"' -f4)
            local timestamp=$(echo "$block_response" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4)
            local block_size=$(echo "$block_response" | grep -o '"size":"[^"]*"' | cut -d'"' -f4)
            local block_gas_limit=$(echo "$block_response" | grep -o '"gasLimit":"[^"]*"' | cut -d'"' -f4)
            local block_gas_used=$(echo "$block_response" | grep -o '"gasUsed":"[^"]*"' | cut -d'"' -f4)
            local tx_count=$(echo "$block_response" | grep -o '"transactions":\[' | wc -l)
            
            echo -e "\n${BLUE}🏗️ 区块信息:${NC}"
            echo "-" | tr ' ' '-' | head -c 50; echo
            echo "区块号: $(format_number $(hex_to_dec "$block_num"))"
            echo "区块哈希: $block_hash"
            echo "父区块哈希: ${parent_hash:-N/A}"
            echo "矿工/验证者: ${miner:-N/A}"
            echo "时间戳: $(format_timestamp "$timestamp")"
            if [[ -n "$block_size" ]]; then
                echo "区块大小: $(format_number $(hex_to_dec "$block_size")) 字节"
            fi
            if [[ -n "$block_gas_limit" ]]; then
                echo "区块Gas限制: $(format_number $(hex_to_dec "$block_gas_limit")) Gas"
            fi
            if [[ -n "$block_gas_used" ]]; then
                echo "区块Gas使用: $(format_number $(hex_to_dec "$block_gas_used")) Gas"
                
                # 计算区块Gas使用率
                if [[ -n "$block_gas_limit" ]] && command -v bc >/dev/null 2>&1; then
                    local gas_limit_dec=$(hex_to_dec "$block_gas_limit")
                    local gas_used_dec=$(hex_to_dec "$block_gas_used")
                    local utilization=$(echo "scale=2; $gas_used_dec * 100 / $gas_limit_dec" | bc)
                    echo "区块Gas使用率: $utilization%"
                fi
            fi
            
            # 交易数量（需要更准确的计算）
            local actual_tx_count=$(echo "$block_response" | grep -o '"0x[a-fA-F0-9]\{64\}"' | wc -l)
            echo "交易数量: $actual_tx_count"
        fi
    fi
    
    # 地址余额信息
    echo -e "\n${GREEN}💰 地址余额信息:${NC}"
    echo "-" | tr ' ' '-' | head -c 50; echo
    
    if [[ -n "$from_addr" ]]; then
        local from_balance_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$from_addr\",\"latest\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$from_balance_response" | grep -q '"result"'; then
            local from_balance=$(echo "$from_balance_response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
            echo "发送方余额: $(wei_to_ether "$from_balance") ETH ($from_addr)"
        fi
    fi
    
    if [[ -n "$to_addr" && "$to_addr" != "$from_addr" ]]; then
        local to_balance_response=$(curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$to_addr\",\"latest\"],\"id\":1}" \
            --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null)
        
        if [[ $? -eq 0 ]] && echo "$to_balance_response" | grep -q '"result"'; then
            local to_balance=$(echo "$to_balance_response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
            echo "接收方余额: $(wei_to_ether "$to_balance") ETH ($to_addr)"
        fi
    fi
    
    echo -e "\n${'='*80}"
    echo -e "${GREEN}✅ 查询完成${NC}"
}

# 主函数
main() {
    echo -e "${BLUE}🔍 以太坊交易详情查询工具 (Bash版本)${NC}"
    echo "=" | tr ' ' '=' | head -c 80; echo
    
    # 检查参数
    if [[ $# -ne 1 ]]; then
        echo "使用方法:"
        echo "  $0 <交易哈希>"
        echo ""
        echo "示例:"
        echo "  $0 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        exit 1
    fi
    
    local tx_hash=$1
    
    # 验证交易哈希格式
    if [[ ! "$tx_hash" =~ ^0x[a-fA-F0-9]{64}$ ]]; then
        echo -e "${RED}❌ 错误: 交易哈希格式不正确${NC}"
        echo "交易哈希应该是66个字符长度，以0x开头的十六进制字符串"
        exit 1
    fi
    
    # 查找可用的RPC端点
    local endpoint
    endpoint=$(find_available_rpc)
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}❌ 错误: 没有可用的RPC端点${NC}"
        exit 1
    fi
    
    # 查询交易详情
    query_transaction_details "$tx_hash" "$endpoint"
}

# 执行主函数
main "$@"