#!/bin/bash

# 完整的P2P协议测试流程示例
# 此脚本展示了从生成testdata到运行P2P测试的完整过程

set -e  # 遇到错误时退出

echo "=== 以太坊P2P协议测试完整流程 ==="
echo

# 配置参数
RPC_URL="http://172.16.0.11:8545"
TEST_DATA_DIR="./testdata"
MAX_BLOCKS=50
TARGET_NODE="enode://4d4e17c18f1953adb05645b4c5be7db5e45ca3add0ab5afca59bf1ce25292009f40c922cea037b503ba8c2c520f0a7bf8853c678da463fd7d0a21869d1062df0@172.16.0.11:30303"

# 检查参数
if [ $# -ge 1 ]; then
    RPC_URL="$1"
fi

if [ $# -ge 2 ]; then
    TARGET_NODE="$2"
fi

echo "RPC URL: $RPC_URL"
echo "测试数据目录: $TEST_DATA_DIR"
echo "最大区块数: $MAX_BLOCKS"
echo "目标节点: $TARGET_NODE"
echo

# 步骤1: 检查Go环境
echo "步骤1: 检查Go环境..."
if ! command -v go &> /dev/null; then
    echo "错误: 未找到Go环境，请先安装Go"
    exit 1
fi
echo "Go版本: $(go version)"
echo

# 步骤2: 检查目标节点连接
echo "步骤2: 检查RPC连接..."
if command -v curl &> /dev/null; then
    if curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        "$RPC_URL" > /dev/null; then
        echo "RPC连接正常"
    else
        echo "警告: 无法连接到RPC节点 $RPC_URL"
        echo "请确保节点正在运行并开启了RPC接口"
    fi
else
    echo "跳过RPC连接检查（未找到curl）"
fi
echo

# 步骤3: 清理旧的测试数据
echo "步骤3: 清理旧的测试数据..."
if [ -d "$TEST_DATA_DIR" ]; then
    echo "删除旧的测试数据目录: $TEST_DATA_DIR"
    rm -rf "$TEST_DATA_DIR"
fi
echo

# 步骤4: 生成测试数据
echo "步骤4: 生成测试数据..."
echo "这可能需要几分钟时间，请耐心等待..."
if go run generate_testdata.go "$RPC_URL" "$TEST_DATA_DIR" "$MAX_BLOCKS"; then
    echo "测试数据生成成功!"
else
    echo "错误: 测试数据生成失败"
    exit 1
fi
echo

# 步骤5: 验证生成的文件
echo "步骤5: 验证生成的文件..."
required_files=("genesis.json" "chain.rlp" "headstate.json" "accounts.json")
for file in "${required_files[@]}"; do
    if [ -f "$TEST_DATA_DIR/$file" ]; then
        size=$(stat -f%z "$TEST_DATA_DIR/$file" 2>/dev/null || stat -c%s "$TEST_DATA_DIR/$file" 2>/dev/null || echo "unknown")
        echo "✓ $file (大小: $size 字节)"
    else
        echo "✗ 缺少文件: $file"
        exit 1
    fi
done
echo

# 步骤6: 显示生成的数据摘要
echo "步骤6: 测试数据摘要..."
if command -v jq &> /dev/null; then
    echo "创世块信息:"
    echo "  链ID: $(jq -r '.config.chainId' "$TEST_DATA_DIR/genesis.json")"
    echo "  Gas限制: $(jq -r '.gasLimit' "$TEST_DATA_DIR/genesis.json")"
    echo "  难度: $(jq -r '.difficulty' "$TEST_DATA_DIR/genesis.json")"
    
    echo "状态信息:"
    echo "  状态根: $(jq -r '.root' "$TEST_DATA_DIR/headstate.json")"
    echo "  账户数量: $(jq '.accounts | length' "$TEST_DATA_DIR/headstate.json")"
    
    echo "测试账户:"
    echo "  账户数量: $(jq '. | length' "$TEST_DATA_DIR/accounts.json")"
else
    echo "安装jq以查看详细信息: sudo apt-get install jq 或 brew install jq"
fi
echo

# 步骤7: 运行P2P测试（如果提供了目标节点）
if [ "$TARGET_NODE" != "enode://your_target_node_id@127.0.0.1:30303" ]; then
    echo "步骤7: 运行P2P协议测试..."
    echo "连接到目标节点: $TARGET_NODE"
    
    if go run example_p2p_test.go "$TEST_DATA_DIR" "$TARGET_NODE"; then
        echo "P2P协议测试成功完成!"
    else
        echo "P2P协议测试失败"
        exit 1
    fi
else
    echo "步骤7: 跳过P2P测试（未提供有效的目标节点）"
    echo "要运行P2P测试，请提供目标节点的enode URL作为第二个参数"
    echo "示例: $0 $RPC_URL 'enode://abc123...@127.0.0.1:30303'"
fi
echo

# 完成
echo "=== 测试流程完成 ==="
echo
echo "生成的文件位于: $TEST_DATA_DIR"
echo "您现在可以使用这些文件进行P2P协议测试:"
echo
echo "手动运行P2P测试:"
echo "  go run example_p2p_test.go $TEST_DATA_DIR <target_enode>"
echo
echo "在您的测试代码中使用:"
echo "  chain, err := ethtest.NewChain(\"$TEST_DATA_DIR\")"
echo
echo "注意事项:"
echo "- 确保目标节点与您的私链兼容"
echo "- 检查网络ID和创世块是否匹配"
echo "- 测试账户仅用于测试目的，不要在生产环境使用"