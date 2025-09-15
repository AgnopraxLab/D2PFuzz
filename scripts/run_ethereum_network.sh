#!/bin/bash

# 脚本：自动化以太坊网络部署和 enode 提取
# 作者：自动生成
# 日期：$(date)

# 设置字符编码为 UTF-8
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8

set -e  # 遇到错误时退出

echo "=== 开始执行以太坊网络部署脚本 ==="

# 1. 更新 Kurtosis
echo "步骤 1: 更新 Kurtosis..."
sudo apt update
sudo apt install -y kurtosis-cli
echo "Kurtosis 更新完成"

# 2. 拉取当前仓库最新版本
echo "步骤 2: 拉取最新代码..."
git pull origin main
echo "代码更新完成"

# 3. 启动 Kurtosis 引擎
echo "步骤 3: 启动 Kurtosis 引擎..."
kurtosis engine start

# 4. 清理旧的 enclave（如果存在）
echo "步骤 4: 清理旧的 enclave..."
kurtosis enclave rm -f my-testnet 2>/dev/null || echo "没有找到旧的 enclave，继续执行"

# 5. 运行以太坊网络并输出到 output.txt
echo "步骤 5: 运行以太坊网络..."

# 创建 output.txt 文件并写入初始信息
{
    echo "开始时间: $(date)"
    echo "执行命令: kurtosis run --enclave my-testnet github.com/ethpandaops/ethereum-package --args-file config.yaml"
    echo ""
} > output.txt

# 运行 kurtosis 命令并将输出追加到 output.txt
kurtosis run --enclave my-testnet github.com/ethpandaops/ethereum-package --args-file config.yaml >> output.txt 2>&1

echo "" >> output.txt
echo "结束时间: $(date)" >> output.txt

echo "以太坊网络部署完成，输出已保存到 output.txt"

# 6. 从 output.txt 中提取 enode 信息
echo "步骤 6: 提取 enode 信息..."

# 清空 enodes.txt 文件
> enodes.txt

# 使用 grep 和 sed 提取 enode 信息
if grep -o 'enode://[^"]*' output.txt > /dev/null 2>&1; then
    echo "找到 enode 信息，正在提取..."
    
    # 提取所有 enode 并格式化
    grep -o 'enode://[^@]*@[^:]*:[0-9]*' output.txt | sort | uniq | while read -r enode; do
        echo " - \"$enode\"" >> enodes.txt
    done
    
    echo "enode 信息已保存到 enodes.txt"
    echo "找到的 enode 数量: $(wc -l < enodes.txt)"
else
    echo "警告: 在 output.txt 中未找到 enode 信息"
    echo "请检查网络是否成功启动"
fi

echo "=== 脚本执行完成 ==="
echo "输出文件:"
echo "  - output.txt: 完整的执行日志"
echo "  - enodes.txt: 提取的 enode 信息"

# 显示 enodes.txt 的内容（如果存在）
if [ -f enodes.txt ] && [ -s enodes.txt ]; then
    echo ""
    echo "提取的 enode 信息:"
    cat enodes.txt
fi