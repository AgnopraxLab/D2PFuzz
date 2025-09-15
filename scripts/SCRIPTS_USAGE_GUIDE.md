# D2PFuzz Scripts 使用指南

本目录包含了 D2PFuzz 项目中用于以太坊网络部署、交易查询和账户管理的各种脚本工具。

## 📁 脚本概览

### 🚀 网络部署脚本

#### `run_ethereum_network.sh`
**功能**: 自动化部署以太坊测试网络
- 更新 Kurtosis 工具
- 拉取最新代码
- 启动 Kurtosis 引擎
- 清理旧的 enclave
- 部署多客户端以太坊网络（Geth、Nethermind、Reth、Besu、Erigon）

**使用方法**:
```bash
chmod +x run_ethereum_network.sh
./run_ethereum_network.sh
```

**输出**: 部署日志保存在 `output.txt` 文件中

---

### 🔍 交易查询脚本

#### `batch_tx_query.py` (Python版本 - 批量查询)
**功能**: 高效批量查询多个交易哈希的状态
- 支持多线程并发查询
- 自动测试多个 RPC 端点
- 结果分组显示（成功/失败/错误）
- 支持 JSON 格式结果保存

**依赖**: `pip install requests`

**使用方法**:
```bash
# 查询单个交易
python3 batch_tx_query.py 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# 从文件批量查询
python3 batch_tx_query.py tx_hashes.txt

# 查询预设示例交易
python3 batch_tx_query.py
```

#### `query_tx.sh` (Bash版本 - 批量查询)
**功能**: 轻量级批量交易查询工具
- 无需额外依赖
- 彩色输出显示
- 结果分组显示

**使用方法**:
```bash
chmod +x query_tx.sh

# 查询单个交易
./query_tx.sh 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# 从文件批量查询
./query_tx.sh tx_hashes.txt

# 查询预设示例交易
./query_tx.sh
```

#### `tx_detail_query.py` (Python版本 - 详细查询)
**功能**: 查询单个交易的完整详细信息
- 交易基本信息（哈希、nonce、gas等）
- 交易收据信息
- 区块信息
- 相关地址余额
- 格式化显示时间戳和金额

**依赖**: `pip install requests`

**使用方法**:
```bash
python3 tx_detail_query.py 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

#### `tx_detail_query.sh` (Bash版本 - 详细查询)
**功能**: 轻量级单交易详细查询工具
- 无需额外依赖
- 彩色格式化输出
- 显示完整交易和收据信息

**使用方法**:
```bash
chmod +x tx_detail_query.sh
./tx_detail_query.sh 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

---

### 👤 账户管理脚本

#### `check_prefunded_nonces.sh`
**功能**: 查询预设账户的 nonce 值和余额
- 查询 21 个预设账户的状态
- 显示 nonce 值（十进制和十六进制）
- 显示账户余额
- 表格化输出

**使用方法**:
```bash
chmod +x check_prefunded_nonces.sh
./check_prefunded_nonces.sh
```

**输出示例**:
```
账户地址                                      | Nonce (十进制) | Nonce (十六进制) | 余额 (Wei)
-------------------------------------------|---------------|-----------------|------------------
0x8943545177806ED17B9F23F0a21ee5948eCaa776 |             5 |            0x5  | 1000000000000000000
```

#### `query_account_transactions.sh`
**功能**: 查询指定账户地址的完整分析信息
- 账户基本信息（nonce、余额、区块高度）
- 创世配置信息
- 交易历史分析
- 支持自定义账户地址和 RPC 端点

**使用方法**:
```bash
chmod +x query_account_transactions.sh

# 使用默认账户
./query_account_transactions.sh

# 修改脚本中的 ACCOUNT 和 RPC_URL 变量来查询其他账户
```

---

## 🌐 RPC 端点配置

所有查询脚本都支持以下 RPC 端点（根据网络部署情况自动选择可用端点）：

- `http://127.0.0.1:32769` - Geth 节点
- `http://127.0.0.1:32788` - Nethermind 节点  
- `http://127.0.0.1:32783` - Reth 节点
- `http://127.0.0.1:32778` - Besu 节点
- `http://127.0.0.1:32774` - Erigon 节点

## 📋 支持文件

### `sample_tx_hashes.txt`
包含示例交易哈希，用于测试批量查询功能

### `tx_query_results.json`
批量查询结果的 JSON 格式保存文件

### `TX_QUERY_README.md`
详细的交易查询工具说明文档

## 🔧 使用建议

1. **首次使用**: 先运行 `run_ethereum_network.sh` 部署测试网络
2. **权限设置**: 给所有 `.sh` 脚本添加执行权限 `chmod +x *.sh`
3. **Python 依赖**: 安装必要的 Python 包 `pip install requests`
4. **网络检查**: 确保 RPC 端点可访问，脚本会自动测试连接
5. **批量查询**: 对于大量交易查询，推荐使用 Python 版本（支持并发）
6. **详细分析**: 需要深入分析单个交易时，使用详细查询脚本

## 🚨 注意事项

- 确保以太坊测试网络正在运行
- 检查防火墙设置，确保 RPC 端口可访问
- 大量并发查询时注意 RPC 端点的速率限制
- 交易哈希必须是有效的 64 字符十六进制字符串（带或不带 0x 前缀）

## 📞 故障排除

1. **连接失败**: 检查网络状态和 RPC 端点是否正确
2. **权限错误**: 确保脚本有执行权限
3. **Python 错误**: 检查 Python 版本（需要 3.6+）和依赖包
4. **查询超时**: 调整脚本中的超时设置或检查网络延迟

---

*最后更新: $(date '+%Y-%m-%d %H:%M:%S')*
*项目: D2PFuzz - 以太坊协议模糊测试工具*