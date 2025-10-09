# Blob 交易验证工具

本目录包含了用于验证 Blob 交易是否成功发送和上链的脚本工具。

## 可用工具

### 1. `query_blob_tx.sh` - Blob 交易查询工具

查询 Blob 交易的详细信息，包括 Blob 数据状态、Gas 使用情况等。

**用法：**
```bash
# 查询单个交易
./scripts/query_blob_tx.sh 0x1234567890abcdef...

# 查询多个交易
./scripts/query_blob_tx.sh 0xhash1 0xhash2 0xhash3

# 从文件读取交易哈希
./scripts/query_blob_tx.sh -f txhashes.txt
```

**输出信息：**
- 交易状态（成功/失败/待确认）
- 区块号
- Gas 使用量
- Blob Gas 使用量和价格
- Blob 数量和版本化哈希
- Beacon 链上的 Blob Sidecar 状态

**示例输出：**
```
✓ 0xabc...def - Blob transaction successful
  Block: 12345 | Gas: 21000 | Blob Gas: 131072 | Blob Price: 1.23 Gwei
  Blob Count: 2
  Blob Versioned Hashes:
    - 0x0123...4567
    - 0x89ab...cdef
  ✓ Found 2 blob sidecar(s) in beacon chain
```

---

### 2. `verify_blob_test.sh` - 自动化测试与验证

运行 Blob 测试并自动验证结果的一站式脚本。

**用法：**
```bash
# 测试单节点 Blob 交易
./scripts/verify_blob_test.sh blob-single

# 测试多节点 Blob 交易
./scripts/verify_blob_test.sh blob-multi

# 使用自定义配置文件
./scripts/verify_blob_test.sh blob-single --config /path/to/config.yaml

# 只运行测试，不验证
./scripts/verify_blob_test.sh blob-single --no-verify
```

**工作流程：**
1. 编译 `manual` 工具
2. 运行指定的 Blob 测试模式
3. 提取交易哈希
4. 自动查询交易状态
5. 生成验证报告

---

### 3. `query_tx.sh` - 通用交易查询工具

现有的通用交易查询工具，也可用于查询 Blob 交易的基本信息。

**用法：**
```bash
# 查询单个交易
./scripts/query_tx.sh 0x1234567890abcdef...

# 从文件读取
./scripts/query_tx.sh -f cmd/manual/txhashes.txt
```

---

## 验证 Blob 功能的完整流程

### 方法 1：使用自动化脚本（推荐）

```bash
# 1. 确保以太坊网络正在运行
./scripts/run_ethereum_network.sh

# 2. 运行 Blob 测试并自动验证
./scripts/verify_blob_test.sh blob-single

# 完成！脚本会自动编译、测试、提取哈希并验证
```

### 方法 2：手动验证

```bash
# 1. 编译并运行测试
cd cmd/manual
go build -o manual
./manual -mode blob-single

# 2. 查询生成的交易
cd ../../scripts
./query_blob_tx.sh -f ../cmd/manual/txhashes.txt

# 或者查询特定的交易哈希
./query_blob_tx.sh 0xYOUR_TRANSACTION_HASH
```

---

## 配置 Beacon 节点（可选）

如果要查询 Blob Sidecar 数据，需要配置 Beacon API 端点：

```bash
# 设置环境变量
export BEACON_ENDPOINT="http://localhost:4000"

# 然后运行查询
./scripts/query_blob_tx.sh 0x...
```

如果未设置，脚本会尝试使用默认的 `http://localhost:4000`。

---

## 常见查询场景

### 场景 1：测试后快速验证

```bash
# 运行测试
cd cmd/manual && ./manual -mode blob-single

# 立即查询结果
cd ../../scripts
./query_blob_tx.sh -f ../cmd/manual/txhashes.txt
```

### 场景 2：检查特定交易的 Blob 数据

```bash
./scripts/query_blob_tx.sh 0xYOUR_TX_HASH
```

### 场景 3：批量验证多节点测试结果

```bash
# 运行多节点测试
./scripts/verify_blob_test.sh blob-multi

# 脚本会自动提取所有节点的交易哈希并验证
```

### 场景 4：仅查看 Blob 数据，不看交易状态

```bash
# 获取区块号
BLOCK_NUM=12345

# 查询 Beacon 链上的 Blob Sidecars
curl "http://localhost:4000/eth/v1/beacon/blob_sidecars/$BLOCK_NUM"
```

---

## 验证检查清单

使用以下清单确认 Blob 功能正常工作：

- [ ] 交易哈希可以成功生成
- [ ] 交易能被节点接收（通过 `query_tx.sh` 查到交易）
- [ ] 交易最终被打包进区块
- [ ] 交易状态为 `0x1`（成功）
- [ ] 交易类型为 `0x3`（Blob 交易）
- [ ] `blobVersionedHashes` 字段存在且非空
- [ ] `blobGasUsed` 字段存在且合理（每个 Blob 为 131072）
- [ ] `blobGasPrice` 字段存在
- [ ] Beacon 链上能查询到对应的 Blob Sidecar（如果 Beacon 节点可用）

---

## 故障排查

### 问题：交易未找到

**可能原因：**
- 交易未成功发送
- RPC 端点连接失败
- 交易哈希错误

**解决方法：**
```bash
# 检查网络状态
./scripts/network_status.sh

# 检查测试输出日志
less /tmp/blob_test_output_*.log
```

### 问题：Blob Sidecar 未找到

**可能原因：**
- Beacon 节点未运行
- Beacon API 端点配置错误
- Blob 数据尚未同步到 Beacon 链

**解决方法：**
```bash
# 检查 Beacon 节点是否运行
curl http://localhost:4000/eth/v1/node/version

# 手动设置正确的端点
export BEACON_ENDPOINT="http://your-beacon-node:4000"
```

### 问题：交易失败（status: 0x0）

**可能原因：**
- Gas 设置不足
- Blob Gas Price 过低
- 账户余额不足
- Blob 数据格式错误

**解决方法：**
```bash
# 查看详细的交易收据
./scripts/trace_tx.sh 0xYOUR_TX_HASH

# 检查账户余额
./scripts/check_prefunded_nonces.sh
```

---

## 进阶：编写自定义验证脚本

你可以基于现有脚本创建自定义验证逻辑：

```bash
#!/bin/bash
# custom_blob_verify.sh

# 引入 RPC 配置
source ./scripts/rpc_config.sh

# 查询交易
TX_HASH="0x..."
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\",\"params\":[\"$TX_HASH\"],\"id\":1}" \
  "${RPC_ENDPOINTS[0]}")

# 提取并验证 Blob 字段
echo "$RESPONSE" | jq -r '.result.blobVersionedHashes'
```

---

## 总结

这些脚本提供了完整的 Blob 交易验证能力：

1. **`query_blob_tx.sh`** - 详细查询 Blob 交易状态
2. **`verify_blob_test.sh`** - 一键测试+验证
3. **`query_tx.sh`** - 通用交易查询

推荐使用 `verify_blob_test.sh` 进行端到端的自动化验证！

