#!/bin/bash

# 查询预设账户的nonce值
RPC_URL="http://127.0.0.1:32791"

# 预设账户地址数组
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

echo "=== 预设账户 Nonce 值查询 ==="
echo "账户地址                                      | Nonce (十进制) | Nonce (十六进制) | 余额 (Wei)"
echo "-------------------------------------------|---------------|-----------------|------------------"

for account in "${ACCOUNTS[@]}"; do
    # 查询nonce值
    nonce_hex=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["'$account'", "latest"],"id":1}' \
        $RPC_URL | jq -r '.result')
    
    # 查询余额
    balance_hex=$(curl -s -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["'$account'", "latest"],"id":1}' \
        $RPC_URL | jq -r '.result')
    
    # 转换为十进制（使用Python处理大数字以避免bash整数溢出）
    if [ "$nonce_hex" != "null" ] && [ "$nonce_hex" != "" ]; then
        nonce_dec=$((16#${nonce_hex#0x}))
        # 使用Python正确处理大数字
        balance_dec=$(python3 -c "print(int('$balance_hex', 16))" 2>/dev/null || echo "计算错误")
        printf "%-42s | %-13s | %-15s | %s\n" "$account" "$nonce_dec" "$nonce_hex" "$balance_dec"
    else
        printf "%-42s | %-13s | %-15s | %s\n" "$account" "ERROR" "ERROR" "ERROR"
    fi
done

echo ""
echo "说明:"
echo "- Nonce = 0: 账户未发送任何交易"
echo "- Nonce > 0: 账户已发送相应数量的交易"
echo "- 余额显示为 Wei 单位 (1 ETH = 10^18 Wei)"