#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
以太坊交易详情查询脚本
通过交易哈希查询交易的详细信息，包括交易数据、收据、区块信息等
"""

import json
import requests
import sys
from typing import Dict, Optional
from datetime import datetime

# 从output.txt中提取的RPC端点
RPC_ENDPOINTS = [
    "http://127.0.0.1:32769",  # el-1-geth-lighthouse
    "http://127.0.0.1:32788",  # el-2-nethermind-lighthouse
    "http://127.0.0.1:32783",  # el-3-reth-lighthouse
    "http://127.0.0.1:32778",  # el-4-besu-lighthouse
    "http://127.0.0.1:32774",  # el-5-erigon-lighthouse
]

class EthereumRPCClient:
    def __init__(self, endpoint: str, timeout: int = 10):
        self.endpoint = endpoint
        self.timeout = timeout
        self.session = requests.Session()
    
    def call_rpc(self, method: str, params: list = None) -> Optional[Dict]:
        """调用RPC方法"""
        if params is None:
            params = []
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        
        try:
            response = self.session.post(
                self.endpoint,
                json=payload,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"RPC调用失败 ({self.endpoint}): {e}")
            return None
    
    def test_connection(self) -> bool:
        """测试RPC连接"""
        result = self.call_rpc("eth_blockNumber")
        return result is not None and "result" in result
    
    def get_transaction(self, tx_hash: str) -> Optional[Dict]:
        """获取交易信息"""
        result = self.call_rpc("eth_getTransactionByHash", [tx_hash])
        if result and "result" in result:
            return result["result"]
        return None
    
    def get_transaction_receipt(self, tx_hash: str) -> Optional[Dict]:
        """获取交易收据"""
        result = self.call_rpc("eth_getTransactionReceipt", [tx_hash])
        if result and "result" in result:
            return result["result"]
        return None
    
    def get_block(self, block_identifier: str, full_transactions: bool = False) -> Optional[Dict]:
        """获取区块信息"""
        result = self.call_rpc("eth_getBlockByHash" if block_identifier.startswith('0x') and len(block_identifier) == 66 else "eth_getBlockByNumber", [block_identifier, full_transactions])
        if result and "result" in result:
            return result["result"]
        return None
    
    def get_balance(self, address: str, block: str = "latest") -> Optional[str]:
        """获取地址余额"""
        result = self.call_rpc("eth_getBalance", [address, block])
        if result and "result" in result:
            return result["result"]
        return None

def wei_to_ether(wei_hex: str) -> float:
    """将Wei转换为Ether"""
    if not wei_hex or wei_hex == "0x0":
        return 0.0
    wei = int(wei_hex, 16)
    return wei / 10**18

def format_gas_price(gas_price_hex: str) -> str:
    """格式化Gas价格"""
    if not gas_price_hex:
        return "0"
    gas_price_wei = int(gas_price_hex, 16)
    gas_price_gwei = gas_price_wei / 10**9
    return f"{gas_price_gwei:.2f} Gwei ({gas_price_wei} Wei)"

def format_timestamp(timestamp_hex: str) -> str:
    """格式化时间戳"""
    if not timestamp_hex:
        return "未知"
    timestamp = int(timestamp_hex, 16)
    dt = datetime.fromtimestamp(timestamp)
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({timestamp})"

def print_transaction_details(tx_hash: str, rpc_client: EthereumRPCClient):
    """打印交易详细信息"""
    print(f"\n{'='*80}")
    print(f"交易详情查询: {tx_hash}")
    print(f"{'='*80}")
    
    # 获取交易信息
    print("\n🔍 正在查询交易信息...")
    tx_info = rpc_client.get_transaction(tx_hash)
    
    if not tx_info:
        print("❌ 交易不存在或查询失败")
        return
    
    # 基本交易信息
    print("\n📋 基本交易信息:")
    print("-" * 50)
    print(f"交易哈希: {tx_info.get('hash', 'N/A')}")
    print(f"区块哈希: {tx_info.get('blockHash', 'N/A')}")
    print(f"区块号: {int(tx_info['blockNumber'], 16) if tx_info.get('blockNumber') else '待确认'}")
    print(f"交易索引: {int(tx_info['transactionIndex'], 16) if tx_info.get('transactionIndex') else 'N/A'}")
    print(f"发送方: {tx_info.get('from', 'N/A')}")
    print(f"接收方: {tx_info.get('to', 'N/A') or '合约创建'}")
    print(f"转账金额: {wei_to_ether(tx_info.get('value', '0x0')):.6f} ETH")
    print(f"Nonce: {int(tx_info['nonce'], 16) if tx_info.get('nonce') else 'N/A'}")
    
    # Gas信息
    print("\n⛽ Gas信息:")
    print("-" * 50)
    print(f"Gas限制: {int(tx_info['gas'], 16):,} Gas" if tx_info.get('gas') else "N/A")
    print(f"Gas价格: {format_gas_price(tx_info.get('gasPrice', '0x0'))}")
    
    # 如果有maxFeePerGas和maxPriorityFeePerGas (EIP-1559)
    if tx_info.get('maxFeePerGas'):
        print(f"最大费用/Gas: {format_gas_price(tx_info['maxFeePerGas'])}")
    if tx_info.get('maxPriorityFeePerGas'):
        print(f"最大优先费用/Gas: {format_gas_price(tx_info['maxPriorityFeePerGas'])}")
    
    # 输入数据
    input_data = tx_info.get('input', '0x')
    print(f"\n📝 输入数据:")
    print("-" * 50)
    if input_data == '0x' or not input_data:
        print("无输入数据 (简单转账)")
    else:
        print(f"数据长度: {len(input_data)} 字符 ({(len(input_data)-2)//2} 字节)")
        print(f"数据预览: {input_data[:100]}{'...' if len(input_data) > 100 else ''}")
        
        # 尝试解析函数选择器
        if len(input_data) >= 10:
            function_selector = input_data[:10]
            print(f"函数选择器: {function_selector}")
    
    # 获取交易收据
    print("\n🧾 正在查询交易收据...")
    receipt = rpc_client.get_transaction_receipt(tx_hash)
    
    if receipt:
        print("\n📊 交易执行结果:")
        print("-" * 50)
        status = receipt.get('status')
        if status == '0x1':
            print("✅ 交易执行成功")
        elif status == '0x0':
            print("❌ 交易执行失败")
        else:
            print(f"状态: {status}")
        
        print(f"实际Gas使用: {int(receipt['gasUsed'], 16):,} Gas" if receipt.get('gasUsed') else "N/A")
        
        # 计算Gas效率
        if tx_info.get('gas') and receipt.get('gasUsed'):
            gas_limit = int(tx_info['gas'], 16)
            gas_used = int(receipt['gasUsed'], 16)
            efficiency = (gas_used / gas_limit) * 100
            print(f"Gas效率: {efficiency:.2f}% ({gas_used:,}/{gas_limit:,})")
        
        # 计算交易费用
        if tx_info.get('gasPrice') and receipt.get('gasUsed'):
            gas_price = int(tx_info['gasPrice'], 16)
            gas_used = int(receipt['gasUsed'], 16)
            tx_fee_wei = gas_price * gas_used
            tx_fee_eth = tx_fee_wei / 10**18
            print(f"交易费用: {tx_fee_eth:.8f} ETH ({tx_fee_wei:,} Wei)")
        
        # 累积Gas使用
        if receipt.get('cumulativeGasUsed'):
            cumulative_gas = int(receipt['cumulativeGasUsed'], 16)
            print(f"区块累积Gas: {cumulative_gas:,} Gas")
        
        # 日志/事件
        logs = receipt.get('logs', [])
        print(f"\n📋 事件日志: {len(logs)} 个事件")
        if logs:
            print("-" * 50)
            for i, log in enumerate(logs[:5]):  # 只显示前5个事件
                print(f"事件 #{i+1}:")
                print(f"  合约地址: {log.get('address', 'N/A')}")
                print(f"  主题数量: {len(log.get('topics', []))}")
                if log.get('topics'):
                    print(f"  事件签名: {log['topics'][0]}")
                print(f"  数据长度: {len(log.get('data', '0x'))} 字符")
                print()
            
            if len(logs) > 5:
                print(f"... 还有 {len(logs) - 5} 个事件")
    
    # 获取区块信息
    if tx_info.get('blockHash'):
        print("\n🧱 正在查询区块信息...")
        block_info = rpc_client.get_block(tx_info['blockHash'])
        
        if block_info:
            print("\n🏗️ 区块信息:")
            print("-" * 50)
            print(f"区块号: {int(block_info['number'], 16)}")
            print(f"区块哈希: {block_info.get('hash', 'N/A')}")
            print(f"父区块哈希: {block_info.get('parentHash', 'N/A')}")
            print(f"矿工/验证者: {block_info.get('miner', 'N/A')}")
            print(f"时间戳: {format_timestamp(block_info.get('timestamp', '0x0'))}")
            print(f"区块大小: {int(block_info['size'], 16):,} 字节" if block_info.get('size') else "N/A")
            print(f"区块Gas限制: {int(block_info['gasLimit'], 16):,} Gas" if block_info.get('gasLimit') else "N/A")
            print(f"区块Gas使用: {int(block_info['gasUsed'], 16):,} Gas" if block_info.get('gasUsed') else "N/A")
            print(f"交易数量: {len(block_info.get('transactions', []))}")
            
            # 计算区块Gas使用率
            if block_info.get('gasLimit') and block_info.get('gasUsed'):
                gas_limit = int(block_info['gasLimit'], 16)
                gas_used = int(block_info['gasUsed'], 16)
                utilization = (gas_used / gas_limit) * 100
                print(f"区块Gas使用率: {utilization:.2f}%")
    
    # 地址余额信息
    print("\n💰 地址余额信息:")
    print("-" * 50)
    
    from_address = tx_info.get('from')
    to_address = tx_info.get('to')
    
    if from_address:
        balance = rpc_client.get_balance(from_address)
        if balance:
            balance_eth = wei_to_ether(balance)
            print(f"发送方余额: {balance_eth:.6f} ETH ({from_address})")
    
    if to_address and to_address != from_address:
        balance = rpc_client.get_balance(to_address)
        if balance:
            balance_eth = wei_to_ether(balance)
            print(f"接收方余额: {balance_eth:.6f} ETH ({to_address})")

def find_available_rpc() -> Optional[EthereumRPCClient]:
    """查找可用的RPC端点"""
    print("🔍 测试RPC连接...")
    
    for endpoint in RPC_ENDPOINTS:
        client = EthereumRPCClient(endpoint)
        if client.test_connection():
            print(f"✅ 使用RPC端点: {endpoint}")
            return client
        else:
            print(f"❌ {endpoint} 连接失败")
    
    return None

def main():
    """主函数"""
    print("🔍 以太坊交易详情查询工具")
    print("=" * 80)
    
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("\n使用方法:")
        print(f"  {sys.argv[0]} <交易哈希>")
        print("\n示例:")
        print(f"  {sys.argv[0]} 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        return
    
    tx_hash = sys.argv[1].strip()
    
    # 验证交易哈希格式
    if not tx_hash.startswith('0x') or len(tx_hash) != 66:
        print("❌ 错误: 交易哈希格式不正确")
        print("交易哈希应该是66个字符长度，以0x开头的十六进制字符串")
        return
    
    # 查找可用的RPC端点
    rpc_client = find_available_rpc()
    if not rpc_client:
        print("❌ 错误: 没有可用的RPC端点")
        return
    
    # 查询交易详情
    try:
        print_transaction_details(tx_hash, rpc_client)
        print(f"\n{'='*80}")
        print("✅ 查询完成")
    except Exception as e:
        print(f"❌ 查询过程中发生错误: {e}")

if __name__ == "__main__":
    main()