#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量查询以太坊交易脚本
通过RPC接口批量查询交易哈希是否在链上
"""

import json
import requests
import sys
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    
    def call_rpc(self, method: str, params: List = None) -> Optional[Dict]:
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
    
    def test_connection(self) -> bool:
        """测试RPC连接"""
        result = self.call_rpc("eth_blockNumber")
        return result is not None and "result" in result

def query_single_transaction(tx_hash: str, rpc_client: EthereumRPCClient) -> Dict:
    """查询单个交易"""
    result = {
        "hash": tx_hash,
        "exists": False,
        "confirmed": False,
        "block_number": None,
        "status": None,
        "endpoint": rpc_client.endpoint,
        "error": None
    }
    
    try:
        # 获取交易信息
        tx_info = rpc_client.get_transaction(tx_hash)
        if tx_info:
            result["exists"] = True
            result["block_number"] = tx_info.get("blockNumber")
            
            # 如果交易已被打包到区块中，获取交易收据
            if tx_info.get("blockNumber"):
                receipt = rpc_client.get_transaction_receipt(tx_hash)
                if receipt:
                    result["confirmed"] = True
                    result["status"] = receipt.get("status")
    
    except Exception as e:
        result["error"] = str(e)
    
    return result

def batch_query_transactions(tx_hashes: List[str], max_workers: int = 5) -> List[Dict]:
    """批量查询交易"""
    # 测试RPC连接并选择可用的端点
    available_clients = []
    print("测试RPC连接...")
    
    for endpoint in RPC_ENDPOINTS:
        client = EthereumRPCClient(endpoint)
        if client.test_connection():
            print(f"✓ {endpoint} 连接成功")
            available_clients.append(client)
        else:
            print(f"✗ {endpoint} 连接失败")
    
    if not available_clients:
        print("错误: 没有可用的RPC端点")
        return []
    
    print(f"\n使用 {len(available_clients)} 个可用的RPC端点进行查询...")
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 为每个交易哈希分配一个RPC客户端
        future_to_hash = {}
        for i, tx_hash in enumerate(tx_hashes):
            client = available_clients[i % len(available_clients)]
            future = executor.submit(query_single_transaction, tx_hash, client)
            future_to_hash[future] = tx_hash
        
        # 收集结果
        for future in as_completed(future_to_hash):
            tx_hash = future_to_hash[future]
            try:
                result = future.result()
                results.append(result)
                
                # 打印进度
                status = "✓" if result["exists"] else "✗"
                confirmed = "已确认" if result["confirmed"] else "未确认" if result["exists"] else "不存在"
                print(f"{status} {tx_hash[:10]}... - {confirmed}")
                
            except Exception as e:
                print(f"✗ {tx_hash[:10]}... - 查询失败: {e}")
                results.append({
                    "hash": tx_hash,
                    "exists": False,
                    "confirmed": False,
                    "error": str(e)
                })
    
    return results

def print_grouped_results(results: List[Dict]):
    """按状态分组显示查询结果"""
    # 分组结果
    existing_txs = [r for r in results if r["exists"]]
    non_existing_txs = [r for r in results if not r["exists"]]
    confirmed_txs = [r for r in existing_txs if r["confirmed"] and r.get("status") == "0x1"]
    failed_txs = [r for r in existing_txs if r["confirmed"] and r.get("status") == "0x0"]
    pending_txs = [r for r in existing_txs if not r["confirmed"]]
    
    print(f"\n=== 查询结果 (按状态分组) ===")
    
    # 显示存在的交易
    if existing_txs:
        print(f"\n✓ 存在的交易 ({len(existing_txs)} 个):")
        print("-" * 40)
        
        # 显示已确认成功的交易
        if confirmed_txs:
            print(f"\n  已确认成功交易 ({len(confirmed_txs)} 个):")
            for tx in confirmed_txs:
                block_num = int(tx["block_number"], 16) if tx["block_number"] else "未知"
                print(f"    ✓ {tx['hash'][:10]}...{tx['hash'][-6:]} - 交易成功 (区块: {block_num})")
        
        # 显示已确认失败的交易
        if failed_txs:
            print(f"\n  已确认失败交易 ({len(failed_txs)} 个):")
            for tx in failed_txs:
                block_num = int(tx["block_number"], 16) if tx["block_number"] else "未知"
                print(f"    ✗ {tx['hash'][:10]}...{tx['hash'][-6:]} - 交易失败 (区块: {block_num})")
        
        # 显示待确认的交易
        if pending_txs:
            print(f"\n  待确认交易 ({len(pending_txs)} 个):")
            for tx in pending_txs:
                print(f"    ◐ {tx['hash'][:10]}...{tx['hash'][-6:]} - 交易存在但未确认 (在内存池中)")
    
    # 显示不存在的交易
    if non_existing_txs:
        print(f"\n✗ 不存在的交易 ({len(non_existing_txs)} 个):")
        print("-" * 40)
        for tx in non_existing_txs:
            error_msg = f" - {tx['error']}" if tx.get('error') else " - 交易不存在"
            print(f"    ✗ {tx['hash'][:10]}...{tx['hash'][-6:]}{error_msg}")

def print_summary(results: List[Dict]):
    """打印查询结果摘要"""
    total = len(results)
    existing_txs = [r for r in results if r["exists"]]
    confirmed_txs = [r for r in existing_txs if r["confirmed"] and r.get("status") == "0x1"]
    failed_txs = [r for r in existing_txs if r["confirmed"] and r.get("status") == "0x0"]
    pending_txs = [r for r in existing_txs if not r["confirmed"]]
    non_existing_txs = [r for r in results if not r["exists"]]
    errors = sum(1 for r in results if r["error"])
    
    print(f"\n=== 查询结果统计 ===")
    print(f"总查询数量: {total}")
    print(f"存在交易: {len(existing_txs)}")
    print(f"  - 已确认成功: {len(confirmed_txs)}")
    print(f"  - 已确认失败: {len(failed_txs)}")
    print(f"  - 待确认: {len(pending_txs)}")
    print(f"不存在交易: {len(non_existing_txs)}")
    print(f"查询错误: {errors}")
    print(f"成功率: {((total - errors) / total * 100):.1f}%" if total > 0 else "0%")

def save_results(results: List[Dict], filename: str = "tx_query_results.json"):
    """保存查询结果到文件"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n结果已保存到: {filename}")
    except Exception as e:
        print(f"保存结果失败: {e}")

def main():
    """主函数"""
    print("以太坊交易批量查询工具")
    print("=" * 50)
    
    # 示例交易哈希列表（用户可以修改这里）
    tx_hashes = [
        # 在这里添加要查询的交易哈希
        # "0x1234567890abcdef...",
        # "0xabcdef1234567890...",
    ]
    
    # 从命令行参数读取交易哈希
    if len(sys.argv) > 1:
        # 支持多种输入方式
        if sys.argv[1].endswith('.txt'):
            # 从文件读取
            try:
                with open(sys.argv[1], 'r') as f:
                    # 过滤掉空行、注释行和无效的哈希
                    tx_hashes = []
                    for line in f:
                        line = line.strip()
                        # 跳过空行和注释行
                        if not line or line.startswith('#'):
                            continue
                        # 检查是否是有效的交易哈希格式（0x开头，66个字符）
                        if line.startswith('0x') and len(line) == 66:
                            tx_hashes.append(line)
                print(f"从文件 {sys.argv[1]} 读取了 {len(tx_hashes)} 个有效交易哈希")
            except Exception as e:
                print(f"读取文件失败: {e}")
                return
        else:
            # 从命令行参数读取
            tx_hashes = sys.argv[1:]
    
    if not tx_hashes:
        print("请提供要查询的交易哈希:")
        print("方式1: python3 batch_tx_query.py 0x123... 0xabc...")
        print("方式2: python3 batch_tx_query.py tx_hashes.txt")
        print("方式3: 修改脚本中的 tx_hashes 列表")
        return
    
    print(f"准备查询 {len(tx_hashes)} 个交易哈希...\n")
    
    # 执行批量查询
    start_time = time.time()
    results = batch_query_transactions(tx_hashes)
    end_time = time.time()
    
    # 打印分组结果
    print_grouped_results(results)
    
    # 打印统计结果
    print_summary(results)
    print(f"查询耗时: {end_time - start_time:.2f} 秒")
    
    # 保存结果
    save_results(results)

if __name__ == "__main__":
    main()