// Copyright 2024 Fudong
// This file is part of the D2PFuzz library.
//
// The D2PFuzz library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The D2PFuzz library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the D2PFuzz library. If not, see <http://www.gnu.org/licenses/>.

package fuzzer

import (
	"encoding/binary"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/snap"
)

// Response type constants
const (
	NoResponse    = -1 // No response
	EmptyResponse = 0  // Empty response
)

// ethRespToInts 将响应包编码为整数数组，用于状态覆盖率分析
func ethRespToInts(resp eth.Packet) []int {
	// 如果没有响应，返回特定状态码
	if resp == nil {
		return []int{NoResponse}
	}

	switch msg := resp.(type) {
	case *eth.BlockHeadersPacket:
		headers := msg.BlockHeadersRequest

		// 如果响应为空，返回空响应状态码
		if len(headers) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{eth.BlockHeadersMsg}

		// 第二个字段：返回的区块头数量
		code = append(code, len(headers))

		// 后续字段：每个区块头的编号作为唯一标识符
		for _, header := range headers {
			code = append(code, int(header.Number.Uint64()))
		}

		return code

	case *eth.BlockBodiesPacket:
		bodies := msg.BlockBodiesResponse

		if len(bodies) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{eth.BlockBodiesMsg}

		// 第二个字段：区块体数量
		code = append(code, len(bodies))

		// 为每个区块体添加唯一标识信息
		for _, body := range bodies {
			// 添加每个交易的 nonce 值作为唯一标识符
			for _, tx := range body.Transactions {
				// 假设 Nonce 是 uint64 类型
				code = append(code, int(tx.Nonce()))
			}
			for _, uncle := range body.Uncles {
				code = append(code, int(uncle.Number.Uint64()))
			}
			for _, withdrawal := range body.Withdrawals {
				code = append(code, int(withdrawal.Index))
			}
		}

		return code

	case *eth.ReceiptsPacket:
		receipts := msg.ReceiptsResponse

		if len(receipts) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{eth.ReceiptsMsg}

		// 第二个字段：收据批次数量
		code = append(code, len(receipts))

		// 添加每个收据的详细信息
		for _, batch := range receipts {
			for _, receipt := range batch {
				// 直接使用已有的uint64值
				code = append(code, int(receipt.CumulativeGasUsed))

				if len(receipt.Logs) > 0 {
					code = append(code, len(receipt.Logs))
				}
			}
		}

		return code

	// 其他类型的响应包处理...
	case *eth.StatusPacket:
		return []int{eth.StatusMsg}

	case *eth.NewBlockHashesPacket:
		hashes := *msg
		if len(hashes) == 0 {
			return []int{EmptyResponse}
		}

		code := []int{eth.NewBlockHashesMsg, len(hashes)}

		// 添加每个块的编号作为唯一标识符
		for _, blockInfo := range hashes {
			code = append(code, int(blockInfo.Number))
		}

		return code

	case *eth.TransactionsPacket:
		txs := *msg
		if len(txs) == 0 {
			return []int{EmptyResponse}
		}

		return []int{eth.TransactionsMsg, len(txs)}

	case *eth.NewBlockPacket:
		if msg.Block == nil {
			return []int{EmptyResponse}
		}

		blockNum := int(msg.Block.NumberU64())
		return []int{eth.NewBlockMsg, 1, blockNum}

	case *eth.PooledTransactionsPacket:
		txs := msg.PooledTransactionsResponse
		if len(txs) == 0 {
			return []int{EmptyResponse}
		}

		return []int{eth.PooledTransactionsMsg, len(txs)}

	case *eth.NewPooledTransactionHashesPacket:
		hashes := msg.Hashes
		if len(hashes) == 0 {
			return []int{EmptyResponse}
		}

		return []int{eth.NewPooledTransactionHashesMsg, len(hashes)}
	}

	return []int{NoResponse}
}

// snapRespToInts 将响应包编码为整数数组，用于状态覆盖率分析
func snapRespToInts(resp snap.Packet) []int {
	if resp == nil {
		return []int{NoResponse}
	}

	switch msg := resp.(type) {
	case *snap.AccountRangePacket:
		// 如果账户列表为空
		if len(msg.Accounts) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{snap.AccountRangeMsg}

		// 第二个字段：账户数量
		code = append(code, len(msg.Accounts))

		// 第三个字段：证明大小
		code = append(code, len(msg.Proof))

		// 计算总数据大小
		totalSize := 0
		for _, acc := range msg.Accounts {
			totalSize += len(acc.Body)
		}
		code = append(code, totalSize)

		// 添加数据哈希特征（取哈希的前4字节转为整数）
		if len(msg.Accounts) > 0 {
			hashSum := make([]byte, 32)
			for _, acc := range msg.Accounts {
				// XOR account body bytes
				for i, b := range acc.Body {
					hashSum[i%len(hashSum)] ^= b
				}
			}
			code = append(code, int(binary.BigEndian.Uint32(hashSum[:4])))
		}

		return code

	case *snap.StorageRangesPacket:
		// 如果存储槽为空
		totalSlots := 0
		for _, slots := range msg.Slots {
			totalSlots += len(slots)
		}

		if len(msg.Slots) == 0 || totalSlots == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{snap.StorageRangesMsg}

		// 第二个字段：账户数量
		code = append(code, len(msg.Slots))

		// 第三个字段：总存储槽数
		code = append(code, totalSlots)

		// 第四个字段：证明大小
		code = append(code, len(msg.Proof))

		// 添加数据哈希特征
		if totalSlots > 0 {
			hashSum := make([]byte, 32)
			for _, slots := range msg.Slots {
				for _, slot := range slots {
					// XOR slot hash and body bytes
					hashBytes := slot.Hash.Bytes()
					for i, b := range hashBytes {
						hashSum[i%len(hashSum)] ^= b
					}
					for i, b := range slot.Body {
						hashSum[i%len(hashSum)] ^= b
					}
				}
			}
			code = append(code, int(binary.BigEndian.Uint32(hashSum[:4])))
		}

		return code

	case *snap.ByteCodesPacket:
		// 如果字节码为空
		if len(msg.Codes) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{snap.ByteCodesMsg}

		// 第二个字段：字节码数量
		code = append(code, len(msg.Codes))

		// 计算总大小
		totalSize := 0
		for _, bytecode := range msg.Codes {
			totalSize += len(bytecode)
		}
		code = append(code, totalSize)

		// 添加字节码哈希特征
		if len(msg.Codes) > 0 {
			hashSum := make([]byte, 32)
			for _, bytecode := range msg.Codes {
				// XOR bytecode bytes
				for i, b := range bytecode {
					hashSum[i%len(hashSum)] ^= b
				}
			}
			code = append(code, int(binary.BigEndian.Uint32(hashSum[:4])))
		}

		return code

	case *snap.TrieNodesPacket:
		// 如果Trie节点为空
		if len(msg.Nodes) == 0 {
			return []int{EmptyResponse}
		}

		// 第一个字段：包类型
		code := []int{snap.TrieNodesMsg}

		// 第二个字段：节点数量
		code = append(code, len(msg.Nodes))

		// 计算总大小
		totalSize := 0
		for _, node := range msg.Nodes {
			totalSize += len(node)
		}
		code = append(code, totalSize)

		// 添加节点哈希特征
		if len(msg.Nodes) > 0 {
			hashSum := make([]byte, 32)
			for _, node := range msg.Nodes {
				// XOR node bytes
				for i, b := range node {
					hashSum[i%len(hashSum)] ^= b
				}
			}
			code = append(code, int(binary.BigEndian.Uint32(hashSum[:4])))
		}

		return code
	}

	return []int{NoResponse}
}
