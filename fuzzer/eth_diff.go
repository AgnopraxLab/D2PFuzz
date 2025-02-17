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
	NoResponse    = -3 // No response
	EmptyResponse = -2 // Empty response
)

// ethRespToInts encodes response packet into integer array
func ethRespToInts(resp eth.Packet) []int {
	if resp == nil {
		return []int{NoResponse}
	}

	switch msg := resp.(type) {
	case *eth.BlockHeadersPacket:
		headers := msg.BlockHeadersRequest
		if len(headers) == 0 {
			return []int{EmptyResponse}
		}

		code := make([]int, 5)

		// [0]: RequestId
		code[0] = int(msg.RequestId)

		// [1]: Number of headers
		code[1] = len(headers)

		// [2]: Starting block number
		code[2] = int(headers[0].Number.Uint64())

		// [3]: Ending block number
		code[3] = int(headers[len(headers)-1].Number.Uint64())

		// [4]: Combined hash of all headers (first 4 bytes)
		hashSum := headers[0].Hash().Bytes()
		for _, h := range headers[1:] {
			hash := h.Hash().Bytes()
			for i := range hashSum {
				hashSum[i] ^= hash[i%len(hash)]
			}
		}
		code[4] = int(binary.BigEndian.Uint32(hashSum[:4]))

		return code

	case *eth.BlockBodiesPacket:
		bodies := msg.BlockBodiesResponse
		if len(bodies) == 0 {
			return []int{EmptyResponse}
		}

		code := make([]int, 6)

		// [0]: RequestId
		code[0] = int(msg.RequestId)

		// [1]: Number of bodies
		code[1] = len(bodies)

		// [2]: Total transaction count
		txCount := 0
		for _, body := range bodies {
			txCount += len(body.Transactions)
		}
		code[2] = txCount

		// [3]: Total uncle count
		uncleCount := 0
		for _, body := range bodies {
			uncleCount += len(body.Uncles)
		}
		code[3] = uncleCount

		// [4]: Total withdrawals count
		withdrawalCount := 0
		for _, body := range bodies {
			withdrawalCount += len(body.Withdrawals)
		}
		code[4] = withdrawalCount

		// [5]: Combined transaction hash
		if txCount > 0 {
			txHashSum := make([]byte, 32)
			for _, body := range bodies {
				for _, tx := range body.Transactions {
					txHash := tx.Hash().Bytes()
					for i := range txHashSum {
						txHashSum[i] ^= txHash[i%len(txHash)]
					}
				}
			}
			code[5] = int(binary.BigEndian.Uint32(txHashSum[:4]))
		}

		return code

	case *eth.ReceiptsPacket:
		receipts := msg.ReceiptsResponse
		if len(receipts) == 0 {
			return []int{EmptyResponse}
		}

		code := make([]int, 4)

		// [0]: RequestId
		code[0] = int(msg.RequestId)

		// [1]: Number of receipt batches
		code[1] = len(receipts)

		// [2]: Total receipt count
		receiptCount := 0
		for _, batch := range receipts {
			receiptCount += len(batch)
		}
		code[2] = receiptCount

		// [3]: Total log count
		logCount := 0
		for _, batch := range receipts {
			for _, receipt := range batch {
				logCount += len(receipt.Logs)
			}
		}
		code[3] = logCount

		return code
	}

	return []int{NoResponse}
}

// snapRespToInts encodes response packet into integer array
func snapRespToInts(resp snap.Packet) []int {
	if resp == nil {
		return []int{NoResponse}
	}

	switch msg := resp.(type) {
	case *snap.AccountRangePacket:
		code := make([]int, 4)
		code[0] = int(msg.ID)
		code[1] = len(msg.Accounts)
		code[2] = len(msg.Proof)

		totalSize := 0
		for _, acc := range msg.Accounts {
			totalSize += len(acc.Body)
		}
		code[3] = totalSize
		return code

	case *snap.StorageRangesPacket:
		code := make([]int, 4)
		code[0] = int(msg.ID)

		// 计算所有账户的存储槽总数
		totalSlots := 0
		for _, slots := range msg.Slots {
			totalSlots += len(slots)
		}
		code[1] = len(msg.Slots) // 账户数量
		code[2] = totalSlots     // 总存储槽数量
		code[3] = len(msg.Proof) // 证明大小
		return code

	case *snap.ByteCodesPacket:
		code := make([]int, 3)
		code[0] = int(msg.ID)
		code[1] = len(msg.Codes)

		totalSize := 0
		for _, bytecode := range msg.Codes {
			totalSize += len(bytecode)
		}
		code[2] = totalSize
		return code

	case *snap.TrieNodesPacket:
		code := make([]int, 3)
		code[0] = int(msg.ID)
		code[1] = len(msg.Nodes)

		totalSize := 0
		for _, node := range msg.Nodes {
			totalSize += len(node)
		}
		code[2] = totalSize
		return code
	}

	return []int{NoResponse}
}
