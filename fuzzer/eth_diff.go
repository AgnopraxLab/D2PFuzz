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
)

// Response type constants
const (
	NoResponse    = -1 // No response
	EmptyResponse = 0  // Empty response
)

// encodeRespToInts encodes response packet into integer array
func encodeRespToInts(resp eth.Packet) []int {
	if resp == nil {
		return []int{NoResponse}
	}

	switch msg := resp.(type) {
	case *eth.BlockHeadersPacket:
		headers := msg.BlockHeadersRequest
		if len(headers) == 0 {
			return []int{EmptyResponse}
		}

		code := make([]int, 6)

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

		// [4]: Combined transaction hash
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
			code[4] = int(binary.BigEndian.Uint32(txHashSum[:4]))
		}

		return code

	case *eth.ReceiptsPacket:
		receipts := msg.ReceiptsResponse
		if len(receipts) == 0 {
			return []int{EmptyResponse}
		}

		code := make([]int, 6)

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
