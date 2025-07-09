// Copyright 2024 Fudong and Hosen
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
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"

	// "github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
)

type GeneralStateTest map[string]*stJSON

type stJSON struct {
	Ps   []StateSeries            `json:"packet-sequence"`
	Out  hexutil.Bytes            `json:"out"`
	Post map[string][]stPostState `json:"post"`
}

type stPostState struct {
	Root    common.Hash `json:"hash"`
	Logs    common.Hash `json:"logs"`
	Indexes stIndex     `json:"indexes"`
}

type stIndex struct {
	Data  int `json:"data"`
	Gas   int `json:"gas"`
	Value int `json:"value"`
}

// BlockCorpus 用于保存所有已知的区块头
type BlockCorpus struct {
	mu      sync.RWMutex
	headers map[int]*types.Header
}

func NewBlockCorpus() *BlockCorpus {
	return &BlockCorpus{
		headers: make(map[int]*types.Header),
	}
}

func (bc *BlockCorpus) AddHeaders(hds []*types.Header) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	for _, h := range hds {
		bc.headers[int(h.Number.Uint64())] = h
	}
}

func (bc *BlockCorpus) GetHeader(index int) (*types.Header, bool) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	h, ok := bc.headers[index]
	return h, ok
}

func (bc *BlockCorpus) AllHeaders() []*types.Header {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	result := make([]*types.Header, 0, len(bc.headers))
	for _, h := range bc.headers {
		result = append(result, h)
	}
	return result
}

// NetworkState 保存 handshake 阶段的网络状态信息
type NetworkState struct {
	ProtocolVersion uint32
	NetworkID       uint64
	TD              *big.Int
	Head            common.Hash
	Genesis         common.Hash
	ForkID          forkid.ID
}

// func (ns *NetworkState) ToStatusPacket() *eth.StatusPacket {
// 	return &eth.StatusPacket{
// 		ProtocolVersion: ns.ProtocolVersion,
// 		NetworkID:       ns.NetworkID,
// 		TD:              ns.TD,
// 		Head:            ns.Head,
// 		Genesis:         ns.Genesis,
// 		ForkID:          ns.ForkID,
// 	}
// }
