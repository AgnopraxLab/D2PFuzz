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

package fuzzing

import (
	"encoding/binary"
	"math/rand"
	"net"
	"unsafe"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	interesting8  = []int8{-128, -1, 0, 1, 16, 32, 64, 100, 127}
	interesting16 = []int16{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767}
	interesting32 = []int32{-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647}
)

func init() {
	for _, v := range interesting8 {
		interesting16 = append(interesting16, int16(v))
	}
	for _, v := range interesting16 {
		interesting32 = append(interesting32, int32(v))
	}
}

type Mutator struct {
	r *rand.Rand
}

func NewMutator(r *rand.Rand) *Mutator {
	return &Mutator{r: r}
}

func (m *Mutator) Rand(n int) int {
	if n <= 0 {
		return 0
	}
	return m.r.Intn(n)
}

func (m *Mutator) Bool() bool {
	return m.r.Int()%2 == 0
}

func (m *Mutator) randByteOrder() binary.ByteOrder {
	if m.Bool() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// chooseLen chooses length of range mutation in range [1,n]. It gives
// preference to shorter ranges.
func (m *Mutator) chooseLen(n int) int {
	switch x := m.Rand(100); {
	case x < 90:
		return m.Rand(min(8, n)) + 1
	case x < 99:
		return m.Rand(min(32, n)) + 1
	default:
		return m.Rand(n) + 1
	}
}

func (m *Mutator) FillBytes(ptr *[]byte) {
	m.r.Read(*ptr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type byteSliceMutator func(*Mutator, []byte) []byte

var byteSliceMutators = []byteSliceMutator{
	byteSliceRemoveBytes,
	byteSliceInsertRandomBytes,
	byteSliceDuplicateBytes,
	byteSliceOverwriteBytes,
	byteSliceBitFlip,
	byteSliceXORByte,
	byteSliceSwapByte,
	byteSliceArithmeticUint8,
	byteSliceArithmeticUint16,
	byteSliceArithmeticUint32,
	byteSliceArithmeticUint64,
	byteSliceOverwriteInterestingUint8,
	byteSliceOverwriteInterestingUint16,
	byteSliceOverwriteInterestingUint32,
	byteSliceInsertConstantBytes,
	byteSliceOverwriteConstantBytes,
	byteSliceShuffleBytes,
	byteSliceSwapBytes,
}

func (m *Mutator) MutateBytes(ptrB *[]byte) {
	b := *ptrB
	defer func() {
		oldHdr := unsafe.SliceData(*ptrB)
		newHdr := unsafe.SliceData(b)
		if oldHdr != newHdr {
			panic("data moved to new address")
		}
		*ptrB = b
	}()

	for {
		mut := byteSliceMutators[m.Rand(len(byteSliceMutators))]
		if mutated := mut(m, b); mutated != nil {
			b = mutated
			return
		}
	}
}

func (m *Mutator) MutateExp(expiration *uint64) {
	if *expiration > 0 {
		switch m.Rand(5) {
		case 0:
			// 递减：确保非负
			maxDecrease := *expiration / 2
			if maxDecrease > 0 {
				delta := uint64(m.r.Int63n(max(int64(maxDecrease), 1)))
				*expiration -= delta
			}
		case 1:
			// 递增：避免溢出
			maxIncrease := uint64(^uint64(0) - *expiration)
			if maxIncrease > 0 {
				maxDelta := max(min64(int64(maxIncrease), 1000000), 1)
				delta := uint64(m.r.Int63n(maxDelta))
				*expiration += delta
			}
		case 2:
			// 乘法：避免溢出
			maxMultiplier := uint64(10)
			if *expiration > 0 {
				safeMultiplier := min64(int64(^uint64(0) / *expiration), int64(maxMultiplier))
				if safeMultiplier > 1 {
					multiplier := uint64(m.r.Int63n(int64(safeMultiplier)-1) + 1)
					*expiration *= multiplier
				}
			}
		case 3:
			// 位反转
			*expiration = ^*expiration
		case 4:
			// 边界值测试
			if m.Bool() {
				*expiration = 0
			} else {
				*expiration = ^uint64(0) // uint64的最大值
			}
		}
	} else {
		// 如果当前值为0，随机设置一个小的正值
		*expiration = uint64(m.r.Int63n(1000) + 1)
	}
}

// 辅助函数：返回两个int64中的较小值
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (m *Mutator) MutateRest(rest *[]rlp.RawValue) {
	// If Rest is empty, first insert an initial value
	if len(*rest) == 0 {
		initialValue := rlp.RawValue{byte(rand.Intn(256))}
		*rest = append(*rest, initialValue)
	}

	// Mutate each RawValue in Rest
	for i := range *rest {
		if len((*rest)[i]) > 0 {
			switch rand.Intn(5) {
			case 0:
				// Random byte replacement
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i][pos] = byte(rand.Intn(256))
			case 1:
				// Byte flip
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i][pos] ^= 0xFF
			case 2:
				// Insert random byte
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i] = append((*rest)[i][:pos], append([]byte{byte(rand.Intn(256))}, (*rest)[i][pos:]...)...)
			case 3:
				// Delete byte
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i] = append((*rest)[i][:pos], (*rest)[i][pos+1:]...)
			case 4:
				// Repeat part of the content
				start := rand.Intn(len((*rest)[i]))
				end := start + rand.Intn(len((*rest)[i])-start)
				(*rest)[i] = append((*rest)[i][:end], append((*rest)[i][start:end], (*rest)[i][end:]...)...)
			}
		}
	}
}

// discv5 protocol
// MutateENRSeq 变异ENR序列号
func (m *Mutator) MutateENRSeq(seq *uint64) {
	switch m.Rand(4) {
	case 0:
		// 随机增加
		*seq += uint64(m.Rand(1000))
	case 1:
		// 随机减少
		if *seq > 0 {
			*seq -= uint64(m.Rand(min(int(*seq), 1000)))
		}
	case 2:
		// 设置为边界值
		if m.Bool() {
			*seq = 0
		} else {
			*seq = ^uint64(0) // 最大值
		}
	case 3:
		// 完全随机值
		*seq = uint64(m.Rand(1000000))
	}
}

// MutateDistances 变异距离数组
func (m *Mutator) MutateDistances(distances *[]uint) {
	switch m.Rand(4) {
	case 0:
		// 添加新距离
		*distances = append(*distances, uint(m.Rand(256)))
	case 1:
		// 删除一个距离
		if len(*distances) > 0 {
			i := m.Rand(len(*distances))
			*distances = append((*distances)[:i], (*distances)[i+1:]...)
		}
	case 2:
		// 修改现有距离
		if len(*distances) > 0 {
			i := m.Rand(len(*distances))
			(*distances)[i] = uint(m.Rand(256))
		}
	case 3:
		// 完全重置
		newLen := m.Rand(10) + 1
		*distances = make([]uint, newLen)
		for i := range *distances {
			(*distances)[i] = uint(m.Rand(256))
		}
	}
}

// MutateNodes 变异节点记录数组
func (m *Mutator) MutateNodes(nodes *[]*enr.Record) {
	if len(*nodes) == 0 {
		return
	}

	switch m.Rand(3) {
	case 0:
		// 删除随机节点
		i := m.Rand(len(*nodes))
		*nodes = append((*nodes)[:i], (*nodes)[i+1:]...)
	case 1:
		// 修改随机节点
		i := m.Rand(len(*nodes))
		if (*nodes)[i] != nil {
			// 修改IP
			(*nodes)[i].Set(enr.IP(net.IPv4(
				byte(m.Rand(256)),
				byte(m.Rand(256)),
				byte(m.Rand(256)),
				byte(m.Rand(256)),
			)))
			// 修改端口
			(*nodes)[i].Set(enr.UDP(uint16(m.Rand(65536))))
		}
	case 2:
		// 复制现有节点
		if len(*nodes) > 0 {
			i := m.Rand(len(*nodes))
			*nodes = append(*nodes, (*nodes)[i])
		}
	}
}

// MutateRequestId 对 RequestId 进行变异
func (m *Mutator) MutateRequestId(id *uint64) {
	switch m.Rand(4) {
	case 0:
		// 随机增加
		*id += uint64(m.Rand(1000))
	case 1:
		// 随机减少
		if *id > 0 {
			*id -= uint64(m.Rand(min(int(*id), 1000)))
		}
	case 2:
		// 设置为边界值
		if m.Bool() {
			*id = 0
		} else {
			*id = ^uint64(0) // 最大值
		}
	case 3:
		// 完全随机值
		*id = uint64(m.Rand(1000))
	}
}

// MutateOrigin 变异区块头的Origin字段
func (m *Mutator) MutateOrigin(origin *eth.HashOrNumber, amount uint64, skip uint64, reverse bool, chain *eth.Chain) {
	// 简单地生成一个随机区块号
	origin.Number = uint64(m.Rand(int(chain.Len()) * 2)) // 允许超出链长度
	origin.Hash = common.Hash{}                          // 清空Hash，使用Number
}

// MutateAmount 变异区块头请求的Amount字段
func (m *Mutator) MutateAmount(amount *uint64, origin uint64, skip uint64, reverse bool, chain *eth.Chain) {
	switch m.Rand(3) {
	case 0:
		// 生成一个较小的值
		*amount = uint64(m.Rand(100)) + 1
	case 1:
		// 生成一个较大的值
		*amount = uint64(m.Rand(10000)) + 100
	case 2:
		// 边界值
		*amount = uint64(m.Rand(2)) // 0 或 1
	}
}

// MutateSkip 变异区块头请求的Skip字段
func (m *Mutator) MutateSkip(skip *uint64, chain *eth.Chain) {
	switch m.Rand(3) {
	case 0:
		// 小值
		*skip = uint64(m.Rand(10))
	case 1:
		// 大值
		*skip = uint64(m.Rand(1000)) + 100
	case 2:
		// 极端值
		if m.Bool() {
			*skip = 0
		} else {
			*skip = ^uint64(0) // 最大值
		}
	}
}

// MutateReverse 变异区块头请求的Reverse字段
func (m *Mutator) MutateReverse(reverse *bool) {
	*reverse = !*reverse // 保持简单的翻转即可
}

// MutateBlockBodiesRequest 变异区块体请求的哈希列表
func (m *Mutator) MutateBlockBodiesRequest(request *eth.GetBlockBodiesRequest, chain *eth.Chain) {
	switch m.Rand(4) {
	case 0:
		// 空列表
		*request = eth.GetBlockBodiesRequest{}

	case 1:
		// 随机选择1-5个有效哈希
		count := m.Rand(5) + 1
		hashes := make(eth.GetBlockBodiesRequest, 0, count)
		blocks := chain.Blocks()
		for i := 0; i < count; i++ {
			if len(blocks) > 0 {
				idx := m.Rand(len(blocks))
				hashes = append(hashes, blocks[idx].Hash())
			}
		}
		*request = hashes

	case 2:
		// 生成1-5个随机哈希
		count := m.Rand(5) + 1
		hashes := make(eth.GetBlockBodiesRequest, 0, count)
		for i := 0; i < count; i++ {
			var hash common.Hash
			hashBytes := make([]byte, common.HashLength)
			m.MutateBytes(&hashBytes)
			copy(hash[:], hashBytes)
			hashes = append(hashes, hash)
		}
		*request = hashes

	case 3:
		// 混合有效和无效哈希
		count := m.Rand(5) + 1
		hashes := make(eth.GetBlockBodiesRequest, 0, count)
		blocks := chain.Blocks()
		for i := 0; i < count; i++ {
			if m.Bool() && len(blocks) > 0 {
				idx := m.Rand(len(blocks))
				hashes = append(hashes, blocks[idx].Hash())
			} else {
				var hash common.Hash
				hashBytes := make([]byte, common.HashLength)
				m.MutateBytes(&hashBytes)
				copy(hash[:], hashBytes)
				hashes = append(hashes, hash)
			}
		}
		*request = hashes
	}
}
