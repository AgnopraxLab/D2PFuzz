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
	"bytes"
	"encoding/binary"
	"math/big"
	"math/rand"
	"net"
	"unsafe"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/snap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
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

// MutateReceiptsRequest 变异收据请求的哈希列表
func (m *Mutator) MutateReceiptsRequest(request *eth.GetReceiptsRequest, chain *eth.Chain) {
	switch m.Rand(4) {
	case 0:
		// 空列表
		*request = eth.GetReceiptsRequest{}

	case 1:
		// 随机选择1-5个有效哈希
		count := m.Rand(5) + 1
		hashes := make(eth.GetReceiptsRequest, 0, count)
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
		hashes := make(eth.GetReceiptsRequest, 0, count)
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
		hashes := make(eth.GetReceiptsRequest, 0, count)
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

func (m *Mutator) MutateTransaction(original *types.Transaction) *types.Transaction {
	// 选择交易类型
	txType := byte(m.Rand(4)) // 0-3对应四种交易类型

	switch txType {
	case types.LegacyTxType:
		return m.mutateLegacyTx(original)
	case types.AccessListTxType:
		return m.mutateAccessListTx(original)
	case types.DynamicFeeTxType:
		return m.mutateDynamicFeeTx(original)
	case types.BlobTxType:
		return m.mutateBlobTx(original)
	default:
		return m.mutateLegacyTx(original) // 默认使用Legacy类型
	}
}

func (m *Mutator) mutateLegacyTx(original *types.Transaction) *types.Transaction {
	// 如果没有原始交易或随机决定创建新交易
	if original == nil || m.Bool() {
		// 创建新交易的各个字段
		// nonce: 交易序号，范围0-999
		nonce := uint64(m.r.Int63n(1000))

		// gasPrice: 燃料价格，范围0-999999999 wei
		gasPrice := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))

		// gas: 燃料限制，范围0-999999
		gas := uint64(m.r.Int63n(1000000))

		// to: 接收地址，可能为nil（合约创建）
		var to *common.Address
		if m.Bool() { // 50%概率设置接收地址
			addr := common.BytesToAddress(m.RandBytes(20)) // 生成20字节的随机地址
			to = &addr
		}

		// value: 转账金额，范围0-999999999 wei
		value := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))

		// data: 交易数据，0-99字节的随机数据
		data := m.RandBytes(m.r.Int63n(100))

		// 创建并返回新交易
		return types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gas,
			To:       to,
			Value:    value,
			Data:     data,
		})
	}

	// 检查原始交易类型
	if original.Type() != types.LegacyTxType {
		return m.mutateLegacyTx(nil) // 如果不是Legacy类型，创建新交易
	}

	// 复制原始交易的所有字段
	nonce := original.Nonce()
	gasPrice := new(big.Int).Set(original.GasPrice()) // 深拷贝
	gas := original.Gas()
	to := original.To()                         // 指针复制
	value := new(big.Int).Set(original.Value()) // 深拷贝
	data := make([]byte, len(original.Data()))
	copy(data, original.Data()) // 深拷贝

	// 随机选择一个字段进行变异
	switch m.r.Int63n(6) { // 随机选择0-5之间的数
	case 0: // 变异nonce
		nonce = uint64(m.r.Int63n(1000))
	case 1: // 变异gasPrice
		gasPrice.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 2: // 变异gas限制
		gas = uint64(m.r.Int63n(1000000))
	case 3: // 变异接收地址
		if m.Bool() {
			addr := common.BytesToAddress(m.RandBytes(20))
			to = &addr
		} else {
			to = nil // 合约创建
		}
	case 4: // 变异转账金额
		value.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 5: // 变异交易数据
		data = m.RandBytes(m.r.Int63n(100))
	}

	// 创建并返回变异后的交易
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       to,
		Value:    value,
		Data:     data,
	})
}

func (m *Mutator) mutateAccessListTx(original *types.Transaction) *types.Transaction {
	if original == nil || m.Bool() {
		// 创建新交易
		nonce := uint64(m.r.Int63n(1000))
		gasPrice := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))
		gas := uint64(m.r.Int63n(1000000))

		var to *common.Address
		if m.Bool() {
			addr := common.BytesToAddress(m.RandBytes(20))
			to = &addr
		}

		value := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))
		data := m.RandBytes(m.r.Int63n(100))
		accessList := m.generateAccessList()

		return types.NewTx(&types.AccessListTx{
			ChainID:    new(big.Int).SetUint64(1),
			Nonce:      nonce,
			GasPrice:   gasPrice,
			Gas:        gas,
			To:         to,
			Value:      value,
			Data:       data,
			AccessList: accessList,
		})
	}

	// 基于原始交易进行变异
	if original.Type() != types.AccessListTxType {
		return m.mutateAccessListTx(nil)
	}

	// 复制原始交易的值
	nonce := original.Nonce()
	gasPrice := new(big.Int).Set(original.GasPrice())
	gas := original.Gas()
	to := original.To()
	value := new(big.Int).Set(original.Value())
	data := make([]byte, len(original.Data()))
	copy(data, original.Data())
	accessList := original.AccessList()

	// 随机选择要变异的字段
	switch m.r.Int63n(8) {
	case 0:
		nonce = uint64(m.r.Int63n(1000))
	case 1:
		gasPrice.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 2:
		gas = uint64(m.r.Int63n(1000000))
	case 3:
		if m.Bool() {
			addr := common.BytesToAddress(m.RandBytes(20))
			to = &addr
		} else {
			to = nil
		}
	case 4:
		value.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 5:
		data = m.RandBytes(m.r.Int63n(100))
	case 6:
		accessList = m.generateAccessList()
	}

	return types.NewTx(&types.AccessListTx{
		ChainID:    new(big.Int).SetUint64(1),
		Nonce:      nonce,
		GasPrice:   gasPrice,
		Gas:        gas,
		To:         to,
		Value:      value,
		Data:       data,
		AccessList: accessList,
	})
}

// 辅助函数：生成随机访问列表
func (m *Mutator) generateAccessList() types.AccessList {
	var accessList types.AccessList
	numEntries := m.r.Int63n(3)
	for i := 0; i < int(numEntries); i++ {
		addr := common.BytesToAddress(m.RandBytes(20))
		numStorageKeys := m.r.Int63n(3)
		storageKeys := make([]common.Hash, numStorageKeys)
		for j := 0; j < int(numStorageKeys); j++ {
			storageKeys[j] = common.BytesToHash(m.RandBytes(32))
		}
		accessList = append(accessList, types.AccessTuple{
			Address:     addr,
			StorageKeys: storageKeys,
		})
	}
	return accessList
}

func (m *Mutator) mutateDynamicFeeTx(original *types.Transaction) *types.Transaction {
	if original == nil || m.Bool() {
		// 创建新交易
		nonce := uint64(m.r.Int63n(1000))
		gasTipCap := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))
		gasFeeCap := new(big.Int).Add(gasTipCap, new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000))))
		gas := uint64(m.r.Int63n(1000000))

		var to *common.Address
		if m.Bool() {
			addr := common.BytesToAddress(m.RandBytes(20))
			to = &addr
		}

		value := new(big.Int).SetUint64(uint64(m.r.Int63n(1000000000)))
		data := m.RandBytes(m.r.Int63n(100))
		accessList := m.generateAccessList()

		return types.NewTx(&types.DynamicFeeTx{
			ChainID:    new(big.Int).SetUint64(1),
			Nonce:      nonce,
			GasTipCap:  gasTipCap,
			GasFeeCap:  gasFeeCap,
			Gas:        gas,
			To:         to,
			Value:      value,
			Data:       data,
			AccessList: accessList,
		})
	}

	// 基于原始交易进行变异
	if original.Type() != types.DynamicFeeTxType {
		return m.mutateDynamicFeeTx(nil)
	}

	// 复制原始交易的值
	nonce := original.Nonce()
	gasTipCap := new(big.Int).Set(original.GasTipCap())
	gasFeeCap := new(big.Int).Set(original.GasFeeCap())
	gas := original.Gas()
	to := original.To()
	value := new(big.Int).Set(original.Value())
	data := make([]byte, len(original.Data()))
	copy(data, original.Data())
	accessList := original.AccessList()

	// 随机选择要变异的字段
	switch m.r.Int63n(9) {
	case 0:
		nonce = uint64(m.r.Int63n(1000))
	case 1:
		gasTipCap.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 2:
		gasFeeCap.SetUint64(uint64(m.r.Int63n(1000000000)))
		if gasFeeCap.Cmp(gasTipCap) < 0 {
			gasFeeCap.Add(gasFeeCap, gasTipCap)
		}
	case 3:
		gas = uint64(m.r.Int63n(1000000))
	case 4:
		if m.Bool() {
			addr := common.BytesToAddress(m.RandBytes(20))
			to = &addr
		} else {
			to = nil
		}
	case 5:
		value.SetUint64(uint64(m.r.Int63n(1000000000)))
	case 6:
		data = m.RandBytes(m.r.Int63n(100))
	case 7:
		accessList = m.generateAccessList()
	}

	return types.NewTx(&types.DynamicFeeTx{
		ChainID:    new(big.Int).SetUint64(1),
		Nonce:      nonce,
		GasTipCap:  gasTipCap,
		GasFeeCap:  gasFeeCap,
		Gas:        gas,
		To:         to,
		Value:      value,
		Data:       data,
		AccessList: accessList,
	})
}

func (m *Mutator) mutateBlobTx(original *types.Transaction) *types.Transaction {
	if original == nil || m.Bool() {
		// 创建新交易
		nonce := uint64(m.r.Int63n(1000))
		gasTipCap := uint256.NewInt(uint64(m.r.Int63n(1000000000)))
		gasFeeCap := new(uint256.Int).Add(gasTipCap, uint256.NewInt(uint64(m.r.Int63n(1000000000))))
		gas := uint64(m.r.Int63n(1000000))

		to := common.BytesToAddress(m.RandBytes(20))
		value := uint256.NewInt(uint64(m.r.Int63n(1000000000)))
		data := m.RandBytes(m.r.Int63n(100))

		blobFeeCap := uint256.NewInt(uint64(m.r.Int63n(1000000000)))
		blobHashes := make([]common.Hash, m.r.Int63n(3)+1)
		for i := range blobHashes {
			blobHashes[i] = common.BytesToHash(m.RandBytes(32))
		}

		accessList := m.generateAccessList()

		return types.NewTx(&types.BlobTx{
			ChainID:    uint256.NewInt(1),
			Nonce:      nonce,
			GasTipCap:  gasTipCap,
			GasFeeCap:  gasFeeCap,
			Gas:        gas,
			To:         to,
			Value:      value,
			Data:       data,
			AccessList: accessList,
			BlobFeeCap: blobFeeCap,
			BlobHashes: blobHashes,
		})
	}

	// 基于原始交易进行变异
	if original.Type() != types.BlobTxType {
		return m.mutateBlobTx(nil)
	}

	// 复制原始交易的值
	nonce := original.Nonce()
	gasTipCap := uint256.NewInt(0).SetBytes(original.GasTipCap().Bytes())
	gasFeeCap := uint256.NewInt(0).SetBytes(original.GasFeeCap().Bytes())
	gas := original.Gas()
	to := original.To()
	value := uint256.NewInt(0).SetBytes(original.Value().Bytes())
	data := make([]byte, len(original.Data()))
	copy(data, original.Data())
	accessList := original.AccessList()
	blobFeeCap := uint256.NewInt(0).SetBytes(original.BlobGasFeeCap().Bytes())
	blobHashes := original.BlobHashes()

	// 随机选择要变异的字段
	switch m.r.Int63n(10) {
	case 0:
		nonce = uint64(m.r.Int63n(1000))
	case 1:
		gasTipCap = uint256.NewInt(uint64(m.r.Int63n(1000000000)))
	case 2:
		gasFeeCap = new(uint256.Int).Add(gasTipCap, uint256.NewInt(uint64(m.r.Int63n(1000000000))))
	case 3:
		gas = uint64(m.r.Int63n(1000000))
	case 4:
		to = &common.Address{}
		copy(to[:], m.RandBytes(20))
	case 5:
		value = uint256.NewInt(uint64(m.r.Int63n(1000000000)))
	case 6:
		data = m.RandBytes(m.r.Int63n(100))
	case 7:
		accessList = m.generateAccessList()
	case 8:
		blobFeeCap = uint256.NewInt(uint64(m.r.Int63n(1000000000)))
	case 9:
		blobHashes = make([]common.Hash, m.r.Int63n(3)+1)
		for i := range blobHashes {
			blobHashes[i] = common.BytesToHash(m.RandBytes(32))
		}
	}

	return types.NewTx(&types.BlobTx{
		ChainID:    uint256.NewInt(1),
		Nonce:      nonce,
		GasTipCap:  gasTipCap,
		GasFeeCap:  gasFeeCap,
		Gas:        gas,
		To:         *to,
		Value:      value,
		Data:       data,
		AccessList: accessList,
		BlobFeeCap: blobFeeCap,
		BlobHashes: blobHashes,
	})
}

// RandBytes 生成指定长度的随机字节数组
func (m *Mutator) RandBytes(length int64) []byte {
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = byte(m.r.Int63n(256))
	}
	return bytes
}

// Mutator 中的公共方法
func (m *Mutator) MutateProtocolVersion() uint32 {
	return uint32(m.r.Int31n(68))
}

func (m *Mutator) MutateNetworkID() uint64 {
	return uint64(m.r.Int63n(5))
}

func (m *Mutator) MutateTotalDifficulty() *big.Int {
	return new(big.Int).SetUint64(uint64(m.r.Int63n(1000000)))
}

func (m *Mutator) MutateHash() common.Hash {
	return common.BytesToHash(m.RandBytes(32))
}

func (m *Mutator) MutateForkID() forkid.ID {
	var hash [4]byte
	binary.BigEndian.PutUint32(hash[:], uint32(m.r.Uint64()))

	return forkid.ID{
		Hash: hash,
		Next: uint64(m.r.Int63n(1000000)),
	}
}

// MutatePooledTransactionsRequest 变异交易池请求的哈希列表
func (m *Mutator) MutatePooledTransactionsRequest(request *eth.GetPooledTransactionsRequest, chain *eth.Chain) {
	switch m.Rand(4) {
	case 0:
		// 空列表
		*request = eth.GetPooledTransactionsRequest{}

	case 1:
		// 随机选择1-5个有效哈希
		blocks := chain.Blocks() // 使用区块中的交易
		if len(blocks) == 0 {
			// 如果没有区块，生成随机哈希
			count := m.Rand(5) + 1
			hashes := make(eth.GetPooledTransactionsRequest, count)
			for i := 0; i < count; i++ {
				hashes[i] = m.MutateHash()
			}
			*request = hashes
			return
		}

		count := m.Rand(5) + 1
		hashes := make(eth.GetPooledTransactionsRequest, count)
		for i := 0; i < count; i++ {
			if len(blocks) > 0 {
				block := blocks[m.Rand(len(blocks))]
				txs := block.Transactions()
				if len(txs) > 0 {
					hashes[i] = txs[m.Rand(len(txs))].Hash()
				} else {
					hashes[i] = m.MutateHash()
				}
			}
		}
		*request = hashes

	case 2:
		// 生成1-5个随机哈希
		count := m.Rand(5) + 1
		hashes := make(eth.GetPooledTransactionsRequest, count)
		for i := 0; i < count; i++ {
			hashes[i] = m.MutateHash()
		}
		*request = hashes

	case 3:
		// 混合有效和无效哈希
		blocks := chain.Blocks()
		count := m.Rand(5) + 1
		hashes := make(eth.GetPooledTransactionsRequest, count)
		for i := 0; i < count; i++ {
			if m.Bool() && len(blocks) > 0 {
				block := blocks[m.Rand(len(blocks))]
				txs := block.Transactions()
				if len(txs) > 0 {
					hashes[i] = txs[m.Rand(len(txs))].Hash()
				} else {
					hashes[i] = m.MutateHash()
				}
			} else {
				hashes[i] = m.MutateHash()
			}
		}
		*request = hashes
	}
}

// // MutateSnapRoot 变异 snap 协议中的 Root 字段
// func (m *Mutator) MutateSnapRoot(root *common.Hash, chain *eth.Chain) {
// 	// 参数检查
// 	if root == nil {
// 		return
// 	}

// 	if chain != nil && chain.Len() > 0 {
// 		// 增加安全检查
// 		head := chain.Head()
// 		if head == nil {
// 			*root = m.MutateHash()
// 			return
// 		}

// 		// 确保 blockNum 在有效范围内
// 		maxBlock := int(chain.Len() - 1)
// 		if maxBlock < 0 {
// 			maxBlock = 0
// 		}
// 		blockNum := m.Rand(maxBlock)

// 		// 获取状态根并验证
// 		validRoot := chain.RootAt(blockNum)
// 		if (validRoot != common.Hash{}) { // 确保不是空哈希
// 			*root = validRoot
// 			return
// 		}
// 	}

// 	// 在以下情况使用随机哈希：
// 	// 1. chain 为 nil
// 	// 2. chain.Len() 为 0
// 	// 3. 获取有效状态根失败
// 	*root = m.MutateHash()
// }

// MutateSnapOriginAndLimit 变异 snap 协议中的 Origin 和 Limit 字段
func (m *Mutator) MutateSnapOriginAndLimit(origin, limit *common.Hash) {
	switch m.Rand(3) {
	case 0: // 只变异 Origin
		*origin = m.MutateHash()
	case 1: // 只变异 Limit
		*limit = m.MutateHash()
	case 2: // 同时变异两者
		*origin = m.MutateHash()
		*limit = m.MutateHash()
	}
	// 确保 Origin <= Limit
	if bytes.Compare(origin.Bytes(), limit.Bytes()) > 0 {
		*origin, *limit = *limit, *origin
	}
}

// MutateSnapBytes 变异 snap 协议中的 Bytes 字段
func (m *Mutator) MutateSnapBytes(bytes *uint64) {
	switch m.Rand(3) {
	case 0: // 小值
		*bytes = uint64(m.Rand(256) + 1)
	case 1: // 中等值
		*bytes = uint64(m.Rand(512) + 256)
	case 2: // 较大值
		*bytes = uint64(m.Rand(1024) + 512)
	}
}

// MutateSnapAccounts 变异 snap 协议中的 Accounts 数组
func (m *Mutator) MutateSnapAccounts() []common.Hash {
	// 控制账户数量在合理范围内 (1-128)
	accountCount := m.Rand(128) + 1
	accounts := make([]common.Hash, accountCount)

	for i := 0; i < accountCount; i++ {
		accounts[i] = m.MutateHash()
	}

	return accounts
}

// MutateSnapRequestId 变异请求 ID
func (m *Mutator) MutateSnapRequestId(id *uint64) {
	*id = uint64(m.Rand(1000000))
}

// MutateSnapStorageRangeOriginAndLimit 变异 GetStorageRanges 中的 Origin 和 Limit 字段
func (m *Mutator) MutateSnapStorageRangeOriginAndLimit(origin, limit *[]byte) {
	switch m.Rand(3) {
	case 0: // 只变异 Origin
		*origin = common.Hex2Bytes(m.MutateHash().Hex()[2:]) // 去掉"0x"前缀
	case 1: // 只变异 Limit
		*limit = common.Hex2Bytes(m.MutateHash().Hex()[2:])
	case 2: // 同时变异两者
		*origin = common.Hex2Bytes(m.MutateHash().Hex()[2:])
		*limit = common.Hex2Bytes(m.MutateHash().Hex()[2:])
	}

	// 确保 Origin <= Limit
	if bytes.Compare(*origin, *limit) > 0 {
		*origin, *limit = *limit, *origin
	}
}

// MutateSnapHashes 变异哈希数组
func (m *Mutator) MutateSnapHashes() []common.Hash {
	// 控制哈希数量在合理范围内 (1-64)
	hashCount := m.Rand(64) + 1
	hashes := make([]common.Hash, hashCount)

	for i := 0; i < hashCount; i++ {
		hashes[i] = m.MutateHash()
	}

	return hashes
}

// MutateSnapTrieNodePaths 变异 TrieNodePathSet 数组
func (m *Mutator) MutateSnapTrieNodePaths() []snap.TrieNodePathSet {
	// 控制路径集合的数量在合理范围内 (1-32)
	pathSetCount := m.Rand(32) + 1
	paths := make([]snap.TrieNodePathSet, pathSetCount)

	for i := 0; i < pathSetCount; i++ {
		// 每个路径集合包含 1-4 个路径
		pathCount := m.Rand(4) + 1
		paths[i] = make([][]byte, pathCount)

		for j := 0; j < pathCount; j++ {
			// 每个路径的长度在 1-64 字节之间
			pathLen := m.Rand(64) + 1
			path := make([]byte, pathLen)
			m.FillBytes(&path)
			paths[i][j] = path
		}
	}

	return paths
}

// MutateBlockHashElement 变异区块哈希公告中的随机元素
func (m *Mutator) MutateBlockHashElement(packet *eth.NewBlockHashesPacket) {
	if len(*packet) > 0 {
		idx := m.Rand(len(*packet))
		if m.Bool() {
			// 变异哈希
			(*packet)[idx].Hash = m.MutateHash()
		} else {
			// 变异区块号
			(*packet)[idx].Number = uint64(m.Rand(1000000))
		}
	}
}

// AddBlockHashElement 添加新的区块哈希公告元素
func (m *Mutator) AddBlockHashElement(packet *eth.NewBlockHashesPacket) {
	*packet = append(*packet, struct {
		Hash   common.Hash
		Number uint64
	}{
		Hash:   m.MutateHash(),
		Number: uint64(m.Rand(1000000)),
	})
}

// RemoveBlockHashElement 删除随机的区块哈希公告元素
func (m *Mutator) RemoveBlockHashElement(packet *eth.NewBlockHashesPacket) {
	if len(*packet) > 1 {
		idx := m.Rand(len(*packet))
		*packet = append((*packet)[:idx], (*packet)[idx+1:]...)
	}
}

// MutateBlockHeader 变异区块头
func (m *Mutator) MutateBlockHeader(header *types.Header) {
	if m.Bool() {
		header.ParentHash = m.MutateHash()
	}
	if m.Bool() {
		header.UncleHash = m.MutateHash()
	}
	if m.Bool() {
		header.Coinbase = m.MutateAddress()
	}
	if m.Bool() {
		header.Root = m.MutateHash()
	}
	if m.Bool() {
		header.TxHash = m.MutateHash()
	}
	if m.Bool() {
		header.ReceiptHash = m.MutateHash()
	}
	if m.Bool() {
		header.Number = new(big.Int).SetUint64(uint64(m.Rand(1000000)))
	}
	if m.Bool() {
		header.GasLimit = uint64(m.Rand(1000000))
	}
	if m.Bool() {
		header.GasUsed = uint64(m.Rand(int(header.GasLimit)))
	}
	if m.Bool() {
		header.Time = uint64(m.Rand(1000000))
	}
}

// AddBlockHeader 添加新的区块头
func (m *Mutator) AddBlockHeader(headers *eth.BlockHeadersRequest, chain *eth.Chain) {
	newHeader := &types.Header{
		ParentHash:  m.MutateHash(),
		UncleHash:   m.MutateHash(),
		Coinbase:    m.MutateAddress(),
		Root:        m.MutateHash(),
		TxHash:      m.MutateHash(),
		ReceiptHash: m.MutateHash(),
		Number:      new(big.Int).SetUint64(uint64(m.Rand(1000000))),
		GasLimit:    uint64(m.Rand(1000000)),
		Time:        uint64(m.Rand(1000000)),
	}
	newHeader.GasUsed = uint64(m.Rand(int(newHeader.GasLimit)))
	*headers = append(*headers, newHeader)
}

// RemoveBlockHeader 删除随机的区块头
func (m *Mutator) RemoveBlockHeader(headers *eth.BlockHeadersRequest) {
	if len(*headers) > 1 {
		idx := m.Rand(len(*headers))
		*headers = append((*headers)[:idx], (*headers)[idx+1:]...)
	}
}

// MutateAddress 生成随机的以太坊地址
func (m *Mutator) MutateAddress() common.Address {
	var addr common.Address
	// 以太坊地址是20字节
	addrBytes := make([]byte, common.AddressLength)
	m.MutateBytes(&addrBytes)
	copy(addr[:], addrBytes)
	return addr
}

// MutateBlockBody 变异区块体
func (m *Mutator) MutateBlockBody(body *eth.BlockBody) {
	// 变异交易列表
	if m.Bool() && len(body.Transactions) > 0 {
		// 变异随机交易
		idx := m.Rand(len(body.Transactions))
		body.Transactions[idx] = m.MutateTransaction(body.Transactions[idx])
	}

	// 变异叔块列表
	if m.Bool() && len(body.Uncles) > 0 {
		// 变异随机叔块头
		idx := m.Rand(len(body.Uncles))
		m.MutateBlockHeader(body.Uncles[idx])
	}

	// 变异提款列表（如果存在）
	if m.Bool() && len(body.Withdrawals) > 0 {
		// 变异随机提款
		idx := m.Rand(len(body.Withdrawals))
		m.MutateWithdrawal(body.Withdrawals[idx])
	}
}

// AddBlockBody 添加新的区块体
func (m *Mutator) AddBlockBody(bodies *eth.BlockBodiesResponse) {
	// 创建新的区块体
	newBody := &eth.BlockBody{
		Transactions: make([]*types.Transaction, m.Rand(5)+1), // 1-5个交易
		Uncles:       make([]*types.Header, m.Rand(2)),        // 0-1个叔块
		Withdrawals:  make([]*types.Withdrawal, m.Rand(3)),    // 0-2个提款
	}

	// 填充交易
	for i := range newBody.Transactions {
		newBody.Transactions[i] = m.MutateTransaction(nil)
	}

	// 填充叔块
	for i := range newBody.Uncles {
		uncle := &types.Header{}
		m.MutateBlockHeader(uncle)
		newBody.Uncles[i] = uncle
	}

	// 填充提款
	for i := range newBody.Withdrawals {
		withdrawal := &types.Withdrawal{}
		m.MutateWithdrawal(withdrawal)
		newBody.Withdrawals[i] = withdrawal
	}

	*bodies = append(*bodies, newBody)
}

// RemoveBlockBody 删除随机的区块体
func (m *Mutator) RemoveBlockBody(bodies *eth.BlockBodiesResponse) {
	if len(*bodies) > 1 {
		idx := m.Rand(len(*bodies))
		*bodies = append((*bodies)[:idx], (*bodies)[idx+1:]...)
	}
}

// MutateWithdrawal 变异提款数据
func (m *Mutator) MutateWithdrawal(withdrawal *types.Withdrawal) {
	if m.Bool() {
		withdrawal.Index = uint64(m.Rand(1000000))
	}
	if m.Bool() {
		withdrawal.Validator = uint64(m.Rand(1000000))
	}
	if m.Bool() {
		withdrawal.Address = m.MutateAddress()
	}
	if m.Bool() {
		withdrawal.Amount = uint64(m.Rand(1000000))
	}
}

// MutateNewBlock 变异 NewBlockPacket 中的字段
func (m *Mutator) MutateNewBlock(block *types.Block) {
	if m.Bool() {
		// 变异区块头
		m.MutateBlockHeader(block.Header())
	}
	if m.Bool() {
		// 变异交易列表
		for i := range block.Transactions() {
			block.Transactions()[i] = m.MutateTransaction(block.Transactions()[i])
		}
	}
	if m.Bool() {
		// 变异叔块列表
		for i := range block.Uncles() {
			m.MutateBlockHeader(block.Uncles()[i])
		}
	}
	if m.Bool() {
		// 变异提款列表
		for i := range block.Withdrawals() {
			m.MutateWithdrawal(block.Withdrawals()[i])
		}
	}
}

// MutatePooledTransactionHash 变异交易哈希
func (m *Mutator) MutatePooledTransactionHash(hashes *eth.NewPooledTransactionHashesPacket) {
	if len(hashes.Hashes) > 0 {
		idx := m.Rand(len(hashes.Hashes))
		hashes.Hashes[idx] = m.MutateHash()
	}
}

// AddPooledTransactionHash 添加新的交易哈希
func (m *Mutator) AddPooledTransactionHash(hashes *eth.NewPooledTransactionHashesPacket) {
	hashes.Hashes = append(hashes.Hashes, m.MutateHash())
}

// RemovePooledTransactionHash 删除随机的交易哈希
func (m *Mutator) RemovePooledTransactionHash(hashes *eth.NewPooledTransactionHashesPacket) {
	if len(hashes.Hashes) > 1 {
		idx := m.Rand(len(hashes.Hashes))
		hashes.Hashes = append(hashes.Hashes[:idx], hashes.Hashes[idx+1:]...)
	}
}

// MutatePooledTransaction 变异交易池中的随机交易
func (m *Mutator) MutatePooledTransaction(txs *eth.PooledTransactionsResponse) {
	if len(*txs) > 0 {
		idx := m.Rand(len(*txs))
		(*txs)[idx] = m.MutateTransaction((*txs)[idx])
	}
}

// AddPooledTransaction 添加新的交易到交易池
func (m *Mutator) AddPooledTransaction(txs *eth.PooledTransactionsResponse) {
	newTx := m.MutateTransaction(nil)
	*txs = append(*txs, newTx)
}

// RemovePooledTransaction 从交易池中删除随机交易
func (m *Mutator) RemovePooledTransaction(txs *eth.PooledTransactionsResponse) {
	if len(*txs) > 1 {
		idx := m.Rand(len(*txs))
		*txs = append((*txs)[:idx], (*txs)[idx+1:]...)
	}
}

// MutateReceipt 变异收据中的随机字段
func (m *Mutator) MutateReceipt(receipt *types.Receipt) {
	if m.Bool() {
		receipt.Status = uint64(m.Rand(2)) // 0 或 1
	}
	if m.Bool() {
		receipt.CumulativeGasUsed = uint64(m.Rand(1000000))
	}
	if m.Bool() {
		receipt.Bloom = types.BytesToBloom(m.MutateHash().Bytes())
	}
	if m.Bool() {
		receipt.TxHash = m.MutateHash()
	}
	if m.Bool() {
		receipt.ContractAddress = m.MutateAddress()
	}
	if m.Bool() {
		receipt.GasUsed = uint64(m.Rand(int(receipt.CumulativeGasUsed + 1)))
	}
}

// MutateReceiptResponse 变异收据响应中的随机收据
func (m *Mutator) MutateReceiptResponse(receipts *eth.ReceiptsResponse) {
	if len(*receipts) > 0 {
		idx := m.Rand(len(*receipts))
		m.MutateReceipt((*receipts)[idx][0])
	}
}

// AddReceipt 添加新的收据
func (m *Mutator) AddReceipt(receipts *eth.ReceiptsResponse) {
	newReceipt := &types.Receipt{
		Status:            uint64(m.Rand(2)),
		CumulativeGasUsed: uint64(m.Rand(1000000)),
		Bloom:             types.BytesToBloom(m.MutateHash().Bytes()),
		TxHash:            m.MutateHash(),
		ContractAddress:   m.MutateAddress(),
	}
	newReceipt.GasUsed = uint64(m.Rand(int(newReceipt.CumulativeGasUsed + 1)))
	*receipts = append(*receipts, []*types.Receipt{newReceipt})
}

// RemoveReceipt 删除随机收据
func (m *Mutator) RemoveReceipt(receipts *eth.ReceiptsResponse) {
	if len(*receipts) > 1 {
		idx := m.Rand(len(*receipts))
		*receipts = append((*receipts)[:idx], (*receipts)[idx+1:]...)
	}
}

// MutateAccountData 变异单个账户数据
func (m *Mutator) MutateAccountData(account *snap.AccountData) {
	if m.Bool() {
		account.Hash = m.MutateHash()
	}
	if m.Bool() {
		account.Body = m.MutateRawValue()
	}
}

// MutateAccountProof 变异账户证明
func (m *Mutator) MutateAccountProof(proof *[][]byte) {
	if len(*proof) > 0 {
		// 变异随机证明节点
		idx := m.Rand(len(*proof))
		m.MutateBytes(&(*proof)[idx])
	}
}

// AddAccountData 添加新的账户数据
func (m *Mutator) AddAccountData(accounts *[]*snap.AccountData) {
	newAccount := &snap.AccountData{
		Hash: m.MutateHash(),
		Body: m.MutateRawValue(),
	}
	*accounts = append(*accounts, newAccount)
}

// RemoveAccountData 删除随机账户数据
func (m *Mutator) RemoveAccountData(accounts *[]*snap.AccountData) {
	if len(*accounts) > 1 {
		idx := m.Rand(len(*accounts))
		*accounts = append((*accounts)[:idx], (*accounts)[idx+1:]...)
	}
}

// MutateRawValue 生成随机的 RLP 编码值
func (m *Mutator) MutateRawValue() rlp.RawValue {
	// 生成随机长度的字节数组 (4-128字节)
	length := m.Rand(124) + 4
	value := make([]byte, length)

	// 填充随机字节
	m.FillBytes(&value)

	// 转换为 RLP 编码值
	return rlp.RawValue(value)
}

// MutateStorageData 变异单个存储数据
func (m *Mutator) MutateStorageData(storage *snap.StorageData) {
	if m.Bool() {
		storage.Hash = m.MutateHash()
	}
	if m.Bool() {
		m.MutateBytes(&storage.Body)
	}
}

// MutateStorageSlots 变异存储槽列表中的随机存储槽
func (m *Mutator) MutateStorageSlots(slots *[][]*snap.StorageData) {
	if len(*slots) > 0 {
		accountIdx := m.Rand(len(*slots))
		if len((*slots)[accountIdx]) > 0 {
			slotIdx := m.Rand(len((*slots)[accountIdx]))
			m.MutateStorageData((*slots)[accountIdx][slotIdx])
		}
	}
}

// AddStorageSlot 添加新的存储槽
func (m *Mutator) AddStorageSlot(slots *[][]*snap.StorageData) {
	if len(*slots) > 0 {
		accountIdx := m.Rand(len(*slots))
		newSlot := &snap.StorageData{
			Hash: m.MutateHash(),
			Body: m.MutateRawValue(),
		}
		(*slots)[accountIdx] = append((*slots)[accountIdx], newSlot)
	}
}

// RemoveStorageSlot 删除随机存储槽
func (m *Mutator) RemoveStorageSlot(slots *[][]*snap.StorageData) {
	if len(*slots) > 0 {
		accountIdx := m.Rand(len(*slots))
		if len((*slots)[accountIdx]) > 1 {
			slotIdx := m.Rand(len((*slots)[accountIdx]))
			(*slots)[accountIdx] = append((*slots)[accountIdx][:slotIdx],
				(*slots)[accountIdx][slotIdx+1:]...)
		}
	}
}

// MutateByteCode 变异单个字节码
func (m *Mutator) MutateByteCode(code *[]byte) {
	if len(*code) > 0 {
		// 变异随机字节
		m.MutateBytes(code)
	}
}

// MutateByteCodesResponse 变异字节码响应中的随机字节码
func (m *Mutator) MutateByteCodesResponse(codes *[][]byte) {
	if len(*codes) > 0 {
		idx := m.Rand(len(*codes))
		m.MutateByteCode(&(*codes)[idx])
	}
}

// AddByteCode 添加新的字节码
func (m *Mutator) AddByteCode(codes *[][]byte) {
	// 生成随机长度的新字节码 (32-1024字节)
	length := m.Rand(992) + 32
	newCode := make([]byte, length)
	m.FillBytes(&newCode)
	*codes = append(*codes, newCode)
}

// RemoveByteCode 删除随机字节码
func (m *Mutator) RemoveByteCode(codes *[][]byte) {
	if len(*codes) > 1 {
		idx := m.Rand(len(*codes))
		*codes = append((*codes)[:idx], (*codes)[idx+1:]...)
	}
}

// MutateTrieNode 变异单个Trie节点
func (m *Mutator) MutateTrieNode(node *[]byte) {
	if len(*node) > 0 {
		m.MutateBytes(node)
	}
}

// MutateTrieNodesResponse 变异Trie节点响应中的随机节点
func (m *Mutator) MutateTrieNodesResponse(nodes *[][]byte) {
	if len(*nodes) > 0 {
		idx := m.Rand(len(*nodes))
		m.MutateTrieNode(&(*nodes)[idx])
	}
}

// AddTrieNode 添加新的Trie节点
func (m *Mutator) AddTrieNode(nodes *[][]byte) {
	// 生成随机长度的新节点 (32-532字节)
	length := m.Rand(500) + 32
	newNode := make([]byte, length)
	m.FillBytes(&newNode)
	*nodes = append(*nodes, newNode)
}

// RemoveTrieNode 删除随机Trie节点
func (m *Mutator) RemoveTrieNode(nodes *[][]byte) {
	if len(*nodes) > 1 {
		idx := m.Rand(len(*nodes))
		*nodes = append((*nodes)[:idx], (*nodes)[idx+1:]...)
	}
}

// mutatePacketType 随机选择一个新的消息类型
func MutateV5PacketType() int {
	packetTypes := []int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 254, 255,
	}
	return packetTypes[rand.Intn(len(packetTypes))]
}
