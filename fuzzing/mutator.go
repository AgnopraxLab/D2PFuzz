package fuzzing

import (
	"encoding/binary"
	"github.com/ethereum/go-ethereum/rlp"
	"math/rand"
	"unsafe"
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

func (m *Mutator) rand(n int) int {
	if n <= 0 {
		return 0
	}
	return m.r.Intn(n)
}

func (m *Mutator) bool() bool {
	return m.r.Int()%2 == 0
}

func (m *Mutator) randByteOrder() binary.ByteOrder {
	if m.bool() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// chooseLen chooses length of range mutation in range [1,n]. It gives
// preference to shorter ranges.
func (m *Mutator) chooseLen(n int) int {
	switch x := m.rand(100); {
	case x < 90:
		return m.rand(min(8, n)) + 1
	case x < 99:
		return m.rand(min(32, n)) + 1
	default:
		return m.rand(n) + 1
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
		mut := byteSliceMutators[m.rand(len(byteSliceMutators))]
		if mutated := mut(m, b); mutated != nil {
			b = mutated
			return
		}
	}
}

func (m *Mutator) MutateExp(expiration *uint64) {
	switch rand.Intn(5) {
	case 0:
		// 自减：减去一个随机值或自身的部分值
		*expiration -= uint64(rand.Int63n(int64(*expiration)/2 + 1))
	case 1:
		// 自加：加上一个随机值或自身的部分值
		*expiration += uint64(rand.Int63n(int64(^*expiration)/2 + 1))
	case 2:
		// 自乘：与一个随机系数相乘
		*expiration *= uint64(rand.Intn(10) + 1) // 乘以1到10之间的系数
	case 3:
		// 取反：按位取反操作
		*expiration = ^*expiration
	case 4:
		// 边界值测试
		if rand.Intn(2) == 0 {
			*expiration = 0
		} else {
			*expiration = ^uint64(0) // uint64 的最大值
		}
	}
}

func (m *Mutator) MutateRest(rest *[]rlp.RawValue) {
	// 如果 Rest 为空，先插入初始值
	if len(*rest) == 0 {
		initialValue := rlp.RawValue{byte(rand.Intn(256))}
		*rest = append(*rest, initialValue)
	}

	// 对 Rest 中的每个 RawValue 进行变异
	for i := range *rest {
		if len((*rest)[i]) > 0 {
			switch rand.Intn(5) {
			case 0:
				// 随机字节替换
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i][pos] = byte(rand.Intn(256))
			case 1:
				// 字节翻转
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i][pos] ^= 0xFF
			case 2:
				// 插入随机字节
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i] = append((*rest)[i][:pos], append([]byte{byte(rand.Intn(256))}, (*rest)[i][pos:]...)...)
			case 3:
				// 删除字节
				pos := rand.Intn(len((*rest)[i]))
				(*rest)[i] = append((*rest)[i][:pos], (*rest)[i][pos+1:]...)
			case 4:
				// 重复部分内容
				start := rand.Intn(len((*rest)[i]))
				end := start + rand.Intn(len((*rest)[i])-start)
				(*rest)[i] = append((*rest)[i][:end], append((*rest)[i][start:end], (*rest)[i][end:]...)...)
			}
		}
	}
}
