package discv4

import (
	"github.com/ethereum/go-ethereum/rlp"
	"math/rand"
)

func (seed *V4Seed) PacketMutate(packets []Packet) {
	for _, pkt := range packets {
		pkt.mutate()
	}
}

func (seed *V4Seed) SeriesMutate(packets []Packet) {
	// 随机打乱Packet的顺序
	rand.Shuffle(len(packets), func(i, j int) { packets[i], packets[j] = packets[j], packets[i] })
}

func (seed *V4Seed) HavocMutate(packets []Packet) {
	switch rand.Intn(2) {
	case 0:
		// 随机重复一个数据包
		idx := rand.Intn(len(packets))
		packets = append(packets, packets[idx])
	case 1:
		// 随机重复多个数据包
		count := rand.Intn(len(packets)) + 1
		for i := 0; i < count; i++ {
			idx := rand.Intn(len(packets))
			packets = append(packets, packets[idx])
		}
	}
}

func mutateRest(rest *[]rlp.RawValue) {
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

func mutateExp(expiration *uint64) {
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
