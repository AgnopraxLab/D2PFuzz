package discv4

import (
	"D2PFuzz/fuzzing"
	"math/rand"
)

func (seed *V4Seed) PacketMutate(packets []Packet, mut *fuzzing.Mutator) {
	for _, pkt := range packets {
		pkt.mutate(mut)
	}
}

func (seed *V4Seed) SeriesMutate(packets []Packet, mut *fuzzing.Mutator) {
	// 随机打乱Packet的顺序
	rand.Shuffle(len(packets), func(i, j int) { packets[i], packets[j] = packets[j], packets[i] })
}

func (seed *V4Seed) HavocMutate(packets []Packet, mut *fuzzing.Mutator) {
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
