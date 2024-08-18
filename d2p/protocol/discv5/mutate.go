package discv5

import "math/rand"

func (seed *V5Seed) PacketMutate(packets []Packet) {
	for _, pkt := range packets {
		pkt.mutate()
	}
}

func (seed *V5Seed) SeriesMutate(packets []Packet) {
	// 随机打乱Packet的顺序
	rand.Shuffle(len(packets), func(i, j int) { packets[i], packets[j] = packets[j], packets[i] })
}

func (seed *V5Seed) HavocMutate(packets []Packet) {
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
