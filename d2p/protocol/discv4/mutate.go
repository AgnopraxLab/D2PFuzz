package discv4

import "math/rand"

func (seed *V4Seed) packetMutate(packets []Packet) {
	for i := range packets {
		// 根据 Packet 的类型来变异不同字段
		switch p := packets[i].(type) {
		case *Ping:
			p.Version = uint(rand.Intn(100))
			p.Expiration = uint64(rand.Int63n(1<<63 - 1))
		case *Pong:
			p.Expiration = uint64(rand.Int63n(1<<63 - 1))
			p.ReplyTok = []byte{byte(rand.Intn(256))}
		case *Findnode:
			p.Expiration = uint64(rand.Int63n(1<<63 - 1))
		case *Neighbors:
			p.Expiration = uint64(rand.Int63n(1<<63 - 1))
		case *ENRRequest:
			p.Expiration = uint64(rand.Int63n(1<<63 - 1))
		case *ENRResponse:
			p.ReplyTok = []byte{byte(rand.Intn(256))}
		}
	}
}

func (seed *V4Seed) seriesMutate(packets []Packet) {
	// 随机打乱Packet的顺序
	rand.Shuffle(len(packets), func(i, j int) { packets[i], packets[j] = packets[j], packets[i] })
}

func (seed *V4Seed) havocMutate(packets []Packet) {
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
