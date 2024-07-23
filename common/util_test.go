package common

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestGetList(t *testing.T) {

	nodes, err := GetList("../test/enode.txt")
	if err != nil {
		t.Fatalf("GetList returned an error: %v", err)
	}

	println(len(nodes))
}

func TestDiscv4Generator(t *testing.T) {
	// Replace with your test data and assertions
	packetType := "ping"
	count := 1
	nodeList := []*enode.Node{
		// Replace with mock nodes or load from test file
		enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303?discport=30304"),
	}

	encodedPackets, hashes, err := discv4Generator(packetType, count, nodeList)
	assert.NoError(t, err, "Discv4Generator should not return error")
	assert.Equal(t, count, len(encodedPackets), "Should generate correct number of packets")
	assert.Equal(t, count, len(hashes), "Should generate correct number of hashes")
	// Add additional assertions as needed
}

func TestDiscv5Generator(t *testing.T) {
	// Replace with your test data and assertions
	packetType := "whoareyou"
	count := 1
	nodeList := []*enode.Node{
		// Replace with mock nodes or load from test file
		enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303?discport=30304"),
	}

	encodedPackets, nonces, err := discv5Generator(packetType, count, nodeList)
	assert.NoError(t, err, "Discv4Generator should not return error")
	assert.Equal(t, count, len(encodedPackets), "Should generate correct number of packets")
	assert.Equal(t, count, len(nonces), "Should generate correct number of hashes")
	// Add additional assertions as needed
}

func TestDiscv5Decode(t *testing.T) {
	// 预定义的 WHOAREYOU 数据包（这是一个示例，你需要替换为实际的数据包）
	encodedPacket, _ := hex.DecodeString("0ccf2c0ba0cef87009a89d85ebf493e20d8d71e5373755ad778e9d0426ff190371d4f9ee39ed1acd1b7d2adf490e65758e6f45588719eb24e22fb846c79e2f")

	// 预定义的节点信息
	node := enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303?discport=30304")

	fromAddr := &net.UDPAddr{IP: node.IP(), Port: node.UDP()}

	fromID, fromNode, decodedPacket, err := decodeDiscv5Packet(encodedPacket, fromAddr)

	assert.NoError(t, err, "Packet decoding should not return error")
	assert.NotNil(t, decodedPacket, "Decoded packet should not be nil")

	// 验证包类型
	whoareyou, ok := decodedPacket.(*v5wire.Whoareyou)
	assert.True(t, ok, "Decoded packet should be of type Whoareyou")

	// 验证包内容
	if ok {
		t.Logf("Decoded WHOAREYOU packet: %+v", whoareyou)
		assert.Equal(t, node.ID(), fromID, "From ID should match")

		// 验证 Nonce（这里使用一个假设的值，你需要替换为实际的预期值）
		expectedNonce := [12]byte{}
		assert.Equal(t, expectedNonce[:], whoareyou.Nonce[:], "Nonce should match")

		assert.Equal(t, uint64(1721275398453), whoareyou.RecordSeq, "RecordSeq should match")

		// 验证 fromNode
		if fromNode != nil {
			assert.Equal(t, node.IP(), fromNode.IP(), "IP should match")
			assert.Equal(t, node.UDP(), fromNode.UDP(), "UDP port should match")
		}
	}
}
