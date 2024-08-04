package common

import (
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/stretchr/testify/assert"
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

	_, err := discv4Generator(packetType, count, nodeList, true)
	assert.NoError(t, err, "Discv4Generator should not return error")
	// Add additional assertions as needed
}

func TestDiscv5Generator(t *testing.T) {
	// Replace with your test data and assertions
	packetType := "ping"
	count := 1
	nodeList := []*enode.Node{
		// Replace with mock nodes or load from test file
		enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303?discport=30304"),
	}

	encodedPackets, err := discv5Generator(packetType, count, nodeList, true)
	assert.NoError(t, err, "Discv4Generator should not return error")
	assert.Equal(t, count, len(encodedPackets), "Should generate correct number of packets")
	// Add additional assertions as needed
}

func TestEthGenerator(t *testing.T) {
	// 准备测试数据
	dir := "/tmp/ethtest" //这个如何设置
	packetType := 1
	count := 3 // 生成 3 个包
	nodeList := []*enode.Node{
		// 替换为模拟节点或从测试文件加载
		enode.MustParse("enode://ba85011c70bcc5c04d8607d3a0ed29aa6179c092cbdda10d5d32684fb33ed01bd94f588ca8f91ac48318087dcb02eaf36773a7a453f0eedd6742af668097b29c@10.0.1.16:30303"),
	}
	genTestFlag := true

	// 调用 ethGenerator 函数
	err := ethGenerator(dir, packetType, count, nodeList, genTestFlag)

	// 注：ethGenerator 函数直接打印包而不是返回它们，

	assert.NoError(t, err, "测试成功")
}
