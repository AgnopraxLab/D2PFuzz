package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v2"
)

// lLogger 实际使用的日志实现
// MockLogger is a mock implementation of Logger interface for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.Called(msg, args)
}

// Config 配置结构体
type Config struct {
	P2P struct {
		MaxPeers       int      `yaml:"max_peers"`
		ListenPort     int      `yaml:"listen_port"`
		BootstrapNodes []string `yaml:"bootstrap_nodes"`
	} `yaml:"p2p"`
}

type Hello struct {
	Version uint64
	Name    string
	Caps    []struct {
		Name    string
		Version uint
	}
	ListenPort uint64
	ID         []byte
}

func main() {
	// mockLogger := &MockLogger{}
	// 创建peer
	fmt.Println("=== 使用配置文件中的enode创建Peer对象示例 ===")

	// 1. 读取配置文件
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		return
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		fmt.Printf("解析配置文件失败: %v\n", err)
		return
	}

	// 2. 从配置文件中获取第一个enode
	if len(config.P2P.BootstrapNodes) == 0 {
		fmt.Println("配置文件中没有找到bootstrap节点")
		return
	}

	enodeURL := config.P2P.BootstrapNodes[0]
	fmt.Printf("使用的enode URL: %s\n", enodeURL)

	// 3. 解析enode URL
	node, err := enode.Parse(enode.ValidSchemes, enodeURL)
	if err != nil {
		fmt.Printf("解析enode URL失败: %v\n", err)
		return
	}

	nodeID := node.ID()
	fmt.Printf("解析的节点ID: %s\n", nodeID.String())

	// rlpxPing
	hello, data, err := rlpxPing(node)
	if hello == nil || err != nil {
		fmt.Printf("hello信息发送失败: %v\n", err)
		return
	}
	fmt.Println("\n=== RLPx Ping 成功！===")
	fmt.Printf("协议版本: %d\n", hello.Version)
	fmt.Printf("节点名称: %s\n", hello.Name)
	fmt.Printf("监听端口: %d\n", hello.ListenPort)
	fmt.Printf("节点ID: %s\n", hex.EncodeToString(hello.ID))
	fmt.Println("支持的协议:")
	for _, cap := range hello.Caps {
		fmt.Printf("  - %s/%d\n", cap.Name, cap.Version)
	}
	fmt.Printf("\n原始数据 (hex): %s\n", hex.EncodeToString(data))
	fmt.Printf("数据长度: %d 字节\n", len(data))

	// 建立 TCP 连接

	// RLPx 握手

	// 协议握手

	// 4. 定义节点能力（支持的协议）
	// caps := hello.Caps

	// // 5. 创建Peer对象，使用从enode解析出的信息
	// nodeName := fmt.Sprintf("node-%s", nodeID.String()[:8])
	// peer := p2p.NewPeer(nodeID, nodeName, caps)
	// fmt.Printf("创建的Peer对象: %s\n", peer.String())

	// // 6. 显示Peer信息
	// fmt.Printf("节点名称: %s\n", peer.Name())
	// fmt.Printf("完整名称: %s\n", peer.Fullname())
	// fmt.Printf("节点ID: %s\n", peer.ID().String())
	// fmt.Printf("节点IP地址: %s\n", node.IP().String())
	// fmt.Printf("节点端口: %d\n", node.TCP())
	// fmt.Printf("支持的协议: %v\n", peer.Caps())

	// // 5. 检查协议支持
	// if peer.RunningCap("eth", []uint{68}) {
	// 	fmt.Println("✓ 支持 ETH 协议版本 68")
	// } else {
	// 	fmt.Println("✗ 不支持 ETH 协议版本 68")
	// }

	// if peer.RunningCap("snap", []uint{1}) {
	// 	fmt.Println("✓ 支持 SNAP 协议版本 1")
	// } else {
	// 	fmt.Println("✗ 不支持 SNAP 协议版本 1")
	// }

	// fmt.Println("\n=== Peer 对象创建完成 ===")
}

func CreateRLPxConnection(node *enode.Node) (*rlpx.Conn, error) {
	tcpEndpoint, ok := node.TCPEndpoint()
	if !ok {
		err := errors.New("node has no TCP endpoint")
		return nil, err
	}
	fd, err := net.Dial("tcp", tcpEndpoint.String())
	if err != nil {
		return nil, err
	}
	conn := rlpx.NewConn(fd, node.Pubkey())
	return conn, err
}

func rlpxPing(n *enode.Node) (*Hello, []byte, error) {

	conn, err := CreateRLPxConnection(n)

	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			fmt.Printf("关闭连接时出错: %v\n", closeErr)
		}
	}()

	ourKey, _ := crypto.GenerateKey()

	publicKey, err := conn.Handshake(ourKey)
	// 格式化密钥输出
	fmt.Printf("私钥: %s\n", hex.EncodeToString(crypto.FromECDSA(ourKey)))
	fmt.Printf("公钥: %s\n", hex.EncodeToString(crypto.FromECDSAPub(publicKey)))
	if err != nil {
		return nil, nil, err
	}
	// handshake 之后第一条数据一定是 Hello 消息
	code, data, _, err := conn.Read()
	if err != nil {
		return nil, nil, err
	}
	switch code {
	case 0:
		var hello Hello
		if err := rlp.DecodeBytes(data, &hello); err != nil {
			return nil, data, fmt.Errorf("invalid handshake: %v", err)
		}
		return &hello, data, nil
	case 1:
		var msg []p2p.DiscReason
		if rlp.DecodeBytes(data, &msg); len(msg) == 0 {
			return nil, data, errors.New("invalid disconnect message")
		}
		return nil, data, fmt.Errorf("received disconnect message: %v", msg[0])
	default:
		return nil, data, fmt.Errorf("invalid message code %d, expected handshake (code zero) or disconnect (code one)", code)
	}
}
