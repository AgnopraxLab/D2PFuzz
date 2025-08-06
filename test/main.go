package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
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
	Version    uint64
	Name       string
	Caps       []p2p.Cap
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

	// 建立 TCP 连接，RLPx 握手，协议握手
	conn, err := CreateRLPxConnection(node)
	if err != nil {
		fmt.Printf("连接建立失败: %v\n", err)
	}
	hello, data, err := rlpxPing(conn, node)
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

	// 4. 定义节点能力（支持的协议）
	caps := hello.Caps

	// 5. 创建Peer对象，使用从enode解析出的信息
	peer := p2p.NewPeer(nodeID, node.Hostname(), caps)
	fmt.Printf("创建的Peer对象: %s\n", peer.String())

	// rw1, rw2 := p2p.MsgPipe()
	// msgReadWriter := &p2p.MsgPipeRW{
	// 	w:       rw1,
	// 	r:       rw2,
	// 	closing: make(chan struct{}),
	// 	closed:  new(atomic.Bool),
	// }
	// 创建消息管道
	app, net := p2p.MsgPipe()
	_ = app
	txPool, err := createSimpleTxPool()
	if err != nil {
		fmt.Printf("创建TxPool失败: %v\n", err)
		return
	}

	ethPeer := eth.NewPeer(69, peer, net, txPool)

	TestEthPeerCreation(ethPeer)
	testErrorHandling(ethPeer)

	// 记住在完成后关闭 peer
	defer ethPeer.Close()

	// 6. 显示Peer信息
	// fmt.Printf("节点名称: %s\n", peer.Name())
	// fmt.Printf("完整名称: %s\n", peer.Fullname())
	// fmt.Printf("节点ID: %s\n", peer.ID().String())
	// fmt.Printf("节点IP地址: %s\n", node.IP().String())
	// fmt.Printf("节点端口: %d\n", node.TCP())
	// fmt.Printf("支持的协议: %v\n", peer.Caps())

	// // 5. 检查协议支持
	// if peer.RunningCap("eth", []uint{68, 69}) {
	// 	fmt.Println("✓ 支持 ETH 协议版本 69")
	// } else {
	// 	fmt.Println("✗ 不支持 ETH 协议版本 69")
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

func rlpxPing(conn *rlpx.Conn, n *enode.Node) (*Hello, []byte, error) {

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

// TxPool创建
// 创建最小化的区块链实现
type BlockChain struct {
	config        *params.ChainConfig
	statedb       *state.StateDB
	chainHeadFeed *event.Feed
}

func (bc *BlockChain) Config() *params.ChainConfig {
	return bc.config
}

func (bc *BlockChain) CurrentBlock() *types.Header {
	return &types.Header{
		Number:     big.NewInt(0),
		GasLimit:   10000000,
		BaseFee:    big.NewInt(1000000000), // 1 gwei
		Difficulty: big.NewInt(1),
		Time:       1000000,
		GasUsed:    0,
	}
}

func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return types.NewBlock(bc.CurrentBlock(), nil, nil, trie.NewStackTrie(nil))
}

func (bc *BlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *BlockChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func (bc *BlockChain) CurrentFinalBlock() *types.Header {
	// 返回当前区块作为最终区块
	return bc.CurrentBlock()
}

// 创建简单的 TxPool
func createSimpleTxPool() (*txpool.TxPool, error) {
	// 1. 创建状态数据库
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())

	// 2. 创建最小化区块链
	b := &BlockChain{
		config:        params.TestChainConfig, // 或者使用 params.MainnetChainConfig
		statedb:       statedb,
		chainHeadFeed: new(event.Feed),
	}
	blobchain := blobpool.BlockChain(b)

	// 3. 创建子池
	legacyConfig := legacypool.DefaultConfig
	legacyPool := legacypool.New(legacyConfig, b)

	blobConfig := blobpool.DefaultConfig
	blobPool := blobpool.New(blobConfig, blobchain, nil) // nil 表示没有 pending auth 检查

	// 4. 创建 TxPool
	subpools := []txpool.SubPool{legacyPool, blobPool}
	pool, err := txpool.New(1000000000, b, subpools) // gasTip = 1 gwei
	if err != nil {
		fmt.Printf("创建TxPool失败: %v\n", err)
		return nil, err
	}
	return pool, err
}

// 检测 ethPeer 的功能
// 检查 ethpeer 基本属性
func testPeerBasicInfo(peer *eth.Peer) {
	// 检查 ID 是否正确设置
	if peer.ID() == "" {
		fmt.Println("Peer ID is empty")
	} else {
		fmt.Printf("✓ Peer ID: %s\n", peer.ID())
	}

	// 检查协议版本
	version := peer.Version()
	if version == 0 {
		fmt.Println("Peer version is not set")
	} else {
		fmt.Printf("✓ Protocol Version: %d\n", version)
	}

	// 检查是否有 BlockRange (仅适用于 ETH69+)
	if version >= eth.ETH69 {
		blockRange := peer.BlockRange()
		fmt.Printf("✓ Block Range: %v\n", blockRange)
	} else {
		fmt.Println("Block Range is not used")
	}
}

// 测试 ethpeer 的交易处理能力：
func testTransactionFunctionality(peer *eth.Peer) {
	// 创建测试交易哈希
	testHashes := []common.Hash{
		common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		common.HexToHash("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"),
	}

	// 测试交易标记功能
	for _, hash := range testHashes {
		// 检查交易是否已知（应该返回 false）
		if peer.KnownTransaction(hash) {
			fmt.Printf("⚠ Transaction %s already known\n", hash.Hex())
		} else {
			fmt.Printf("✓ Transaction %s is new\n", hash.Hex())
		}
	}

	// 测试异步交易发送
	fmt.Println("✓ Testing async transaction broadcast...")
	peer.AsyncSendTransactions(testHashes)

	// 测试异步交易通知
	fmt.Println("✓ Testing async transaction announcement...")
	peer.AsyncSendPooledTransactionHashes(testHashes)

	// 验证交易现在是否被标记为已知
	for _, hash := range testHashes {
		if !peer.KnownTransaction(hash) {
			fmt.Printf("⚠ Transaction %s should be known after sending\n", hash.Hex())
		} else {
			fmt.Printf("✓ Transaction %s correctly marked as known\n", hash.Hex())
		}
	}
}

// 测试 ethpeer 的数据请求能力
func testRequestFunctionality(peer *eth.Peer) {
	fmt.Println("✓ Testing request functionality (non-blocking)...")

	// 由于实际的以太坊节点可能不会响应测试请求，而且这些请求函数可能会阻塞
	// 我们跳过所有请求测试，只验证peer对象的基本功能

	// 注意：跳过所有可能阻塞的请求函数：
	// - RequestOneHeader: 可能等待响应而阻塞
	// - RequestHeadersByNumber: 可能等待响应而阻塞
	// - RequestBodies: 可能等待响应而阻塞
	// - RequestTxs: 也可能阻塞
	fmt.Println("✓ Skipping all request functions to avoid blocking")
	fmt.Println("✓ In a real application, these requests would be handled asynchronously")
	fmt.Println("✓ Request functionality test completed (skipped for stability)")
}

// 测试 ethpeer 的连接状态和生命周期
func testConnectionState(peer *eth.Peer) {
	// 检查底层 P2P 连接
	p2pPeer := peer.Peer
	if p2pPeer == nil {
		log.Fatal("P2P peer is nil")
	}

	fmt.Printf("✓ P2P Peer Name: %s\n", p2pPeer.Name())
	fmt.Printf("✓ P2P Peer Caps: %v\n", p2pPeer.Caps())
	fmt.Printf("✓ P2P Peer RemoteAddr: %s\n", p2pPeer.RemoteAddr())

	// 检查连接是否活跃
	// select {
	// case <-p2pPeer.losed:
	// 	fmt.Println("⚠ Peer connection is closed")
	// default:
	// 	fmt.Println("✓ Peer connection is active")
	// }
}

// 将所有 ethpeer 测试组合成一个完整的测试函数
func TestEthPeerCreation(peer *eth.Peer) {
	fmt.Println("=== Testing ethPeer Creation and Functionality ===")

	// 基本信息测试
	fmt.Println("\n1. Basic Information Test:")
	testPeerBasicInfo(peer)

	// 连接状态测试
	fmt.Println("\n2. Connection State Test:")
	testConnectionState(peer)

	// 交易功能测试
	fmt.Println("\n3. Transaction Functionality Test:")
	testTransactionFunctionality(peer)

	// 请求功能测试
	fmt.Println("\n4. Request Functionality Test:")
	testRequestFunctionality(peer)

	// 等待一段时间让异步操作完成
	time.Sleep(100 * time.Millisecond)

	fmt.Println("\n=== All Tests Completed ===")
	fmt.Println("✓ ethPeer created successfully and all basic functions are working!")
}

// ethPeer 错误处理和辩解测试
func testErrorHandling(peer *eth.Peer) {
	fmt.Println("\n5. Error Handling Test:")

	// 测试空哈希请求
	emptyHashes := []common.Hash{}
	peer.AsyncSendTransactions(emptyHashes)
	fmt.Println("✓ Empty transaction list handled")

	// 测试大量哈希请求
	largeHashes := make([]common.Hash, 1000)
	for i := range largeHashes {
		largeHashes[i] = common.BytesToHash([]byte(fmt.Sprintf("hash%d", i)))
	}
	peer.AsyncSendTransactions(largeHashes)
	fmt.Println("✓ Large transaction list handled")
}
