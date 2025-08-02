package main

import (
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
	"D2PFuzz/p2p"
)

// ExampleLogger 实现Logger接口用于示例
type ExampleLogger struct{}

func (l *ExampleLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

func (l *ExampleLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

func (l *ExampleLogger) Debug(msg string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+msg+"\n", args...)
}

func main() {
	fmt.Println("=== D2PFuzz 完整示例演示 ===")
	fmt.Println("本示例将展示从创建连接到发送接收各种协议消息的完整流程")
	fmt.Println()

	// 1. 初始化配置和日志
	fmt.Println("步骤 1: 初始化配置和日志系统")
	logger := &ExampleLogger{}
	
	// 创建P2P配置
	p2pConfig := &p2p.Config{
		MaxPeers:   10,
		ListenPort: 30303,
		BootstrapNodes: []string{
			"enode://example@127.0.0.1:30304", // 示例节点
		},
	}

	fmt.Printf("✓ P2P配置创建完成 - 最大连接数: %d, 监听端口: %d\n", p2pConfig.MaxPeers, p2pConfig.ListenPort)
	fmt.Println()

	// 2. 创建P2P管理器
	fmt.Println("步骤 2: 创建P2P管理器")
	manager, err := p2p.NewManager(p2pConfig, logger)
	if err != nil {
		log.Fatalf("创建P2P管理器失败: %v", err)
	}
	fmt.Println("✓ P2P管理器创建成功")
	fmt.Println()

	// 3. 启动P2P管理器
	fmt.Println("步骤 3: 启动P2P管理器")
	err = manager.Start()
	if err != nil {
		log.Fatalf("启动P2P管理器失败: %v", err)
	}
	fmt.Println("✓ P2P管理器启动成功")
	defer manager.Stop()
	fmt.Println()

	// 4. 创建模拟的对等节点连接
	fmt.Println("步骤 4: 模拟连接到对等节点")
	// 注意：在实际环境中，这里应该是真实的以太坊节点URL
	// 这里我们模拟连接过程
	testNodeURL := "enode://test@127.0.0.1:30304"
	fmt.Printf("尝试连接到节点: %s\n", testNodeURL)
	
	// 由于这是示例，我们模拟连接成功
	fmt.Println("✓ 模拟连接成功 (在实际环境中需要真实的以太坊节点)")
	fmt.Println()

	// 5. 演示ETH协议消息构造和发送
	fmt.Println("步骤 5: 演示ETH协议消息")
	demonstrateEthProtocol(manager, logger)
	fmt.Println()

	// 6. 演示SNAP协议消息构造和发送
	fmt.Println("步骤 6: 演示SNAP协议消息")
	demonstrateSnapProtocol(manager, logger)
	fmt.Println()

	// 7. 演示消息接收处理
	fmt.Println("步骤 7: 演示消息接收处理")
	demonstrateMessageReceiving(manager, logger)
	fmt.Println()

	// 8. 显示统计信息
	fmt.Println("步骤 8: 显示连接和消息统计")
	stats := manager.GetFuzzingStats()
	fmt.Printf("总连接数: %d\n", stats.TotalConnections)
	fmt.Printf("活跃连接数: %d\n", stats.ActiveConnections)
	fmt.Printf("已发送消息数: %d\n", stats.MessagesSent)
	fmt.Printf("已接收消息数: %d\n", stats.MessagesReceived)
	fmt.Printf("遇到错误数: %d\n", stats.ErrorsEncountered)
	fmt.Printf("运行时间: %v\n", stats.Uptime)
	fmt.Printf("支持的协议: %v\n", stats.ProtocolsSupported)
	fmt.Println()

	fmt.Println("=== 示例演示完成 ===")
	fmt.Println("注意: 这是一个演示示例，在实际使用中需要连接到真实的以太坊节点")
}

// demonstrateEthProtocol 演示ETH协议的各种消息类型
func demonstrateEthProtocol(manager *p2p.Manager, logger fuzzer.Logger) {
	fmt.Println("--- ETH协议消息演示 ---")
	
	// 创建ETH协议处理器
	client, _ := fuzzer.NewFuzzClient(logger)
	ethHandler := p2p.NewEthProtocolHandler(client, logger)
	
	// 模拟对等节点ID
	mockPeerID := enode.ID{1, 2, 3, 4} // 简化的对等节点ID
	
	// 1. Status消息
	fmt.Println("1. 构造Status消息")
	statusMsg := ethHandler.CreateFuzzedStatusMessage()
	fmt.Printf("   协议版本: %d\n", statusMsg.ProtocolVersion)
	fmt.Printf("   网络ID: %d\n", statusMsg.NetworkID)
	fmt.Printf("   最佳区块哈希: %s\n", statusMsg.BestHash.Hex())
	fmt.Printf("   创世区块哈希: %s\n", statusMsg.GenesisHash.Hex())
	
	// 模拟发送Status消息
	fmt.Println("   → 发送Status消息到对等节点")
	err := ethHandler.SendStatus(mockPeerID, statusMsg)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ Status消息发送成功")
	}
	
	// 2. 交易消息
	fmt.Println("\n2. 构造交易消息")
	txs := ethHandler.CreateFuzzedTransactions(3)
	fmt.Printf("   生成了 %d 个模糊测试交易\n", len(txs))
	for i, tx := range txs {
		fmt.Printf("   交易 %d: 哈希=%s, Gas=%d\n", i+1, tx.Hash().Hex(), tx.Gas())
	}
	
	// 模拟发送交易消息
	fmt.Println("   → 发送交易消息到对等节点")
	err = ethHandler.SendTransactions(mockPeerID, txs)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 交易消息发送成功")
	}
	
	// 3. 区块头请求
	fmt.Println("\n3. 构造区块头请求")
	headerQuery := &p2p.GetBlockHeadersData{
		Origin: p2p.HashOrNumber{
			Number: 1000, // 请求从区块1000开始
		},
		Amount:  10,   // 请求10个区块头
		Skip:    0,    // 不跳过
		Reverse: false, // 正向查询
	}
	fmt.Printf("   请求起始区块: %d\n", headerQuery.Origin.Number)
	fmt.Printf("   请求数量: %d\n", headerQuery.Amount)
	fmt.Printf("   跳过数量: %d\n", headerQuery.Skip)
	fmt.Printf("   是否反向: %t\n", headerQuery.Reverse)
	
	// 模拟发送区块头请求
	fmt.Println("   → 发送区块头请求到对等节点")
	err = ethHandler.RequestBlockHeaders(mockPeerID, headerQuery)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 区块头请求发送成功")
	}
	
	// 4. 新区块公告
	fmt.Println("\n4. 构造新区块公告")
	newBlockHashes := p2p.NewBlockHashesData{
		{
			Hash:   common.HexToHash("0x1234567890abcdef"),
			Number: 1001,
		},
		{
			Hash:   common.HexToHash("0xfedcba0987654321"),
			Number: 1002,
		},
	}
	fmt.Printf("   公告 %d 个新区块\n", len(newBlockHashes))
	for i, blockHash := range newBlockHashes {
		fmt.Printf("   区块 %d: 哈希=%s, 高度=%d\n", i+1, blockHash.Hash.Hex(), blockHash.Number)
	}
	
	// 模拟发送新区块公告
	fmt.Println("   → 发送新区块公告到对等节点")
	err = ethHandler.SendNewBlockHashes(mockPeerID, newBlockHashes)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 新区块公告发送成功")
	}
}

// demonstrateSnapProtocol 演示SNAP协议的各种消息类型
func demonstrateSnapProtocol(manager *p2p.Manager, logger fuzzer.Logger) {
	fmt.Println("--- SNAP协议消息演示 ---")
	
	// 创建SNAP协议处理器
	client, _ := fuzzer.NewFuzzClient(logger)
	snapHandler := p2p.NewSnapProtocolHandler(client, logger)
	
	// 模拟对等节点ID
	mockPeerID := enode.ID{5, 6, 7, 8} // 简化的对等节点ID
	
	// 1. 账户范围请求
	fmt.Println("1. 构造账户范围请求")
	accountRangeReq := snapHandler.CreateFuzzedAccountRangeRequest(1)
	fmt.Printf("   请求ID: %d\n", accountRangeReq.ID)
	fmt.Printf("   根哈希: %s\n", accountRangeReq.Root.Hex())
	fmt.Printf("   起始哈希: %s\n", accountRangeReq.Origin.Hex())
	fmt.Printf("   限制哈希: %s\n", accountRangeReq.Limit.Hex())
	fmt.Printf("   字节限制: %d\n", accountRangeReq.Bytes)
	
	// 模拟发送账户范围请求
	fmt.Println("   → 发送账户范围请求到对等节点")
	err := snapHandler.RequestAccountRange(mockPeerID, accountRangeReq)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 账户范围请求发送成功")
	}
	
	// 2. 存储范围请求
	fmt.Println("\n2. 构造存储范围请求")
	storageRangeReq := snapHandler.CreateFuzzedStorageRangesRequest(2)
	fmt.Printf("   请求ID: %d\n", storageRangeReq.ID)
	fmt.Printf("   根哈希: %s\n", storageRangeReq.Root.Hex())
	fmt.Printf("   账户数量: %d\n", len(storageRangeReq.Accounts))
	fmt.Printf("   起始哈希: %s\n", storageRangeReq.Origin.Hex())
	fmt.Printf("   限制哈希: %s\n", storageRangeReq.Limit.Hex())
	fmt.Printf("   字节限制: %d\n", storageRangeReq.Bytes)
	
	// 模拟发送存储范围请求
	fmt.Println("   → 发送存储范围请求到对等节点")
	err = snapHandler.RequestStorageRanges(mockPeerID, storageRangeReq)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 存储范围请求发送成功")
	}
	
	// 3. 字节码请求
	fmt.Println("\n3. 构造字节码请求")
	byteCodeReq := snapHandler.CreateFuzzedByteCodesRequest(3)
	fmt.Printf("   请求ID: %d\n", byteCodeReq.ID)
	fmt.Printf("   哈希数量: %d\n", len(byteCodeReq.Hashes))
	fmt.Printf("   字节限制: %d\n", byteCodeReq.Bytes)
	for i, hash := range byteCodeReq.Hashes {
		fmt.Printf("   哈希 %d: %s\n", i+1, hash.Hex())
	}
	
	// 模拟发送字节码请求
	fmt.Println("   → 发送字节码请求到对等节点")
	err = snapHandler.RequestByteCodes(mockPeerID, byteCodeReq)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 字节码请求发送成功")
	}
	
	// 4. Trie节点请求
	fmt.Println("\n4. 构造Trie节点请求")
	trieNodeReq := snapHandler.CreateFuzzedTrieNodesRequest(4)
	fmt.Printf("   请求ID: %d\n", trieNodeReq.ID)
	fmt.Printf("   根哈希: %s\n", trieNodeReq.Root.Hex())
	fmt.Printf("   路径集合数量: %d\n", len(trieNodeReq.Paths))
	fmt.Printf("   字节限制: %d\n", trieNodeReq.Bytes)
	
	// 模拟发送Trie节点请求
	fmt.Println("   → 发送Trie节点请求到对等节点")
	err = snapHandler.RequestTrieNodes(mockPeerID, trieNodeReq)
	if err != nil {
		fmt.Printf("   ✗ 发送失败: %v\n", err)
	} else {
		fmt.Println("   ✓ Trie节点请求发送成功")
	}
}

// demonstrateMessageReceiving 演示消息接收和处理
func demonstrateMessageReceiving(manager *p2p.Manager, logger fuzzer.Logger) {
	fmt.Println("--- 消息接收处理演示 ---")
	
	// 创建模拟的消息接收场景
	fmt.Println("1. 模拟接收ETH协议消息")
	fmt.Println("   → 等待Status消息...")
	fmt.Println("   ✓ 收到Status消息，协议版本: 68, 网络ID: 1")
	fmt.Println("   → 处理Status消息完成")
	
	fmt.Println("\n   → 等待交易消息...")
	fmt.Println("   ✓ 收到交易消息，包含 5 个交易")
	fmt.Println("   → 验证交易格式和签名")
	fmt.Println("   → 交易处理完成")
	
	fmt.Println("\n   → 等待区块头消息...")
	fmt.Println("   ✓ 收到区块头消息，包含 10 个区块头")
	fmt.Println("   → 验证区块头链式关系")
	fmt.Println("   → 区块头处理完成")
	
	fmt.Println("\n2. 模拟接收SNAP协议消息")
	fmt.Println("   → 等待账户范围响应...")
	fmt.Println("   ✓ 收到账户范围响应，包含 100 个账户")
	fmt.Println("   → 验证账户数据和证明")
	fmt.Println("   → 账户范围响应处理完成")
	
	fmt.Println("\n   → 等待存储范围响应...")
	fmt.Println("   ✓ 收到存储范围响应，包含 50 个存储槽")
	fmt.Println("   → 验证存储数据和证明")
	fmt.Println("   → 存储范围响应处理完成")
	
	fmt.Println("\n   → 等待字节码响应...")
	fmt.Println("   ✓ 收到字节码响应，包含 3 个合约字节码")
	fmt.Println("   → 验证字节码哈希")
	fmt.Println("   → 字节码响应处理完成")
	
	fmt.Println("\n3. 消息处理统计")
	fmt.Println("   ETH协议消息: 处理成功 15 个，失败 0 个")
	fmt.Println("   SNAP协议消息: 处理成功 8 个，失败 0 个")
	fmt.Println("   总处理时间: 1.23秒")
	fmt.Println("   平均处理时间: 53.5毫秒/消息")
	
	// 模拟一些延时来展示实时处理
	time.Sleep(100 * time.Millisecond)
	fmt.Println("\n   ✓ 所有消息接收和处理完成")
}