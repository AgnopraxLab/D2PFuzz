package main

import (
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/fuzzer"
	"D2PFuzz/p2p"
)

// SimpleLogger 简单的日志实现
type SimpleLogger struct{}

func (l *SimpleLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

func (l *SimpleLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

func (l *SimpleLogger) Debug(msg string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+msg+"\n", args...)
}

func main() {
	fmt.Println("=== D2PFuzz 快速入门示例 ===")
	fmt.Println()

	// 1. 创建日志器
	logger := &SimpleLogger{}

	// 2. 创建P2P配置
	config := &p2p.Config{
		MaxPeers:   5,
		ListenPort: 30303,
	}

	// 3. 创建P2P管理器
	manager, err := p2p.NewManager(config, logger)
	if err != nil {
		log.Fatalf("创建管理器失败: %v", err)
	}

	// 4. 启动管理器
	err = manager.Start()
	if err != nil {
		log.Fatalf("启动管理器失败: %v", err)
	}
	defer manager.Stop()

	fmt.Println("✓ P2P管理器启动成功")

	// 5. 演示基本的消息构造和发送
	demonstrateBasicUsage(logger)

	fmt.Println("\n=== 快速入门示例完成 ===")
}

func demonstrateBasicUsage(logger fuzzer.Logger) {
	fmt.Println("\n--- 基本使用演示 ---")

	// 创建fuzzer客户端
	client, err := fuzzer.NewFuzzClient(logger)
	if err != nil {
		fmt.Printf("创建客户端失败: %v\n", err)
		return
	}
	defer client.Close()

	// 创建协议处理器
	ethHandler := p2p.NewEthProtocolHandler(client, logger)
	snapHandler := p2p.NewSnapProtocolHandler(client, logger)

	// 模拟对等节点ID
	mockPeerID := enode.ID{1, 2, 3, 4}

	// 1. ETH协议示例
	fmt.Println("\n1. ETH协议消息示例:")

	// 创建Status消息
	statusMsg := ethHandler.CreateFuzzedStatusMessage()
	fmt.Printf("   Status消息 - 协议版本: %d, 网络ID: %d\n", 
		statusMsg.ProtocolVersion, statusMsg.NetworkID)

	// 创建交易消息
	txs := ethHandler.CreateFuzzedTransactions(2)
	fmt.Printf("   交易消息 - 生成了 %d 个测试交易\n", len(txs))
	for i, tx := range txs {
		fmt.Printf("     交易%d: Gas=%d, GasPrice=%s\n", 
			i+1, tx.Gas(), tx.GasPrice().String())
	}

	// 创建区块头请求
	headerQuery := &p2p.GetBlockHeadersData{
		Origin:  p2p.HashOrNumber{Number: 1000},
		Amount:  5,
		Skip:    0,
		Reverse: false,
	}
	fmt.Printf("   区块头请求 - 起始区块: %d, 数量: %d\n", 
		headerQuery.Origin.Number, headerQuery.Amount)

	// 2. SNAP协议示例
	fmt.Println("\n2. SNAP协议消息示例:")

	// 创建账户范围请求
	accountReq := snapHandler.CreateFuzzedAccountRangeRequest(1)
	fmt.Printf("   账户范围请求 - ID: %d, 字节限制: %d\n", 
		accountReq.ID, accountReq.Bytes)
	fmt.Printf("     根哈希: %s\n", accountReq.Root.Hex()[:20]+"...")

	// 创建存储范围请求
	storageReq := snapHandler.CreateFuzzedStorageRangesRequest(2)
	fmt.Printf("   存储范围请求 - ID: %d, 账户数: %d\n", 
		storageReq.ID, len(storageReq.Accounts))

	// 创建字节码请求
	byteCodeReq := snapHandler.CreateFuzzedByteCodesRequest(3)
	fmt.Printf("   字节码请求 - ID: %d, 哈希数: %d\n", 
		byteCodeReq.ID, len(byteCodeReq.Hashes))

	// 3. 模拟发送消息（实际环境中需要真实的对等节点）
	fmt.Println("\n3. 消息发送模拟:")
	fmt.Println("   注意: 以下发送会失败，因为没有真实的对等节点连接")

	// 尝试发送ETH消息
	err = ethHandler.SendStatus(mockPeerID, statusMsg)
	if err != nil {
		fmt.Printf("   ETH Status消息发送: ✗ (%v)\n", err)
	} else {
		fmt.Println("   ETH Status消息发送: ✓")
	}

	err = ethHandler.SendTransactions(mockPeerID, txs)
	if err != nil {
		fmt.Printf("   ETH 交易消息发送: ✗ (%v)\n", err)
	} else {
		fmt.Println("   ETH 交易消息发送: ✓")
	}

	// 尝试发送SNAP消息
	err = snapHandler.RequestAccountRange(mockPeerID, accountReq)
	if err != nil {
		fmt.Printf("   SNAP 账户请求发送: ✗ (%v)\n", err)
	} else {
		fmt.Println("   SNAP 账户请求发送: ✓")
	}

	// 4. 总结
	fmt.Println("\n4. 总结:")
	fmt.Println("   ✓ 成功创建了各种协议消息")
	fmt.Println("   ✓ 演示了消息构造的基本流程")
	fmt.Println("   ✓ 展示了ETH和SNAP协议的主要消息类型")
	fmt.Println("   ℹ 要实际发送消息，需要连接到真实的以太坊节点")

	// 5. 下一步建议
	fmt.Println("\n5. 下一步:")
	fmt.Println("   - 配置真实的以太坊节点连接")
	fmt.Println("   - 实现消息接收和处理逻辑")
	fmt.Println("   - 添加更复杂的模糊测试场景")
	fmt.Println("   - 集成监控和日志系统")
}