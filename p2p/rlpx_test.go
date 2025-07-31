package p2p

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
)

// TestRLPxClientConnect 测试RLPx客户端连接到真实enode节点
func TestRLPxClientConnect(t *testing.T) {
	// 创建RLPx客户端
	client, err := NewRLPxClient()
	if err != nil {
		t.Fatalf("Failed to create RLPx client: %v", err)
	}
	defer client.Close()

	// 解析enode地址（使用测试环境中的节点）
	enodeURL := "enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303"
	err = client.ParseEnode(enodeURL)
	if err != nil {
		t.Fatalf("Failed to parse enode: %v", err)
	}

	// 建立RLPx连接
	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	fmt.Println("=== RLPx连接建立成功 ===")

	// 发送Hello消息（P2P协议握手）
	fmt.Println("\n=== 发送Hello消息 ===")
	err = client.SendHello()
	if err != nil {
		t.Logf("Failed to send Hello message: %v", err)
	} else {
		fmt.Println("Hello消息发送成功")
	}

	// 尝试接收响应消息
	fmt.Println("\n=== 尝试接收响应消息 ===")
	code, data, err := client.ReceiveRLPMessage()
	if err != nil {
		t.Logf("Failed to receive message (这是正常的，因为远程节点可能立即关闭连接): %v", err)
	} else {
		fmt.Printf("接收到消息 - Code: %d, Data: %x\n", code, data)

		// 尝试解析接收到的数据
		if code == 0x00 { // Hello消息
			var helloResp struct {
				Version    uint64
				Name       string
				Caps       []interface{}
				ListenPort uint64
				ID         []byte
			}
			err = rlp.DecodeBytes(data, &helloResp)
			if err != nil {
				t.Logf("Failed to decode Hello response: %v", err)
			} else {
				fmt.Printf("Hello响应解析成功 - Version: %d, Name: %s\n", helloResp.Version, helloResp.Name)
			}
		}
	}

	// 发送Ping消息
	fmt.Println("\n=== 发送Ping消息 ===")
	err = client.SendPing()
	if err != nil {
		t.Logf("Failed to send Ping message: %v", err)
	} else {
		fmt.Println("Ping消息发送成功")
	}

	// 发送自定义RLP数据
	fmt.Println("\n=== 发送自定义RLP数据 ===")
	customData := map[string]interface{}{
		"type":      "test",
		"message":   "Hello from D2PFuzz",
		"timestamp": time.Now().Unix(),
	}
	err = client.SendRLPMessage(0x10, customData) // 使用自定义消息代码0x10
	if err != nil {
		t.Logf("Failed to send custom RLP message: %v", err)
	} else {
		fmt.Println("自定义RLP消息发送成功")
	}

	// 发送原始字节数据
	fmt.Println("\n=== 发送原始字节数据 ===")
	rawData := []byte("This is raw test data from D2PFuzz")
	err = client.SendCustomMessage(0x11, rawData)
	if err != nil {
		t.Logf("Failed to send raw message: %v", err)
	} else {
		fmt.Println("原始数据消息发送成功")
	}

	fmt.Println("\n=== RLPx测试完成 ===")
	fmt.Printf("节点信息: %s\n", client.GetNodeInfo().String())
	fmt.Printf("本地公钥: %x\n", client.GetLocalPublicKey())
}

// TestRLPxClientBasicOperations 测试RLPx客户端基本操作
func TestRLPxClientBasicOperations(t *testing.T) {
	// 创建客户端
	client, err := NewRLPxClient()
	if err != nil {
		t.Fatalf("Failed to create RLPx client: %v", err)
	}

	// 测试解析无效enode
	err = client.ParseEnode("invalid-enode")
	if err == nil {
		t.Error("Expected error for invalid enode, but got nil")
	}

	// 测试未连接时发送消息
	err = client.SendHello()
	if err == nil {
		t.Error("Expected error when sending message without connection, but got nil")
	}

	// 测试未连接时接收消息
	_, _, err = client.ReceiveRLPMessage()
	if err == nil {
		t.Error("Expected error when receiving message without connection, but got nil")
	}

	fmt.Println("基本操作测试通过")
}
