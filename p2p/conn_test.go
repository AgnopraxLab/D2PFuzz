package p2p

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// 解析enode获取IP和端口
func TestParseEnode(t *testing.T) {
	enode := "enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303"

	// 使用字符串处理方法分离enode
	// 移除"enode://"前缀
	enodeWithoutPrefix := strings.TrimPrefix(enode, "enode://")

	// 使用@符号分割公钥和地址部分
	parts := strings.Split(enodeWithoutPrefix, "@")
	if len(parts) != 2 {
		t.Fatalf("Invalid enode format")
	}

	// 将解析结果赋值给全局变量
	publickey := parts[0]
	address := parts[1]

	fmt.Println("Public Key:", publickey)
	fmt.Println("Address:", address)
}

// 测试建立TCP连接
func TestConn(t *testing.T) {
	// publickey := "c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3""
	listener, err := net.Listen("tcp", "localhost:30303")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func(t *testing.T) {
		conn, err := listener.Accept()
		if err != nil {
			// 在非测试goroutine中不能直接调用t.Fatalf，改用channel传递错误
			accepted <- nil
			return
		}
		accepted <- conn
	}(t)
	fmt.Println("accepted: ", accepted)
}

// 测试连接到真实enode节点
func TestConnectToEnode(t *testing.T) {
	// 使用真实的enode地址
	enodeURL := "enode://c662256b97629f5337fcfc15577a5795967be785cd8df680d3cb7a3df61dac63ac123df31605a449578b7190b83fa35d9ac500fb6f48c0a2c80e6c34bc9fb3d3@172.16.0.11:30303"
	
	// 创建P2P客户端
	client := NewP2PClient()
	defer client.Close() // 提前设置defer，确保连接被关闭
	
	// 链式操作，使用辅助函数处理错误
	err := client.ParseEnode(enodeURL)
	if err!=nil{
		t.Fatalf("Failed to parse enode")
	}
	t.Log("Enode parsed successfully")
	
	err = client.Connect()
	if err != nil {
		t.Fatalf("Connection failed (expected if node is offline): %v", err)
	}
	t.Log("Successfully connected to enode!")
	
	err = client.SendMessage("hello")
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	t.Log("Message sent successfully")
	
	// 尝试接收消息，但不强制要求成功（因为对方可能立即关闭连接）
	receive, err := client.ReceiveMessage()
	if err != nil {
		t.Logf("Note: Failed to receive message (this is normal if the remote node closes connection immediately): %v", err)
		t.Log("Connection test completed - node is reachable and accepts connections")
	} else {
		t.Logf("Received message: %s", receive)
	}
}
