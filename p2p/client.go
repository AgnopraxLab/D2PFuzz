package p2p

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// P2PClient P2P客户端结构
type P2PClient struct {
	conn net.Conn
	publicKey string
	address string
}

// NewP2PClient 创建新的P2P客户端
func NewP2PClient() *P2PClient {
	return &P2PClient{}
}

// ParseEnode 解析enode地址
func (c *P2PClient) ParseEnode(enodeURL string) error {
	// 移除"enode://"前缀
	enodeWithoutPrefix := strings.TrimPrefix(enodeURL, "enode://")
	
	// 使用@符号分割公钥和地址部分
	parts := strings.Split(enodeWithoutPrefix, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid enode format")
	}
	
	c.publicKey = parts[0]
	c.address = parts[1]
	
	fmt.Printf("Parsed enode - Public Key: %s, Address: %s\n", c.publicKey, c.address)
	return nil
}

// Connect 连接到解析的enode地址
func (c *P2PClient) Connect() error {
	if c.address == "" {
		return fmt.Errorf("no address to connect to, please parse enode first")
	}
	
	fmt.Printf("Attempting to connect to %s...\n", c.address)
	
	// 设置连接超时
	conn, err := net.DialTimeout("tcp", c.address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.address, err)
	}
	
	c.conn = conn
	fmt.Printf("Successfully connected to %s\n", c.address)
	return nil
}

// SendMessage 发送消息
func (c *P2PClient) SendMessage(message string) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	
	_, err := c.conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	
	fmt.Printf("Message sent: %s\n", message)
	return nil
}

// ReceiveMessage 接收消息
func (c *P2PClient) ReceiveMessage() (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("not connected")
	}
	
	// 设置读取超时
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	buffer := make([]byte, 1024)
	n, err := c.conn.Read(buffer)
	if err != nil {
		// 检查是否是超时错误
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("receive timeout: no data received within 5 seconds")
		}
		return "", fmt.Errorf("failed to receive message: %v", err)
	}
	
	message := string(buffer[:n])
	fmt.Printf("Message received: %s\n", message)
	return message, nil
}

// Close 关闭连接
func (c *P2PClient) Close() error {
	if c.conn != nil {
		fmt.Println("Closing connection...")
		return c.conn.Close()
	}
	return nil
}

// GetPublicKey 获取公钥
func (c *P2PClient) GetPublicKey() string {
	return c.publicKey
}

// GetAddress 获取地址
func (c *P2PClient) GetAddress() string {
	return c.address
}