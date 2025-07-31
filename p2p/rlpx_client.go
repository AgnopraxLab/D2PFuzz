package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"D2PFuzz/p2p/enode"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

// RLPxClient RLPx协议客户端
type RLPxClient struct {
	conn    *rlpx.Conn
	node    *enode.Node
	privKey *ecdsa.PrivateKey
	pubKey  *ecdsa.PublicKey
	address string
}

// NewRLPxClient 创建新的RLPx客户端
func NewRLPxClient() (*RLPxClient, error) {
	// 生成临时私钥用于握手
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return &RLPxClient{
		privKey: privKey,
		pubKey:  &privKey.PublicKey,
	}, nil
}

// ParseEnode 解析enode地址并创建Node对象
func (c *RLPxClient) ParseEnode(enodeURL string) error {
	node, err := enode.ParseV4(enodeURL)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	c.node = node
	c.address = fmt.Sprintf("%s:%d", node.IP(), node.TCP())

	fmt.Printf("Parsed enode - ID: %s, Address: %s\n", node.ID().String(), c.address)
	return nil
}

// Connect 建立RLPx连接
func (c *RLPxClient) Connect() error {
	if c.node == nil {
		return fmt.Errorf("no node to connect to, please parse enode first")
	}

	fmt.Printf("Attempting RLPx connection to %s...\n", c.address)

	// 建立TCP连接
	tcpConn, err := net.DialTimeout("tcp", c.address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to establish TCP connection: %v", err)
	}

	// 执行RLPx握手
	remotePubKey := c.node.Pubkey()
	if remotePubKey == nil {
		tcpConn.Close()
		return fmt.Errorf("remote node has no public key")
	}

	// 创建RLPx连接并执行握手
	rlpxConn := rlpx.NewConn(tcpConn, remotePubKey)
	_, err = rlpxConn.Handshake(c.privKey)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("RLPx handshake failed: %v", err)
	}

	c.conn = rlpxConn
	fmt.Printf("Successfully established RLPx connection to %s\n", c.address)
	return nil
}

// SendRLPMessage 发送RLP编码的消息
func (c *RLPxClient) SendRLPMessage(msgCode uint64, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	// RLP编码数据
	payload, err := rlp.EncodeToBytes(data)
	if err != nil {
		return fmt.Errorf("failed to encode message: %v", err)
	}

	// 发送消息
	_, err = c.conn.Write(msgCode, payload)
	if err != nil {
		return fmt.Errorf("failed to send RLP message: %v", err)
	}

	fmt.Printf("Sent RLP message - Code: %d, Size: %d bytes\n", msgCode, len(payload))
	return nil
}

// ReceiveRLPMessage 接收RLP编码的消息
func (c *RLPxClient) ReceiveRLPMessage() (uint64, []byte, error) {
	if c.conn == nil {
		return 0, nil, fmt.Errorf("not connected")
	}

	// 设置读取超时
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	code, data, _, err := c.conn.Read()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return 0, nil, fmt.Errorf("receive timeout: no message received within 10 seconds")
		}
		return 0, nil, fmt.Errorf("failed to receive RLP message: %v", err)
	}

	fmt.Printf("Received RLP message - Code: %d, Size: %d bytes\n", code, len(data))
	return code, data, nil
}

// SendHello 发送Hello消息（P2P协议握手）
func (c *RLPxClient) SendHello() error {
	helloMsg := struct {
		Version    uint64
		Name       string
		Caps       []interface{}
		ListenPort uint64
		ID         []byte
	}{
		Version:    5, // P2P协议版本
		Name:       "D2PFuzz/1.0.0",
		Caps:       []interface{}{}, // 支持的协议能力
		ListenPort: 0,
		ID:         crypto.FromECDSAPub(c.pubKey),
	}

	return c.SendRLPMessage(0x00, helloMsg) // Hello消息的代码是0x00
}

// SendPing 发送Ping消息
func (c *RLPxClient) SendPing() error {
	return c.SendRLPMessage(0x02, []interface{}{}) // Ping消息的代码是0x02
}

// SendDisconnect 发送断开连接消息
func (c *RLPxClient) SendDisconnect(reason uint64) error {
	return c.SendRLPMessage(0x01, []interface{}{reason}) // Disconnect消息的代码是0x01
}

// SendCustomMessage 发送自定义消息
func (c *RLPxClient) SendCustomMessage(msgCode uint64, payload []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	_, err := c.conn.Write(msgCode, payload)
	if err != nil {
		return fmt.Errorf("failed to send custom message: %v", err)
	}

	fmt.Printf("Sent custom message - Code: %d, Size: %d bytes\n", msgCode, len(payload))
	return nil
}

// GetNodeInfo 获取连接的节点信息
func (c *RLPxClient) GetNodeInfo() *enode.Node {
	return c.node
}

// GetLocalPublicKey 获取本地公钥
func (c *RLPxClient) GetLocalPublicKey() *ecdsa.PublicKey {
	return c.pubKey
}

// Close 关闭RLPx连接
func (c *RLPxClient) Close() error {
	if c.conn != nil {
		fmt.Println("Closing RLPx connection...")
		return c.conn.Close()
	}
	return nil
}

// IsConnected 检查是否已连接
func (c *RLPxClient) IsConnected() bool {
	return c.conn != nil
}
