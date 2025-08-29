package main

import (
	"crypto/ecdsa"
	"reflect"
	"time"

	// "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"

	// "path"
	"strings"

	// "time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"

	// "github.com/ethereum/go-ethereum/common/hexutil"

	// "github.com/ethereum/go-ethereum/core/forkid"

	"github.com/ethereum/go-ethereum/core/types"

	// "github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
	"gopkg.in/yaml.v2"

	ethtest "D2PFuzz/devp2p/protocol/eth"
)

// Config 配置结构体
type Config struct {
	P2P struct {
		MaxPeers       int      `yaml:"max_peers"`
		ListenPort     int      `yaml:"listen_port"`
		BootstrapNodes []string `yaml:"bootstrap_nodes"`
		JWTSecret      string   `yaml:"jwt_secret"`
	} `yaml:"p2p"`
}

type protocolHandshake struct {
	Version    uint64
	Name       string
	Caps       []p2p.Cap
	ListenPort uint64
	ID         []byte // secp256k1 public key

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// loadConfig 读取配置文件
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createRLPxConnection 创建RLPx连接
func createRLPxConnection(node *enode.Node, privateKey *ecdsa.PrivateKey) (*rlpx.Conn, error) {

	// 连接到节点
	addr := fmt.Sprintf("%s:%d", node.IP(), node.TCP())
	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	// 执行RLPx握手
	conn := rlpx.NewConn(tcpConn, node.Pubkey())
	fmt.Printf("conn: %v\n", conn)

	_, err = conn.Handshake(privateKey)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to perform RLPx handshake: %w", err)
	}
	// fmt.Println("publickKey: ", publicKey)
	fmt.Println("RLPx handshake completed successfully")

	return conn, nil
}

// // testGetBlockHeaders 测试GetBlockHeaders请求
// func testGetBlockHeaders(conn *rlpx.Conn) error {
// 	// 首先进行ETH协议握手
// 	err := performETHHandshake(conn)
// 	if err != nil {
// 		return fmt.Errorf("failed to perform ETH handshake: %w", err)
// 	}

// 	request := &eth.GetBlockHeadersPacket{
// 		RequestId: 1,
// 		GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
// 			Origin: eth.HashOrNumber{
// 				Number: 1,
// 			}, // 请求从区块1开始
// 			Amount:  10, // 请求10个区块头
// 			Skip:    0,
// 			Reverse: false,
// 		},
// 	}

// 	// 使用RLP编码发送消息
// 	data, err := rlp.EncodeToBytes(request)
// 	if err != nil {
// 		return fmt.Errorf("failed to encode GetBlockHeaders request: %w", err)
// 	}

// 	_, err = conn.Write(0x03, data) // GetBlockHeadersMsg = 0x03
// 	if err != nil {
// 		return fmt.Errorf("failed to send GetBlockHeaders request: %w", err)
// 	}
// 	fmt.Println("GetBlockHeaders request sent successfully")

// 	// 接收响应
// 	code, responseData, _, err := conn.Read()
// 	if err != nil {
// 		return fmt.Errorf("failed to read response: %w", err)
// 	}
// 	fmt.Printf("Received message with code: %d, size: %d\n", code, len(responseData))

// 	if code == 0x04 { // BlockHeadersMsg = 0x04
// 		type BlockHeadersPacket struct {
// 			RequestId uint64
// 			Headers   []*types.Header
// 		}
// 		var response BlockHeadersPacket
// 		err = rlp.DecodeBytes(responseData, &response)
// 		if err != nil {
// 			return fmt.Errorf("failed to decode block headers: %w", err)
// 		}
// 		fmt.Printf("Received %d block headers:\n", len(response.Headers))

// 		for i, header := range response.Headers {
// 			fmt.Printf("  Header %d: Block #%d, Hash: %s\n", i+1, header.Number.Uint64(), header.Hash().Hex())
// 		}
// 	} else {
// 		fmt.Printf("Unexpected message code: %d\n", code)
// 	}

// 	return nil
// }

// // performETHHandshake 执行ETH协议握手
// func performETHHandshake(conn *rlpx.Conn) error {
// 	// 使用默认的主网配置创建状态包
// 	genesisHash := common.HexToHash("0x307b844cd0697aeebd02d2ee2443f0fa7e990258ec48e980d97c81669d00affd")
// 	latestHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
// 	td := big.NewInt(0)

// 	// 创建一个虚拟的创世区块用于forkid计算
// 	genesisHeader := &types.Header{
// 		Number:     big.NewInt(0),
// 		Time:       0,
// 		Difficulty: big.NewInt(1),
// 	}

// 	// 创建一个虚拟区块用于forkid计算
// 	body := &types.Body{}
// 	genesisBlock := types.NewBlock(genesisHeader, body, nil, nil)
// 	fmt.Println("genesisBlock: ", genesisBlock)
// 	status := &eth.StatusPacket68{
// 		ProtocolVersion: 68, // ETH68
// 		NetworkID:       1,  // 主网
// 		TD:              td,
// 		Head:            latestHash,
// 		Genesis:         genesisHash,
// 		ForkID:          forkid.NewID(params.MainnetChainConfig, genesisBlock, 0, 0),
// 	}

// 	// 发送状态包
// 	statusData, err := rlp.EncodeToBytes(status)
// 	if err != nil {
// 		return fmt.Errorf("failed to encode status packet: %w", err)
// 	} else {
// 		fmt.Println("statusData: ", statusData)
// 	}
// 	code1, err := conn.Write(0x00, statusData) // StatusMsg = 0x00
// 	if err != nil {
// 		return fmt.Errorf("failed to send status packet: %w", err)
// 	} else {
// 		fmt.Println("code1: ", code1)
// 	}

// 	fmt.Println("ETH status packet sent")

// 	// 接收对方的状态包
// 	code, data, _, err := conn.Read()
// 	if err != nil {
// 		return fmt.Errorf("failed to read status response: %w", err)
// 	}

// 	fmt.Printf("Received message - Code: %d, Data length: %d\n", code, len(data))
// 	fmt.Printf("Raw data (hex): %x\n", data)

// 	// 解析原始数据为可读格式
// 	handshake := parseRawData(data)
// 	fmt.Printf("Parsed data: %v\n", handshake)

// 	// 专门解析P2P握手数据
// 	parseP2PHandshakeData(data)

// 	if code == 0x00 {
// 		fmt.Println("\nThis appears to be a P2P handshake message, not an ETH status message.")
// 		fmt.Println("The peer is responding with its protocol capabilities.")
// 	} else {
// 		fmt.Printf("Received message with code %d\n", code)
// 	}

// 	return nil
// }

// parseRawData 解析原始数据为可读格式
func parseRawData(data []byte) *protocolHandshake {
	if len(data) == 0 {
		fmt.Println("empty data")
		return nil
	}

	// 尝试解析为RLP结构
	var result interface{}
	err := rlp.DecodeBytes(data, &result)
	if err != nil {
		fmt.Println("rlp decode error")
		return nil
	}
	fmt.Println("解析前data:", data)
	// 尝试解析为P2P握手消息
	var handshake protocolHandshake
	err = rlp.DecodeBytes(data, &handshake)
	if err == nil {
		fmt.Println("decode bytes error")
		return nil
	}

	return &protocolHandshake{
		Version:    handshake.Version,
		Name:       handshake.Name,
		Caps:       handshake.Caps,
		ListenPort: handshake.ListenPort,
	}
}

// parseP2PHandshakeData 专门解析P2P握手数据
func parseP2PHandshakeData(data []byte) {
	var handshake protocolHandshake
	err := rlp.DecodeBytes(data, &handshake)
	if err != nil {
		fmt.Printf("Failed to decode P2P handshake: %v\n", err)
		return
	}

	fmt.Printf("=== P2P Handshake Details ===\n")
	fmt.Printf("Version: %d\n", handshake.Version)
	fmt.Printf("Name: %s\n", handshake.Name)
	fmt.Printf("Listen Port: %d\n", handshake.ListenPort)
	fmt.Printf("Node ID: %x\n", handshake.ID)
	fmt.Printf("Capabilities:\n")
	for i, cap := range handshake.Caps {
		fmt.Printf("  %d. %s/%d\n", i+1, cap.Name, cap.Version)
	}
	fmt.Printf("==============================\n")
}

// 直接解析十六进制字符串
func parseJWTSecretFromHexString(hexString string) ([]byte, error) {
	// 去除可能的0x前缀和空白字符
	hexString = strings.TrimSpace(hexString)
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	// 转换为字节数组
	jwtSecret, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// 验证长度
	if len(jwtSecret) != 32 {
		return nil, fmt.Errorf("invalid JWT secret length: expected 32 bytes, got %d", len(jwtSecret))
	}

	return jwtSecret, nil
}

func main() {
	// 1. 读取当前目录下config.yaml文件的配置
	config, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}

	// 2. 获取其中的enode值，解析之后获取其中的IP和端口
	if len(config.P2P.BootstrapNodes) == 0 {
		fmt.Println("No bootstrap nodes found in config")
		return
	}

	// 使用第一个bootstrap node
	enodeStr := config.P2P.BootstrapNodes[0]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		fmt.Printf("Failed to parse enode: %v\n", err)
		return
	}

	fmt.Printf("Connecting to node: %s\n", node.String())
	fmt.Printf("IP: %s, Port: %d\n", node.IP(), node.TCP())

	// 先创建suite，suite通过dial返回conn
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		fmt.Printf("Failed to parse JWT secret: %v\n", err)
		return
	}
	// _, secret, err := MakeJWTSecret()
	if err != nil {
		fmt.Printf("Failed to make JWT secret: %v\n", err)
		return
	}
	suite, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]))
	if err != nil {
		fmt.Printf("Failed to create suite: %v\n", err)
		return
	}

	// GetBlockHeaders测试
	// headers, err := GetBlockHeaders(suite)
	// if err != nil {
	// 	fmt.Printf("Failed to get block headers: %v\n", err)
	// 	return
	// }
	// printHeaders(headers)

	// 发送交易测试
	// err = sendTransaction(suite)
	// if err != nil {
	// 	fmt.Printf("Failed to send transaction: %v\n", err)
	// 	return
	// }

	// 获取收据
	// receipts, err := GetReceipts(suite)
	// if err != nil {
	// 	fmt.Printf("Failed to get receipts: %v\n", err)
	// 	return
	// }
	// printReceipts(receipts)

	// 发送大量交易并获取交易池
	resp := sendLargeTransactions(suite)
	printPooledTransactions(resp)
}

func sendLargeTransactions(s *ethtest.Suite) eth.PooledTransactionsResponse {
	// 这个测试首先向节点发送约count笔交易，然后请求这些交易使用 GetPooledTransactions 在另一个对等连接上。
	var (
		nonce  = uint64(32)
		from   = "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31"
		count  = 2000
		txs    []*types.Transaction
		hashes []common.Hash
		set    = make(map[common.Hash]struct{})
	)
	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		fmt.Println("failed to generate private key")
		return nil
	}
	var to common.Address = common.HexToAddress("0xE25583099BA105D9ec0A67f5Ae86D90e50036425")
	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   big.NewInt(3151908),
			Nonce:     nonce + uint64(i),
			GasTipCap: big.NewInt(2000000000),
			GasFeeCap: big.NewInt(20000000000),
			Gas:       30000,
			To:        &to,
			Value:     common.Big1,
		}
		tx := types.NewTx(inner)
		tx, err = types.SignTx(tx, types.NewLondonSigner(big.NewInt(3151908)), prik)
		if err != nil {
			fmt.Println("failed to sign tx: err")
		}
		txs = append(txs, tx)
		set[tx.Hash()] = struct{}{}
		hashes = append(hashes, tx.Hash())
	}
	// Send txs.
	if err := s.SendTxs(txs); err != nil {
		fmt.Printf("failed to send txs: %v", err)
	}

	// Set up receive connection to ensure node is peered with the receiving
	// connection before tx request is sent.
	conn, err := s.Dial()
	if err != nil {
		fmt.Printf("dial failed: %v", err)
	}
	defer conn.Close()
	if err = conn.Peer(nil); err != nil {
		fmt.Printf("peering failed: %v", err)
	}
	// Create and send pooled tx request.
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    1234,
		GetPooledTransactionsRequest: hashes,
	}
	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		fmt.Printf("could not write to conn: %v", err)
	}
	// Check that all received transactions match those that were sent to node.
	msg := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, &msg); err != nil {
		fmt.Printf("error reading from connection: %v", err)
	}
	if got, want := msg.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in response: got %d, want %d", got, want)
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			fmt.Printf("unexpected tx received: %v", got.Hash())
		}
	}
	return msg.PooledTransactionsResponse
}

func printPooledTransactions(resp eth.PooledTransactionsResponse) {
	if len(resp) == 0 {
		fmt.Println("没有池化交易数据")
		return
	}

	fmt.Printf("=== 池化交易响应 ===\n")
	fmt.Printf("交易总数: %d\n\n", len(resp))

	for i, tx := range resp {
		fmt.Printf("--- 交易 %d ---\n", i+1)

		// 基本交易信息
		fmt.Printf("交易哈希: %s\n", tx.Hash().Hex())
		fmt.Printf("交易类型: %d\n", tx.Type())
		fmt.Printf("Nonce: %d\n", tx.Nonce())

		// 地址信息
		if tx.To() != nil {
			fmt.Printf("接收地址: %s\n", tx.To().Hex())
		} else {
			fmt.Printf("接收地址: 合约创建交易\n")
		}

		// 金额和Gas信息
		fmt.Printf("转账金额: %s Wei\n", tx.Value().String())
		fmt.Printf("Gas限制: %d\n", tx.Gas())

		// Gas价格信息（根据交易类型显示不同字段）
		switch tx.Type() {
		case types.LegacyTxType:
			fmt.Printf("Gas价格: %s Wei\n", tx.GasPrice().String())
		case types.AccessListTxType:
			fmt.Printf("Gas价格: %s Wei\n", tx.GasPrice().String())
		case types.DynamicFeeTxType:
			fmt.Printf("最大费用: %s Wei\n", tx.GasFeeCap().String())
			fmt.Printf("优先费用: %s Wei\n", tx.GasTipCap().String())
		case types.BlobTxType:
			fmt.Printf("最大费用: %s Wei\n", tx.GasFeeCap().String())
			fmt.Printf("优先费用: %s Wei\n", tx.GasTipCap().String())
			if tx.BlobGasFeeCap() != nil {
				fmt.Printf("Blob Gas费用上限: %s Wei\n", tx.BlobGasFeeCap().String())
			}
			if tx.BlobHashes() != nil {
				fmt.Printf("Blob哈希数量: %d\n", len(tx.BlobHashes()))
				for j, blobHash := range tx.BlobHashes() {
					fmt.Printf("  Blob哈希 %d: %s\n", j+1, blobHash.Hex())
				}
			}
		default:
			fmt.Printf("Gas价格: %s Wei\n", tx.GasPrice().String())
		}

		// 链ID
		if tx.ChainId() != nil {
			fmt.Printf("链ID: %d\n", tx.ChainId().Uint64())
		}

		// 交易数据
		data := tx.Data()
		if len(data) > 0 {
			fmt.Printf("数据长度: %d 字节\n", len(data))
			if len(data) <= 64 {
				fmt.Printf("数据内容: %x\n", data)
			} else {
				fmt.Printf("数据内容(前32字节): %x...\n", data[:32])
			}
		} else {
			fmt.Printf("数据: 无\n")
		}

		// 交易大小
		fmt.Printf("交易大小: %d 字节\n", tx.Size())

		// 签名信息
		v, r, s := tx.RawSignatureValues()
		fmt.Printf("签名 V: %d\n", v.Uint64())
		fmt.Printf("签名 R: %s\n", r.String())
		fmt.Printf("签名 S: %s\n", s.String())

		// 计算发送者地址（如果可能）
		if signer := types.LatestSignerForChainID(tx.ChainId()); signer != nil {
			if sender, err := types.Sender(signer, tx); err == nil {
				fmt.Printf("发送者地址: %s\n", sender.Hex())
			} else {
				fmt.Printf("发送者地址: 无法计算 (%v)\n", err)
			}
		}

		fmt.Println()
	}
}

func printMsg(msg any) {
	fmt.Printf("Msg: %v\n", msg)
}

func sendTransaction(s *ethtest.Suite) error {
	nonce := uint64(0)
	var to common.Address = common.HexToAddress("0xE25583099BA105D9ec0A67f5Ae86D90e50036425")
	txdata := &types.DynamicFeeTx{
		ChainID:   big.NewInt(3151908),
		Nonce:     nonce,
		GasTipCap: big.NewInt(2000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       30000,
		To:        &to, // 使用之前定义的to变量作为接收地址
		Value:     common.Big1,
	}
	innertx := types.NewTx(txdata)
	prik, err := crypto.HexToECDSA("bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31")
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}
	tx, err := types.SignTx(innertx, types.NewLondonSigner(big.NewInt(3151908)), prik)
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}

	// 记录发送时间
	sendStart := time.Now()
	if err := s.SendTxs([]*types.Transaction{tx}); err != nil {
		elapsed := time.Since(sendStart)
		fmt.Printf("交易发送失败，耗时: %v\n", elapsed)
		return err
	}
	nonce += 1
	return nil
}

func printReceipts(receipts []*eth.ReceiptList68) {
	if len(receipts) == 0 {
		fmt.Println("没有收据数据")
		return
	}

	for i, receiptList := range receipts {
		fmt.Printf("=== 区块 %d 的收据列表 ===\n", i+1)

		// ReceiptList68 应该是一个包含多个Receipt的列表
		// 根据go-ethereum的实现，这应该是 []*types.Receipt
		if receiptList == nil {
			fmt.Println("收据列表为空")
			continue
		}

		// 由于ReceiptList68的具体结构不明确，我们需要通过反射来访问其字段
		reflectValue := reflect.ValueOf(receiptList).Elem()
		reflectType := reflectValue.Type()

		fmt.Printf("收据列表类型: %s\n", reflectType.Name())
		fmt.Printf("字段数量: %d\n", reflectValue.NumField())

		// 遍历所有字段
		for j := 0; j < reflectValue.NumField(); j++ {
			field := reflectType.Field(j)
			fieldValue := reflectValue.Field(j)

			fmt.Printf("  字段 %s (%s): ", field.Name, field.Type)

			// 如果字段可以被访问
			if fieldValue.CanInterface() {
				switch fieldValue.Kind() {
				case reflect.Slice:
					fmt.Printf("切片长度 %d\n", fieldValue.Len())
					// 如果是Receipt切片，打印每个Receipt的详细信息
					if field.Type.String() == "[]*types.Receipt" {
						for k := 0; k < fieldValue.Len(); k++ {
							receipt := fieldValue.Index(k).Interface().(*types.Receipt)
							printSingleReceipt(receipt, k+1)
						}
					}
				case reflect.Ptr:
					if !fieldValue.IsNil() {
						fmt.Printf("%v\n", fieldValue.Interface())
					} else {
						fmt.Println("nil")
					}
				default:
					fmt.Printf("%v\n", fieldValue.Interface())
				}
			} else {
				fmt.Println("无法访问")
			}
		}
		fmt.Println()
	}
}

func printSingleReceipt(receipt *types.Receipt, index int) {
	fmt.Printf("    --- 收据 %d ---\n", index)

	// 基本信息
	fmt.Printf("    交易类型: %d\n", receipt.Type)
	fmt.Printf("    交易哈希: %s\n", receipt.TxHash.Hex())
	fmt.Printf("    状态: %d\n", receipt.Status)

	// Gas相关信息
	fmt.Printf("    累计Gas使用量: %d\n", receipt.CumulativeGasUsed)
	fmt.Printf("    Gas使用量: %d\n", receipt.GasUsed)
	if receipt.EffectiveGasPrice != nil {
		fmt.Printf("    有效Gas价格: %s Wei\n", receipt.EffectiveGasPrice.String())
	}

	// 合约地址（如果是合约创建交易）
	if receipt.ContractAddress != (common.Address{}) {
		fmt.Printf("    合约地址: %s\n", receipt.ContractAddress.Hex())
	} else {
		fmt.Printf("    合约地址: 无（非合约创建交易）\n")
	}

	// 区块信息
	if receipt.BlockHash != (common.Hash{}) {
		fmt.Printf("    区块哈希: %s\n", receipt.BlockHash.Hex())
	}
	if receipt.BlockNumber != nil {
		fmt.Printf("    区块号: %d\n", receipt.BlockNumber.Uint64())
	}
	fmt.Printf("    交易索引: %d\n", receipt.TransactionIndex)

	// Bloom过滤器
	fmt.Printf("    Bloom过滤器: %x\n", receipt.Bloom)

	// Blob相关信息（如果存在）
	if receipt.BlobGasUsed > 0 {
		fmt.Printf("    Blob Gas使用量: %d\n", receipt.BlobGasUsed)
	}
	if receipt.BlobGasPrice != nil {
		fmt.Printf("    Blob Gas价格: %s Wei\n", receipt.BlobGasPrice.String())
	}

	// 日志信息
	if len(receipt.Logs) > 0 {
		fmt.Printf("    日志数量: %d\n", len(receipt.Logs))
		for j, log := range receipt.Logs {
			fmt.Printf("      日志 %d:\n", j+1)
			fmt.Printf("        地址: %s\n", log.Address.Hex())
			fmt.Printf("        主题数量: %d\n", len(log.Topics))
			for k, topic := range log.Topics {
				fmt.Printf("        主题 %d: %s\n", k+1, topic.Hex())
			}
			fmt.Printf("        数据长度: %d 字节\n", len(log.Data))
			if len(log.Data) > 0 && len(log.Data) <= 64 {
				fmt.Printf("        数据: %x\n", log.Data)
			}
		}
	} else {
		fmt.Printf("    日志: 无\n")
	}

	fmt.Println()
}

func GetReceipts(s *ethtest.Suite) (list []*eth.ReceiptList68, err error) {
	conn, err := s.DialAndPeer(nil)
	if err != nil {
		fmt.Printf("peering failed: %v", err)
	}
	defer conn.Close()

	// Find some blocks containing receipts.
	var hashes = make([]common.Hash, 0, 3)
	for i := range s.GetChain().Len() {
		block := s.GetChain().GetBlock(i)
		if len(block.Transactions()) > 0 {
			hashes = append(hashes, block.Hash())
		}
		if len(hashes) == cap(hashes) {
			break
		}
	}

	// Create block bodies request.
	req := &eth.GetReceiptsPacket{
		RequestId:          22,
		GetReceiptsRequest: (eth.GetReceiptsRequest)(hashes),
	}
	if err := conn.Write(1, eth.GetReceiptsMsg, req); err != nil {
		fmt.Printf("could not write to connection: %v", err)
	}
	// Wait for response.
	resp := new(eth.ReceiptsPacket[*eth.ReceiptList68])
	if err := conn.ReadMsg(1, eth.ReceiptsMsg, &resp); err != nil {
		fmt.Printf("error reading block bodies msg: %v", err)
	}
	if got, want := resp.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in respond", got, want)
	}
	if len(resp.List) != len(req.GetReceiptsRequest) {
		fmt.Printf("wrong bodies in response: expected %d bodies, got %d", len(req.GetReceiptsRequest), len(resp.List))
	}
	return resp.List, nil
}

func printHeaders(headers *eth.BlockHeadersPacket) {
	for i, header := range headers.BlockHeadersRequest {
		fmt.Printf("=== Header %d ===\n", i+1)
		fmt.Printf("区块号: %d\n", header.Number.Uint64())
		fmt.Printf("区块哈希: %s\n", header.Hash().Hex())
		fmt.Printf("父区块哈希: %s\n", header.ParentHash.Hex())
		fmt.Printf("时间戳: %d\n", header.Time)
		fmt.Printf("Gas限制: %d\n", header.GasLimit)
		fmt.Printf("Gas使用量: %d\n", header.GasUsed)
		fmt.Printf("难度: %s\n", header.Difficulty.String())
		fmt.Printf("矿工地址: %s\n", header.Coinbase.Hex())
		fmt.Printf("状态根: %s\n", header.Root.Hex())
		fmt.Printf("交易根: %s\n", header.TxHash.Hex())
		fmt.Printf("收据根: %s\n", header.ReceiptHash.Hex())
		fmt.Println()
	}
}

func GetBlockHeaders(suite *ethtest.Suite) (*eth.BlockHeadersPacket, error) {
	// chain, err := ethtest.NewChain("./testdata")
	// if err != nil {
	// 	return nil, err
	// }
	conn, err := suite.DialAndPeer(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := &eth.GetBlockHeadersPacket{
		RequestId: 33,
		GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
			Origin:  eth.HashOrNumber{Number: uint64(0)},
			Amount:  uint64(10),
			Skip:    0,
			Reverse: false,
		},
	}
	// Read headers response.
	if err = conn.Write(1, eth.GetBlockHeadersMsg, req); err != nil {
		fmt.Printf("could not write to connection: %v", err)
	}
	headers := new(eth.BlockHeadersPacket)
	if err = conn.ReadMsg(1, eth.BlockHeadersMsg, &headers); err != nil {
		fmt.Printf("error reading msg: %v", err)
	}
	if got, want := headers.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id")
	}
	// Check for correct headers.
	expected, err := suite.GetChain().GetHeaders(req)
	if err != nil {
		fmt.Printf("failed to get headers for given request: %v", err)
	}
	if !headersMatch(expected, headers.BlockHeadersRequest) {
		fmt.Printf("header mismatch: \nexpected %v \ngot %v", expected, headers)
	}
	return headers, nil
}

// headersMatch returns whether the received headers match the given request
func headersMatch(expected []*types.Header, headers []*types.Header) bool {
	return reflect.DeepEqual(expected, headers)
}
