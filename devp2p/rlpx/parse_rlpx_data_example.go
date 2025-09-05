package rlpx

import (
	"bytes"
	"fmt"

	// "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// 解析RLPx连接Read方法返回的data数据示例
func ParseRLPxData(code uint64, data []byte) {
	fmt.Printf("消息代码: 0x%02x\n", code)
	fmt.Printf("数据长度: %d 字节\n", len(data))
	fmt.Printf("原始数据: %x\n", data)
	fmt.Println("---")

	// 根据消息代码解析不同类型的消息
	switch code {
	// case eth.StatusMsg:
	// 	ParseStatusMessage(data)
	case eth.NewBlockHashesMsg:
		ParseNewBlockHashesMessage(data)
	case eth.TransactionsMsg:
		ParseTransactionsMessage(data)
	// case eth.GetBlockHeadersMsg:
	// 	ParseGetBlockHeadersMessage(data)
	case eth.BlockHeadersMsg:
		ParseBlockHeadersMessage(data)
	case eth.GetBlockBodiesMsg:
		ParseGetBlockBodiesMessage(data)
	case eth.BlockBodiesMsg:
		ParseBlockBodiesMessage(data)
	case eth.GetReceiptsMsg:
		ParseGetReceiptsMessage(data)
	case eth.ReceiptsMsg:
		ParseReceiptsMessage(data)
	case eth.GetPooledTransactionsMsg:
		ParseGetPooledTransactionsMessage(data)
	case eth.PooledTransactionsMsg:
		ParsePooledTransactionsMessage(data)
	default:
		fmt.Printf("未知消息类型: 0x%02x\n", code)
		// 尝试通用RLP解析
		ParseGenericRLP(data)
	}
}

// 解析状态消息 (握手)
// func ParseStatusMessage(data []byte) {
// 	fmt.Println("解析状态消息:")
// 	var status eth.StatusPacket68
// 	if err := rlp.DecodeBytes(data, &status); err != nil {
// 		fmt.Printf("解析错误: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("  协议版本: %d\n", status.ProtocolVersion)
// 	fmt.Printf("  网络ID: %d\n", status.NetworkID)
// 	fmt.Printf("  总难度: %s\n", status.TD.String())
// 	fmt.Printf("  最新区块哈希: %s\n", status.Head.Hex())
// 	fmt.Printf("  创世区块哈希: %s\n", status.Genesis.Hex())
// 	if status.ForkID != nil {
// 		fmt.Printf("  分叉ID: %x, 下一个分叉: %d\n", status.ForkID.Hash, status.ForkID.Next)
// 	}
// }

// 解析新区块哈希消息
func ParseNewBlockHashesMessage(data []byte) {
	fmt.Println("解析新区块哈希消息:")
	var hashes eth.NewBlockHashesPacket
	if err := rlp.DecodeBytes(data, &hashes); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  区块数量: %d\n", len(hashes))
	for i, hash := range hashes {
		fmt.Printf("  区块 %d: 哈希=%s, 高度=%d\n", i+1, hash.Hash.Hex(), hash.Number)
	}
}

// 解析交易消息
func ParseTransactionsMessage(data []byte) {
	fmt.Println("解析交易消息:")
	var txs eth.TransactionsPacket
	if err := rlp.DecodeBytes(data, &txs); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  交易数量: %d\n", len(txs))
	for i, tx := range txs {
		fmt.Printf("  交易 %d: 哈希=%s, Nonce=%d, Gas=%d\n",
			i+1, tx.Hash().Hex(), tx.Nonce(), tx.Gas())
		if tx.To() != nil {
			fmt.Printf("    接收者: %s\n", tx.To().Hex())
		} else {
			fmt.Printf("    合约创建交易\n")
		}
		fmt.Printf("    金额: %s Wei\n", tx.Value().String())
	}
}

// 解析获取区块头请求
// func ParseGetBlockHeadersMessage(data []byte) {
// 	fmt.Println("解析获取区块头请求:")
// 	var req eth.GetBlockHeadersPacket
// 	if err := rlp.DecodeBytes(data, &req); err != nil {
// 		fmt.Printf("解析错误: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("  请求ID: %d\n", req.RequestId)
// 	fmt.Printf("  起始位置: ")
// 	if req.HashOrNumber.Hash != (common.Hash{}) {
// 		fmt.Printf("哈希=%s\n", req.HashOrNumber.Hash.Hex())
// 	} else {
// 		fmt.Printf("区块号=%d\n", req.HashOrNumber.Number)
// 	}
// 	fmt.Printf("  数量: %d\n", req.Amount)
// 	fmt.Printf("  跳过: %d\n", req.Skip)
// 	fmt.Printf("  反向: %t\n", req.Reverse)
// }

// 解析区块头响应
func ParseBlockHeadersMessage(data []byte) {
	fmt.Println("解析区块头响应:")
	var resp eth.BlockHeadersPacket
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", resp.RequestId)
	fmt.Printf("  区块头数量: %d\n", len(resp.BlockHeadersRequest))
	for i, header := range resp.BlockHeadersRequest {
		fmt.Printf("  区块头 %d: 高度=%d, 哈希=%s\n",
			i+1, header.Number.Uint64(), header.Hash().Hex())
		fmt.Printf("    父哈希: %s\n", header.ParentHash.Hex())
		fmt.Printf("    时间戳: %d\n", header.Time)
		fmt.Printf("    Gas限制: %d\n", header.GasLimit)
		fmt.Printf("    Gas使用: %d\n", header.GasUsed)
	}
}

// 解析获取区块体请求
func ParseGetBlockBodiesMessage(data []byte) {
	fmt.Println("解析获取区块体请求:")
	var req eth.GetBlockBodiesPacket
	if err := rlp.DecodeBytes(data, &req); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", req.RequestId)
	fmt.Printf("  请求的区块哈希数量: %d\n", len(req.GetBlockBodiesRequest))
	for i, hash := range req.GetBlockBodiesRequest {
		fmt.Printf("  哈希 %d: %s\n", i+1, hash.Hex())
	}
}

// 解析区块体响应
func ParseBlockBodiesMessage(data []byte) {
	fmt.Println("解析区块体响应:")
	var resp eth.BlockBodiesPacket
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", resp.RequestId)
	fmt.Printf("  区块体数量: %d\n", len(resp.BlockBodiesResponse))
	for i, body := range resp.BlockBodiesResponse {
		fmt.Printf("  区块体 %d:\n", i+1)
		fmt.Printf("    交易数量: %d\n", len(body.Transactions))
		fmt.Printf("    叔块数量: %d\n", len(body.Uncles))
		if body.Withdrawals != nil {
			fmt.Printf("    提取数量: %d\n", len(body.Withdrawals))
		}
	}
}

// 解析获取收据请求
func ParseGetReceiptsMessage(data []byte) {
	fmt.Println("解析获取收据请求:")
	var req eth.GetReceiptsPacket
	if err := rlp.DecodeBytes(data, &req); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", req.RequestId)
	fmt.Printf("  请求的区块哈希数量: %d\n", len(req.GetReceiptsRequest))
	for i, hash := range req.GetReceiptsRequest {
		fmt.Printf("  哈希 %d: %s\n", i+1, hash.Hex())
	}
}

// 解析收据响应 (简化版，实际需要根据协议版本处理)
func ParseReceiptsMessage(data []byte) {
	fmt.Println("解析收据响应:")
	// 注意：收据消息的解析比较复杂，因为有不同的协议版本
	// 这里提供一个基本的解析框架
	var receipts [][]*types.Receipt
	if err := rlp.DecodeBytes(data, &receipts); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  区块数量: %d\n", len(receipts))
	for i, blockReceipts := range receipts {
		fmt.Printf("  区块 %d 收据数量: %d\n", i+1, len(blockReceipts))
		for j, receipt := range blockReceipts {
			fmt.Printf("    收据 %d: 状态=%d, Gas使用=%d\n",
				j+1, receipt.Status, receipt.CumulativeGasUsed)
			fmt.Printf("      日志数量: %d\n", len(receipt.Logs))
		}
	}
}

// 解析获取池化交易请求
func ParseGetPooledTransactionsMessage(data []byte) {
	fmt.Println("解析获取池化交易请求:")
	var req eth.GetPooledTransactionsPacket
	if err := rlp.DecodeBytes(data, &req); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", req.RequestId)
	fmt.Printf("  请求的交易哈希数量: %d\n", len(req.GetPooledTransactionsRequest))
	for i, hash := range req.GetPooledTransactionsRequest {
		fmt.Printf("  哈希 %d: %s\n", i+1, hash.Hex())
	}
}

// 解析池化交易响应
func ParsePooledTransactionsMessage(data []byte) {
	fmt.Println("解析池化交易响应:")
	var resp eth.PooledTransactionsPacket
	if err := rlp.DecodeBytes(data, &resp); err != nil {
		fmt.Printf("解析错误: %v\n", err)
		return
	}
	fmt.Printf("  请求ID: %d\n", resp.RequestId)
	fmt.Printf("  交易数量: %d\n", len(resp.PooledTransactionsResponse))
	for i, tx := range resp.PooledTransactionsResponse {
		fmt.Printf("  交易 %d: 哈希=%s, Nonce=%d\n",
			i+1, tx.Hash().Hex(), tx.Nonce())
	}
}

// 通用RLP解析 - 当不知道具体消息类型时使用
func ParseGenericRLP(data []byte) {
	fmt.Println("通用RLP解析:")

	// 创建RLP流
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))

	// 检查数据类型
	kind, size, err := stream.Kind()
	if err != nil {
		fmt.Printf("无法确定RLP类型: %v\n", err)
		return
	}

	switch kind {
	case rlp.Byte:
		fmt.Printf("  类型: 单字节\n")
		b, err := stream.Uint8()
		if err != nil {
			fmt.Printf("  解析错误: %v\n", err)
		} else {
			fmt.Printf("  值: 0x%02x (%d)\n", b, b)
		}
	case rlp.String:
		fmt.Printf("  类型: 字符串/字节数组\n")
		fmt.Printf("  长度: %d\n", size)
		b, err := stream.Bytes()
		if err != nil {
			fmt.Printf("  解析错误: %v\n", err)
		} else {
			fmt.Printf("  值: %x\n", b)
			if len(b) <= 32 { // 如果数据不太长，尝试显示为字符串
				fmt.Printf("  字符串: %q\n", string(b))
			}
		}
	case rlp.List:
		fmt.Printf("  类型: 列表\n")
		fmt.Printf("  大小: %d 字节\n", size)

		// 尝试解析为通用接口切片
		var items []interface{}
		stream.Reset(bytes.NewReader(data), uint64(len(data)))
		if err := stream.Decode(&items); err != nil {
			fmt.Printf("  解析列表错误: %v\n", err)
		} else {
			fmt.Printf("  元素数量: %d\n", len(items))
			for i, item := range items {
				fmt.Printf("  元素 %d: %T = %v\n", i, item, item)
			}
		}
	}
}

// 使用p2p.Msg结构解析消息的便捷函数
func ParseP2PMessage(msg p2p.Msg) {
	fmt.Printf("P2P消息解析:\n")
	fmt.Printf("  消息代码: 0x%02x\n", msg.Code)
	fmt.Printf("  消息大小: %d 字节\n", msg.Size)
	fmt.Printf("  接收时间: %v\n", msg.ReceivedAt)

	// 读取消息内容
	data := make([]byte, msg.Size)
	if _, err := msg.Payload.Read(data); err != nil {
		fmt.Printf("  读取消息内容错误: %v\n", err)
		return
	}

	// 解析消息内容
	ParseRLPxData(msg.Code, data)
}

// func main() {
// 	fmt.Println("RLPx数据解析示例")
// 	fmt.Println("=================")

// 	// 示例1: 解析状态消息
// 	fmt.Println("\n示例1: 状态消息")
// 	statusData := common.FromHex("f84927808405f5e1008405f5e100a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000c6c0c0")
// 	ParseRLPxData(eth.StatusMsg, statusData)

// 	// 示例2: 解析获取区块头请求
// 	fmt.Println("\n示例2: 获取区块头请求")
// 	headerReqData := common.FromHex("e8820457e4a000000000000000000000000000000000000000000000000000000000deadc0de050580")
// 	ParseRLPxData(eth.GetBlockHeadersMsg, headerReqData)

// 	// 示例3: 通用RLP解析
// 	fmt.Println("\n示例3: 通用RLP解析")
// 	genericData := common.FromHex("c483646f67")
// 	ParseRLPxData(0xFF, genericData) // 使用未知消息代码

// 	fmt.Println("\n解析完成!")
// 	fmt.Println("\n使用说明:")
// 	fmt.Println("1. 从RLPx连接的Read方法获取code和data")
// 	fmt.Println("2. 调用ParseRLPxData(code, data)进行解析")
// 	fmt.Println("3. 根据消息类型查看相应的解析结果")
// 	fmt.Println("4. 对于未知消息类型，会进行通用RLP解析")
// }
