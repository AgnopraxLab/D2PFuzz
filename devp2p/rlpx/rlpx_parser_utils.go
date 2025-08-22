package rlpx

import (
	"bytes"
	"fmt"

	// "reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// RLPxDataParser RLPx数据解析器
type RLPxDataParser struct{}

// NewRLPxDataParser 创建新的解析器实例
func NewRLPxDataParser() *RLPxDataParser {
	return &RLPxDataParser{}
}

// ParseToHex 将data转换为十六进制字符串显示
func (p *RLPxDataParser) ParseToHex(data []byte) string {
	return hexutil.Encode(data)
}

// ParseToString 尝试将data解析为字符串（如果是可打印字符）
func (p *RLPxDataParser) ParseToString(data []byte) string {
	// 检查是否为可打印ASCII字符
	for _, b := range data {
		if b < 32 || b > 126 {
			return "<非可打印字符>"
		}
	}
	return string(data)
}

// ParseRLPStructure 解析RLP数据结构
func (p *RLPxDataParser) ParseRLPStructure(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空数据")
	}

	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	kind, _, err := stream.Kind()
	if err != nil {
		return nil, fmt.Errorf("无法确定RLP类型: %v", err)
	}

	switch kind {
	case rlp.Byte:
		b, err := stream.Uint8()
		if err != nil {
			return nil, err
		}
		return b, nil

	case rlp.String:
		b, err := stream.Bytes()
		if err != nil {
			return nil, err
		}
		return b, nil

	case rlp.List:
		// 尝试解析为通用列表
		var items []interface{}
		stream.Reset(bytes.NewReader(data), uint64(len(data)))
		if err := stream.Decode(&items); err != nil {
			return nil, fmt.Errorf("解析列表失败: %v", err)
		}
		return items, nil

	default:
		return nil, fmt.Errorf("未知RLP类型")
	}
}

// ParseAsUint64 尝试将data解析为uint64
func (p *RLPxDataParser) ParseAsUint64(data []byte) (uint64, error) {
	var value uint64
	err := rlp.DecodeBytes(data, &value)
	return value, err
}

// ParseAsString 尝试将data解析为字符串
func (p *RLPxDataParser) ParseAsString(data []byte) (string, error) {
	var value string
	err := rlp.DecodeBytes(data, &value)
	return value, err
}

// ParseAsBytes 尝试将data解析为字节数组
func (p *RLPxDataParser) ParseAsBytes(data []byte) ([]byte, error) {
	var value []byte
	err := rlp.DecodeBytes(data, &value)
	return value, err
}

// ParseAsHash 尝试将data解析为哈希
func (p *RLPxDataParser) ParseAsHash(data []byte) (common.Hash, error) {
	var hash common.Hash
	err := rlp.DecodeBytes(data, &hash)
	return hash, err
}

// ParseAsAddress 尝试将data解析为地址
func (p *RLPxDataParser) ParseAsAddress(data []byte) (common.Address, error) {
	var addr common.Address
	err := rlp.DecodeBytes(data, &addr)
	return addr, err
}

// ParseAsList 尝试将data解析为列表
func (p *RLPxDataParser) ParseAsList(data []byte) ([]interface{}, error) {
	var list []interface{}
	err := rlp.DecodeBytes(data, &list)
	return list, err
}

// AnalyzeRLPData 分析RLP数据并提供多种解析结果
func (p *RLPxDataParser) AnalyzeRLPData(data []byte) {
	fmt.Printf("=== RLP数据分析 ===\n")
	fmt.Printf("原始数据长度: %d 字节\n", len(data))
	fmt.Printf("十六进制: %s\n", p.ParseToHex(data))

	if len(data) == 0 {
		fmt.Println("数据为空")
		return
	}

	// 分析RLP结构
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	kind, size, err := stream.Kind()
	if err != nil {
		fmt.Printf("RLP结构分析失败: %v\n", err)
		return
	}

	fmt.Printf("RLP类型: %s\n", kind.String())
	fmt.Printf("RLP大小: %d 字节\n", size)

	// 尝试不同的解析方式
	fmt.Println("\n=== 尝试不同解析方式 ===")

	// 1. 尝试解析为uint64
	if val, err := p.ParseAsUint64(data); err == nil {
		fmt.Printf("作为uint64: %d (0x%x)\n", val, val)
	}

	// 2. 尝试解析为字符串
	if val, err := p.ParseAsString(data); err == nil {
		fmt.Printf("作为字符串: %q\n", val)
	}

	// 3. 尝试解析为字节数组
	if val, err := p.ParseAsBytes(data); err == nil {
		fmt.Printf("作为字节数组: %x\n", val)
		if len(val) <= 50 { // 只显示较短的数据
			fmt.Printf("  可打印字符: %q\n", p.ParseToString(val))
		}
	}

	// 4. 尝试解析为哈希
	if val, err := p.ParseAsHash(data); err == nil {
		fmt.Printf("作为哈希: %s\n", val.Hex())
	}

	// 5. 尝试解析为地址
	if val, err := p.ParseAsAddress(data); err == nil {
		fmt.Printf("作为地址: %s\n", val.Hex())
	}

	// 6. 尝试解析为列表
	if val, err := p.ParseAsList(data); err == nil {
		fmt.Printf("作为列表: %d 个元素\n", len(val))
		for i, item := range val {
			if i >= 5 { // 只显示前5个元素
				fmt.Printf("  ... (还有 %d 个元素)\n", len(val)-5)
				break
			}
			fmt.Printf("  [%d]: %T = %v\n", i, item, item)
		}
	}

	// 7. 通用结构解析
	if structure, err := p.ParseRLPStructure(data); err == nil {
		fmt.Printf("通用结构: %T\n", structure)
		switch v := structure.(type) {
		case []interface{}:
			fmt.Printf("  列表长度: %d\n", len(v))
		case []byte:
			fmt.Printf("  字节长度: %d\n", len(v))
		default:
			fmt.Printf("  值: %v\n", v)
		}
	}
}

// DecodeToStruct 尝试将data解码到指定的结构体
func (p *RLPxDataParser) DecodeToStruct(data []byte, target interface{}) error {
	return rlp.DecodeBytes(data, target)
}

// GetRLPInfo 获取RLP数据的基本信息
func (p *RLPxDataParser) GetRLPInfo(data []byte) (kind rlp.Kind, size uint64, err error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("空数据")
	}
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	return stream.Kind()
}

// PrettyPrint 美化打印RLP数据
func (p *RLPxDataParser) PrettyPrint(data []byte, indent string) {
	if len(data) == 0 {
		fmt.Printf("%s<空数据>\n", indent)
		return
	}

	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	kind, size, err := stream.Kind()
	if err != nil {
		fmt.Printf("%s<解析错误: %v>\n", indent, err)
		return
	}

	switch kind {
	case rlp.Byte:
		if b, err := stream.Uint8(); err == nil {
			fmt.Printf("%sByte: 0x%02x (%d)\n", indent, b, b)
		}
	case rlp.String:
		if b, err := stream.Bytes(); err == nil {
			fmt.Printf("%sString/Bytes (%d bytes): %x\n", indent, len(b), b)
			if len(b) <= 32 {
				fmt.Printf("%s  As string: %q\n", indent, p.ParseToString(b))
			}
		}
	case rlp.List:
		fmt.Printf("%sList (%d bytes):\n", indent, size)
		if items, err := p.ParseAsList(data); err == nil {
			for i, item := range items {
				fmt.Printf("%s  [%d]: %T = %v\n", indent, i, item, item)
			}
		}
	}
}

// 使用示例函数
func DemonstrateParser() {
	fmt.Println("RLPx数据解析器使用示例")
	fmt.Println("========================")

	parser := NewRLPxDataParser()

	// 示例数据
	testData := [][]byte{
		// 单个数字
		common.FromHex("05"),
		// 字符串
		common.FromHex("83646f67"), // "dog"
		// 列表
		common.FromHex("c483646f67"), // ["dog"]
		// 复杂列表
		common.FromHex("cc83646f6783636174"), // ["dog", "cat"]
	}

	for i, data := range testData {
		fmt.Printf("\n--- 示例 %d ---\n", i+1)
		parser.AnalyzeRLPData(data)
	}
}
