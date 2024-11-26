package fuzzer

import (
	"bytes"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

// mockNode 创建一个测试用的 enode 节点
func mock5Node(t *testing.T) *enode.Node {
	// 生成测试用的私钥
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	// 创建一个新的 enode 节点，使用生成的公钥
	ip := net.ParseIP("127.0.0.1")
	return enode.NewV4(&key.PublicKey, ip, 30303, 30303)
}

func Test5PacketStart(t *testing.T) {
	// 创建测试用例
	tests := []struct {
		name        string          // 测试用例名称
		setupMaker  func() *V5Maker // 设置 V4Maker 的函数
		wantErr     bool            // 是否期望出错
		checkOutput bool            // 是否检查输出
	}{
		{
			name: "Normal case with valid node",
			setupMaker: func() *V5Maker {
				maker := NewV5Maker("../test")
				// 设置一个 mock 节点作为目标
				maker.targetList = []*enode.Node{mock5Node(t)}
				return maker
			},
			wantErr:     false, // 期望成功执行
			checkOutput: true,  // 检查是否有日志输出
		},
		//{
		//	name: "Case with empty target list",
		//	setupMaker: func() *V4Maker {
		//		f := &filler.Filler{}
		//		maker := NewV4Maker(f, "../test")
		//		// 设置空的目标列表
		//		maker.targetList = []*enode.Node{}
		//		return maker
		//	},
		//	wantErr:     true,  // 期望出错
		//	checkOutput: false, // 不检查输出
		//},
	}

	// 运行所有测试用例
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 使用 setup 函数创建 V4Maker
			maker := tt.setupMaker()
			// 确保测试结束时关闭 maker
			defer maker.Close()

			// 创建一个缓冲区用于捕获日志输出
			var buf bytes.Buffer

			// 执行 PacketStart 函数
			err := maker.PacketStart(&buf)

			// 验证错误情况
			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}

			// 验证输出
			if tt.checkOutput {
				output := buf.String()
				assert.NotEmpty(t, output, "Expected trace output but got none")
				// 可以添加更具体的输出内容检查
				assert.Contains(t, output, "TRACE", "Expected trace prefix in output")
			}
		})
	}
}
