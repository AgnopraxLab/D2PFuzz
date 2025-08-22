// 根据 genesis.json 文件和 rpcURL 生成 testdata 文件
// 生成的文件包括：genesis.json, chain.rlp, headstate.json, accounts.json
// 后续根据情况添加：forkenv.json, headblock.json, headfcu.json, newpayload.json, txinfo.json

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"log"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// generatorConfig is the configuration of the chain generator.
type generatorConfig struct {
	// genesis options
	forkInterval int    // number of blocks between forks
	lastFork     string // last enabled fork
	merged       bool   // create a proof-of-stake chain

	// chain options
	txInterval  int // frequency of blocks containing transactions
	txCount     int // number of txs in block
	chainLength int // number of generated blocks

	// output options
	outputs   []string // enabled outputs
	outputDir string   // path where output files should be placed

	client    *ethclient.Client
	rpcClient *rpc.Client
}

// generator is the central object in the chain generation process.
// It holds the configuration, state, and all instantiated transaction generators.
type generator struct {
	cfg      generatorConfig
	genesis  *core.Genesis
	td       *big.Int
	accounts []genAccount
	rand     *rand.Rand

	// Modifier lists.
	virgins   []*modifierInstance
	mods      []*modifierInstance
	modOffset int

	// for write/export
	blockchain *core.BlockChain
	clRequests map[uint64][][]byte
}

type modifierInstance struct {
	name          string
	blockModifier blockModifier
}

type genAccount struct {
	addr common.Address
	key  *ecdsa.PrivateKey
}

// GenerateAll 生成所有必需的测试数据文件
func (g *generator) GenerateAll(ctx context.Context, maxBlocks int) error {
	log.Println("开始生成测试数据...")

	// 1. 生成genesis.json
	log.Println("生成genesis.json...")
	if err := g.generateGenesis(ctx); err != nil {
		return fmt.Errorf("failed to generate genesis: %v", err)
	}

	// 2. 生成chain.rlp
	log.Println("生成chain.rlp...")
	if err := g.generateChainRLP(ctx, maxBlocks); err != nil {
		return fmt.Errorf("failed to generate chain.rlp: %v", err)
	}

	// 3. 生成headstate.json
	log.Println("生成headstate.json...")
	if err := g.generateHeadState(ctx); err != nil {
		return fmt.Errorf("failed to generate headstate: %v", err)
	}

	// 4. 生成accounts.json
	log.Println("生成accounts.json...")
	if err := g.generateAccounts(ctx); err != nil {
		return fmt.Errorf("failed to generate accounts: %v", err)
	}

	log.Println("测试数据生成完成!")
	return nil
}

// generateGenesis 生成genesis.json文件
func (g *generator) generateGenesis(ctx context.Context) error {
	// 获取创世块
	genesisBlock, err := g.cfg.client.BlockByNumber(ctx, big.NewInt(0))
	if err != nil {
		return fmt.Errorf("failed to get genesis block: %v", err)
	}

	// 获取链ID
	chainID, err := g.cfg.client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %v", err)
	}

	// 获取创世状态
	var genesisAlloc map[string]interface{}
	if err := g.cfg.rpcClient.CallContext(ctx, &genesisAlloc, "debug_dumpBlock", "0x0"); err != nil {
		// 如果debug_dumpBlock不可用，尝试其他方法
		log.Printf("debug_dumpBlock不可用，使用默认配置: %v", err)
		genesisAlloc = make(map[string]interface{})
	}

	// 构建genesis配置
	genesis := map[string]interface{}{
		"config": map[string]interface{}{
			"chainId":                 chainID.Uint64(),
			"homesteadBlock":          0,
			"eip150Block":             0,
			"eip155Block":             0,
			"eip158Block":             0,
			"byzantiumBlock":          0,
			"constantinopleBlock":     0,
			"petersburgBlock":         0,
			"istanbulBlock":           0,
			"muirGlacierBlock":        0,
			"berlinBlock":             0,
			"londonBlock":             0,
			"arrowGlacierBlock":       0,
			"grayGlacierBlock":        0,
			"terminalTotalDifficulty": 0,
		},
		"nonce":      fmt.Sprintf("0x%x", genesisBlock.Nonce()),
		"timestamp":  fmt.Sprintf("0x%x", genesisBlock.Time()),
		"extraData":  genesisBlock.Extra(),
		"gasLimit":   fmt.Sprintf("0x%x", genesisBlock.GasLimit()),
		"difficulty": fmt.Sprintf("0x%x", genesisBlock.Difficulty()),
		"mixHash":    genesisBlock.MixDigest(),
		"coinbase":   genesisBlock.Coinbase(),
		"alloc":      genesisAlloc,
	}

	// 写入文件
	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis: %v", err)
	}

	filePath := filepath.Join(g.cfg.outputDir, "genesis.json")

	return os.WriteFile(filePath, data, 0644)
}

// generateChainRLP 生成chain.rlp文件
func (g *generator) generateChainRLP(ctx context.Context, maxBlocks int) error {
	// 获取最新区块号
	latestBlock, err := g.cfg.client.BlockByNumber(ctx, nil)

	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}

	latestBlockNum := int(latestBlock.NumberU64())
	if maxBlocks > 0 && maxBlocks < latestBlockNum {
		latestBlockNum = maxBlocks
	}
	fmt.Println("latestBlock: ", latestBlock)
	log.Printf("获取区块 1 到 %d...", latestBlockNum)

	// 创建RLP编码器
	filePath := filepath.Join(g.cfg.outputDir, "chain.rlp")

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create chain.rlp: %v", err)
	}
	defer file.Close()

	// 从区块1开始编码（跳过创世块）
	for i := 1; i <= latestBlockNum; i++ {
		block, err := g.cfg.client.BlockByNumber(ctx, big.NewInt(int64(i)))

		if err != nil {
			return fmt.Errorf("failed to get block %d: %v", i, err)
		}

		// RLP编码区块
		encoded, err := rlp.EncodeToBytes(block)
		if err != nil {
			return fmt.Errorf("failed to encode block %d: %v", i, err)
		}

		// 写入文件
		if _, err := file.Write(encoded); err != nil {
			return fmt.Errorf("failed to write block %d: %v", i, err)
		}

		if i%10 == 0 {
			log.Printf("已处理区块 %d/%d", i, latestBlockNum)
		}
	}

	return nil
}

// generateHeadState 生成headstate.json文件
func (g *generator) generateHeadState(ctx context.Context) error {
	// 获取最新区块
	latestBlock, err := g.cfg.client.BlockByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}

	blockNum := fmt.Sprintf("0x%x", latestBlock.NumberU64())

	// 尝试使用debug_dumpBlock获取状态
	var stateDump interface{}
	if err := g.cfg.rpcClient.CallContext(ctx, &stateDump, "debug_dumpBlock", blockNum); err != nil {
		log.Printf("debug_dumpBlock不可用: %v", err)
		// 创建基本的状态转储
		stateDump = map[string]interface{}{
			"root":     latestBlock.Root().Hex(),
			"accounts": map[string]interface{}{},
		}
	}

	// 写入文件
	data, err := json.MarshalIndent(stateDump, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state dump: %v", err)
	}

	filePath := filepath.Join(g.cfg.outputDir, "headstate.json")
	return os.WriteFile(filePath, data, 0644)
}

// generateAccounts 生成accounts.json文件
func (g *generator) generateAccounts(ctx context.Context) error {
	// 尝试获取节点账户
	var accounts []common.Address
	if err := g.cfg.rpcClient.CallContext(ctx, &accounts, "eth_accounts"); err != nil {

		log.Printf("无法获取节点账户: %v", err)
		// 生成一些测试账户
		accounts = g.generateTestAccounts(5)

	}

	accountMap := make(map[string]map[string]string)

	for _, addr := range accounts {
		// 为每个账户生成私钥（注意：这只是用于测试）
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %v", err)
		}

		accountMap[addr.Hex()] = map[string]string{
			"key": hexutil.Encode(crypto.FromECDSA(privateKey)),
		}
	}

	// 写入文件
	data, err := json.MarshalIndent(accountMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal accounts: %v", err)
	}

	filePath := filepath.Join(g.cfg.outputDir, "accounts.json")

	return os.WriteFile(filePath, data, 0644)
}

// generateTestAccounts 生成测试账户地址
func (g *generator) generateTestAccounts(count int) []common.Address {
	var accounts []common.Address
	for i := 0; i < count; i++ {
		privateKey, _ := crypto.GenerateKey()
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		accounts = append(accounts, address)
	}
	return accounts
}

// Close 关闭连接
func (g *generator) Close() {
	if g.cfg.client != nil {
		g.cfg.client.Close()
	}
	if g.cfg.rpcClient != nil {
		g.cfg.rpcClient.Close()
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: go run generate_testdata.go <RPC_URL> <输出目录> [最大区块数]")
		fmt.Println("示例: go run generate_testdata.go http://localhost:8545 ./testdata 100")
		os.Exit(1)
	}

	rpcURL := os.Args[1]
	outputDir := os.Args[2]
	maxBlocks := 0

	if len(os.Args) > 3 {
		if blocks, err := strconv.Atoi(os.Args[3]); err == nil {
			maxBlocks = blocks
		}
	}

	generator, err := initGenerator(rpcURL, outputDir)
	if err != nil {
		log.Fatalf("创建生成器失败: %v", err)
	}
	defer generator.Close()

	ctx := context.Background()
	if err := generator.GenerateAll(ctx, maxBlocks); err != nil {
		log.Fatalf("生成测试数据失败: %v", err)
	}

	fmt.Printf("测试数据已生成到目录: %s\n", outputDir)
	fmt.Println("生成的文件:")
	fmt.Println("- genesis.json: 创世块配置")
	fmt.Println("- chain.rlp: RLP编码的区块链数据")
	fmt.Println("- headstate.json: 最新区块的状态数据")
	fmt.Println("- accounts.json: 测试账户和私钥")
}

func initGenerator(rpcURL, outputDir string) (*generator, error) {
	// 初始化生成器
	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %v", err)
	}

	client := ethclient.NewClient(rpcClient)

	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	return &generator{
		cfg: generatorConfig{
			client:    client,
			rpcClient: rpcClient,
			outputDir: outputDir,
		},
	}, nil
}

func initGenesis() {
}

func initChain() {
}

func initAccounts() {
}
func initHeadState() {

}
