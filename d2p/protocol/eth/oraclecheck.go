package eth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"log"
	"math/big"
	"strings"
	"time"
)

const (
	maxPendingTransactions = 10000 // 最大允许的待处理交易数量
	cleanupThreshold       = 3000  // 清理后保留的交易数量（约为最大值的30%）
)

// OracleState 用于维护Oracle的状态
type OracleState struct {
	LatestBlockNumber       uint64
	TotalDifficulty         *big.Int
	AccountBalances         map[common.Address]string
	AccountNonces           map[common.Address]uint64
	BlockHashes             map[uint64]common.Hash
	NetworkID               uint64
	ProtocolVersion         uint32
	GenesisHash             common.Hash
	PacketHistory           []interface{}
	GasLimit                uint64
	GenesisConfig           *params.ChainConfig
	GenesisBlock            *types.Block
	GenesisAlloc            types.GenesisAlloc
	CurrentHeader           *types.Header
	Senders                 map[common.Address]uint64
	PendingTransactions     []*types.Transaction
	PendingTransactionMap   map[common.Hash]*types.Transaction
	PendingTransactionTypes map[common.Hash]byte
	PendingTransactionSizes map[common.Hash]uint32
	LastPendingUpdateTime   time.Time
}

// NewOracleState 创建一个新的OracleState
func NewOracleState() *OracleState {
	return &OracleState{
		TotalDifficulty:         new(big.Int),
		AccountBalances:         make(map[common.Address]string),
		AccountNonces:           make(map[common.Address]uint64),
		BlockHashes:             make(map[uint64]common.Hash),
		PacketHistory:           make([]interface{}, 0),
		Senders:                 make(map[common.Address]uint64),
		PendingTransactions:     make([]*types.Transaction, 0),
		PendingTransactionMap:   make(map[common.Hash]*types.Transaction),
		PendingTransactionTypes: make(map[common.Hash]byte),
		PendingTransactionSizes: make(map[common.Hash]uint32),
	}
}

// InitOracleState 初始化Oracle状态
func InitOracleState(client *Suite) *OracleState {
	state := NewOracleState()

	chain := client.chain

	// 设置基本信息
	state.LatestBlockNumber = uint64(len(chain.blocks) - 1)
	state.TotalDifficulty.Set(chain.blocks[len(chain.blocks)-1].Difficulty())
	state.GenesisHash = chain.blocks[0].Hash()
	state.GasLimit = chain.genesis.GasLimit

	// 复制账户状态
	for addr, account := range chain.state {
		state.AccountBalances[addr] = account.Balance
		state.AccountNonces[addr] = account.Nonce
	}

	// 复制区块哈希
	for i, block := range chain.blocks {
		state.BlockHashes[uint64(i)] = block.Hash()
	}

	// 设置网络ID和协议版本
	state.NetworkID = chain.config.ChainID.Uint64()
	state.ProtocolVersion = 66 // 假设使用的是ETH66协议版本

	// 复制创世块配置
	state.GenesisConfig = chain.config
	state.GenesisAlloc = chain.genesis.Alloc
	state.GenesisBlock = chain.blocks[0] // check client.chain.blocks[0] 是否为创世区块

	// 设置当前区块头
	state.CurrentHeader = chain.blocks[len(chain.blocks)-1].Header()

	// 复制发送者信息
	for addr, info := range chain.senders {
		state.Senders[addr] = info.Nonce
	}

	return state
}

// OracleCheck 检查并修正生成的数据包，然后更新Oracle状态
func OracleCheck(packet interface{}, state *OracleState, s *Suite) (interface{}, error) {
	var checkedPacket interface{}
	var err error

	switch p := packet.(type) {
	case *StatusPacket:
		checkedPacket, err = checkStatusPacket(p, state)
	case *NewBlockHashesPacket:
		checkedPacket, err = checkNewBlockHashesPacket(p, state)
	case *TransactionsPacket:
		checkedPacket, err = checkTransactionsPacket(p, state, s)
	case *GetBlockHeadersPacket:
		checkedPacket, err = checkGetBlockHeadersPacket(p, state)
	case *BlockHeadersPacket:
		checkedPacket, err = checkBlockHeadersPacket(p, state)
	case *GetBlockBodiesPacket:
		checkedPacket, err = checkGetBlockBodiesPacket(p, state)
	case *BlockBodiesPacket:
		checkedPacket, err = checkBlockBodiesPacket(p, state)
	case *NewBlockPacket:
		checkedPacket, err = checkNewBlockPacket(p, state)
	case *NewPooledTransactionHashesPacket:
		checkedPacket, err = checkNewPooledTransactionHashesPacket(p, state)
	case *GetPooledTransactionsPacket:
		checkedPacket, err = checkGetPooledTransactionsPacket(p, state)
	case *PooledTransactionsPacket:
		checkedPacket, err = checkPooledTransactionsPacket(p, state)
	case *GetReceiptsPacket:
		checkedPacket, err = checkGetReceiptsPacket(p, state)
	case *ReceiptsPacket:
		checkedPacket, err = checkReceiptsPacket(p, state)
	default:
		log.Printf("Unknown packet type: %T", packet)
		return packet, nil
	}

	if err != nil {
		return nil, fmt.Errorf("packet check failed: %v", err)
	}

	// 更新Oracle状态
	if err := updateOracleState(checkedPacket, state); err != nil {
		return nil, fmt.Errorf("failed to update oracle state: %v", err)
	}

	return checkedPacket, nil
}

func checkStatusPacket(p *StatusPacket, state *OracleState) (*StatusPacket, error) {
	// 1. 包自身的逻辑检验
	if p.ProtocolVersion == 0 {
		return nil, errors.New("invalid protocol version")
	}
	if p.NetworkID == 0 {
		return nil, errors.New("invalid network ID")
	}
	if p.TD == nil || p.TD.Sign() <= 0 {
		return nil, errors.New("invalid total difficulty")
	}
	if p.Head == (common.Hash{}) {
		return nil, errors.New("invalid head hash")
	}
	if p.Genesis == (common.Hash{}) {
		return nil, errors.New("invalid genesis hash")
	}
	currentForkID := forkid.NewID(state.GenesisConfig, state.GenesisBlock, state.LatestBlockNumber, state.CurrentHeader.Time)
	if p.ForkID != currentForkID {
		p.ForkID = currentForkID
	}

	// 2. 对照state检验包的数据是否正确，如果错误，改为state的状态
	if p.ProtocolVersion != state.ProtocolVersion {
		p.ProtocolVersion = state.ProtocolVersion
	}
	if p.NetworkID != state.NetworkID {
		p.NetworkID = state.NetworkID
	}
	if p.TD.Cmp(state.TotalDifficulty) != 0 {
		p.TD = new(big.Int).Set(state.TotalDifficulty)
	}
	if p.Head != state.BlockHashes[state.LatestBlockNumber] {
		p.Head = state.BlockHashes[state.LatestBlockNumber]
	}
	if p.Genesis != state.GenesisHash {
		p.Genesis = state.GenesisHash
	}

	return p, nil
}

func checkNewBlockHashesPacket(p *NewBlockHashesPacket, state *OracleState) (*NewBlockHashesPacket, error) {

	validBlocks := make([]struct {
		Hash   common.Hash
		Number uint64
	}, 0)

	for _, block := range *p {
		// 确保区块号大于当前最新
		if block.Number <= state.LatestBlockNumber {
			block.Number = state.LatestBlockNumber + 1
		}

		// 检查哈希是否已存在，如果存在则生成新的哈希
		for {
			if _, exists := state.BlockHashes[block.Number]; !exists {
				break
			}
			randomBytes := make([]byte, 32)
			if _, err := rand.Read(randomBytes); err != nil {
				return nil, fmt.Errorf("failed to generate random hash: %v", err)
			}
			block.Hash = common.BytesToHash(randomBytes)
		}

		// 添加有效块
		validBlocks = append(validBlocks, block)

		// 更新为下一个预期的块号
		state.LatestBlockNumber = block.Number
	}

	// 确保块号连续
	for i := 1; i < len(validBlocks); i++ {
		if validBlocks[i].Number != validBlocks[i-1].Number+1 {
			validBlocks[i].Number = validBlocks[i-1].Number + 1
		}
	}

	*p = validBlocks
	return p, nil
}

func checkTransactionsPacket(p *TransactionsPacket, state *OracleState, s *Suite) (*TransactionsPacket, error) {
	validTxs := make([]*types.Transaction, 0)
	seenNonces := make(map[common.Address]uint64)
	invalidCount := 0

	for _, tx := range *p {
		// 1. 基本有效性检查
		if tx == nil {
			invalidCount++
			continue // 跳过空交易
		}

		// 2. 检查签名和发送者
		from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			invalidCount++
			continue // 跳过无效签名的交易
		}

		// 3. 检查 nonce
		expectedNonce, exists := seenNonces[from]
		if !exists {
			expectedNonce = state.AccountNonces[from]
		}
		if tx.Nonce() < expectedNonce {
			invalidCount++
			continue // 跳过 nonce 过低的交易
		}
		if tx.Nonce() > expectedNonce {
			// 修正 nonce
			newTx := types.NewTx(&types.DynamicFeeTx{
				ChainID:   tx.ChainId(),
				Nonce:     expectedNonce,
				GasTipCap: tx.GasTipCap(),
				GasFeeCap: tx.GasFeeCap(),
				Gas:       tx.Gas(),
				To:        tx.To(),
				Value:     tx.Value(),
				Data:      tx.Data(),
			})
			signedTx, err := s.chain.SignTx(from, newTx)
			if err != nil {
				invalidCount++
				continue // 跳过无法签名的交易
			}
			tx = signedTx
		}

		// 4. 检查 gas 相关字段
		if tx.GasFeeCap().Cmp(tx.GasTipCap()) < 0 {
			// 修正 GasFeeCap
			newTx := types.NewTx(&types.DynamicFeeTx{
				ChainID:   tx.ChainId(),
				Nonce:     tx.Nonce(),
				GasTipCap: tx.GasTipCap(),
				GasFeeCap: new(big.Int).Add(tx.GasTipCap(), big.NewInt(1)), // GasFeeCap = GasTipCap + 1
				Gas:       tx.Gas(),
				To:        tx.To(),
				Value:     tx.Value(),
				Data:      tx.Data(),
			})
			signedTx, err := s.chain.SignTx(from, newTx)
			if err != nil {
				invalidCount++
				continue // 跳过无法签名的交易
			}
			tx = signedTx
		}

		// 5. 检查余额是否足够支付交易
		balance, ok := new(big.Int).SetString(state.AccountBalances[from], 10)
		if !ok {
			invalidCount++
			// 如果无法解析余额字符串，记录错误并跳过这个交易
			log.Printf("Error parsing balance for address %s: %s", from.Hex(), state.AccountBalances[from])
			continue
		}
		cost := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas()))
		cost.Add(cost, tx.Value())
		if balance.Cmp(cost) < 0 {
			// 尝试修改交易金额
			maxValue := new(big.Int).Sub(balance, new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas())))
			if maxValue.Sign() > 0 {
				newTx := types.NewTx(&types.DynamicFeeTx{
					ChainID:   tx.ChainId(),
					Nonce:     tx.Nonce(),
					GasTipCap: tx.GasTipCap(),
					GasFeeCap: tx.GasFeeCap(),
					Gas:       tx.Gas(),
					To:        tx.To(),
					Value:     maxValue,
					Data:      tx.Data(),
				})
				signedTx, err := s.chain.SignTx(from, newTx)
				if err != nil {
					invalidCount++
					continue // 跳过无法签名的交易
				}
				tx = signedTx
				log.Printf("Modified transaction value for address %s: original %s, new %s", from.Hex(), tx.Value().String(), maxValue.String())
			} else {
				invalidCount++
				log.Printf("Insufficient balance for address %s: balance %s, required %s", from.Hex(), balance.String(), cost.String())
				continue
			}
		}
		// 将有效交易添加到列表
		validTxs = append(validTxs, tx)
		seenNonces[from] = tx.Nonce() + 1
	}

	*p = validTxs
	log.Printf("Total invalid transactions: %d", invalidCount)
	return p, nil
}

func checkGetBlockHeadersPacket(p *GetBlockHeadersPacket, state *OracleState) (*GetBlockHeadersPacket, error) {
	// GetBlockHeadersPacket 不用check
	return p, nil
}

func checkBlockHeadersPacket(p *BlockHeadersPacket, state *OracleState) (*BlockHeadersPacket, error) {
	var warnings []string
	validHeaders := make([]*types.Header, 0, len(p.BlockHeadersRequest))

	for _, header := range p.BlockHeadersRequest {
		if header == nil {
			warnings = append(warnings, "skipped nil header")
			continue
		}

		blockNumber := header.Number.Uint64()

		// 检查区块号是否超过了当前已知的最新区块
		if blockNumber > state.LatestBlockNumber {
			warnings = append(warnings, fmt.Sprintf("block number %d exceeds latest known block %d", blockNumber, state.LatestBlockNumber))
		}

		// 检查区块哈希是否与已知的哈希一致
		knownHash, exists := state.BlockHashes[blockNumber]
		if exists && knownHash != header.Hash() {
			warnings = append(warnings, fmt.Sprintf("hash mismatch for block %d: expected %s, got %s", blockNumber, knownHash.Hex(), header.Hash().Hex()))
		}

		validHeaders = append(validHeaders, header)
	}

	p.BlockHeadersRequest = validHeaders

	if len(warnings) > 0 {
		log.Printf("BlockHeadersPacket warnings: %s", strings.Join(warnings, "; "))
	}

	return p, nil
}
func checkGetBlockBodiesPacket(p *GetBlockBodiesPacket, state *OracleState) (*GetBlockBodiesPacket, error) {
	// GetBlockHeadersPacket 不用check
	return p, nil
}

func checkBlockBodiesPacket(p *BlockBodiesPacket, state *OracleState) (*BlockBodiesPacket, error) {
	var warnings []string

	for i, body := range p.BlockBodiesResponse {
		if body == nil {
			warnings = append(warnings, fmt.Sprintf("skipped nil body at index %d", i))
			continue
		}
	}

	if len(warnings) > 0 {
		log.Printf("BlockBodiesPacket warnings: %s", strings.Join(warnings, "; "))
	}

	return p, nil
}

func checkNewBlockPacket(p *NewBlockPacket, state *OracleState) (*NewBlockPacket, error) {
	header := p.Block.Header()

	// 检查区块号
	expectedNumber := new(big.Int).Add(state.CurrentHeader.Number, common.Big1)
	if header.Number.Cmp(expectedNumber) != 0 {
		return nil, fmt.Errorf("invalid block number: got %v, want %v", header.Number, expectedNumber)
	}

	// 检查父哈希
	if header.ParentHash != state.CurrentHeader.Hash() {
		return nil, fmt.Errorf("invalid parent hash: got %v, want %v", header.ParentHash, state.CurrentHeader.Hash())
	}

	// 检查gas limit
	if header.GasLimit != state.GasLimit {
		return nil, fmt.Errorf("invalid gas limit: got %v, want %v", header.GasLimit, state.GasLimit)
	}

	// 检查时间戳
	if header.Time <= state.CurrentHeader.Time {
		return nil, fmt.Errorf("invalid timestamp: got %v, not after %v", header.Time, state.CurrentHeader.Time)
	}

	// 检查总难度
	expectedTD := new(big.Int).Add(state.TotalDifficulty, header.Difficulty)
	if p.TD.Cmp(expectedTD) != 0 {
		return nil, fmt.Errorf("invalid total difficulty: got %v, want %v", p.TD, expectedTD)
	}
	// 验证交易
	validTxs := make([]*types.Transaction, 0)
	seenNonces := make(map[common.Address]uint64)
	invalidCount := 0

	for _, tx := range p.Block.Transactions() {
		// 1. 基本有效性检查
		if tx == nil {
			invalidCount++
			continue
		}

		// 2. 检查签名和发送者
		from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		if err != nil {
			invalidCount++
			continue
		}

		// 3. 检查 nonce
		expectedNonce, exists := seenNonces[from]
		if !exists {
			expectedNonce = state.AccountNonces[from]
		}
		if tx.Nonce() < expectedNonce {
			invalidCount++
			continue
		}

		// 4. 检查 gas 相关字段
		if tx.GasFeeCap().Cmp(tx.GasTipCap()) < 0 {
			invalidCount++
			continue
		}

		// 5. 检查余额是否足够支付交易
		balance, ok := new(big.Int).SetString(state.AccountBalances[from], 10)
		if !ok {
			invalidCount++
			continue
		}
		cost := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas()))
		cost.Add(cost, tx.Value())
		if balance.Cmp(cost) < 0 {
			invalidCount++
			continue
		}

		validTxs = append(validTxs, tx)
		seenNonces[from] = tx.Nonce() + 1
	}

	if len(validTxs) != len(p.Block.Transactions()) {
		return nil, fmt.Errorf("invalid transactions: %d out of %d are invalid", invalidCount, len(p.Block.Transactions()))
	}

	return p, nil
}

func checkNewPooledTransactionHashesPacket(p *NewPooledTransactionHashesPacket, state *OracleState) (*NewPooledTransactionHashesPacket, error) {
	validIndices := make([]int, 0, len(p.Types))
	seenHashes := make(map[common.Hash]struct{})
	var invalidCount int

	for i, txType := range p.Types {
		isValid := true

		// 检查交易类型是否有效
		if txType > 2 {
			log.Printf("Invalid transaction type at index %d: %d", i, txType)
			isValid = false
		}

		// 检查交易大小是否合理
		if p.Sizes[i] == 0 || p.Sizes[i] > 128*1024 { // 假设最大交易大小为 128KB
			log.Printf("Invalid transaction size at index %d: %d", i, p.Sizes[i])
			isValid = false
		}

		// 检查是否有重复的哈希
		if _, exists := seenHashes[p.Hashes[i]]; exists {
			log.Printf("Duplicate transaction hash at index %d: %s", i, p.Hashes[i].Hex())
			isValid = false
		}

		// 检查哈希是否为零值
		if p.Hashes[i] == (common.Hash{}) {
			log.Printf("Zero hash at index %d", i)
			isValid = false
		}

		if isValid {
			validIndices = append(validIndices, i)
			seenHashes[p.Hashes[i]] = struct{}{}
		} else {
			invalidCount++
		}
	}
	// 如果有无效交易，修改原始包
	if invalidCount > 0 {
		newTypes := make([]byte, len(validIndices))
		newSizes := make([]uint32, len(validIndices))
		newHashes := make([]common.Hash, len(validIndices))

		for newIndex, oldIndex := range validIndices {
			newTypes[newIndex] = p.Types[oldIndex]
			newSizes[newIndex] = p.Sizes[oldIndex]
			newHashes[newIndex] = p.Hashes[oldIndex]
		}

		p.Types = newTypes
		p.Sizes = newSizes
		p.Hashes = newHashes

		log.Printf("Removed %d invalid transactions from NewPooledTransactionHashesPacket", invalidCount)
	}

	return p, nil
}

func checkGetPooledTransactionsPacket(p *GetPooledTransactionsPacket, state *OracleState) (*GetPooledTransactionsPacket, error) {
	// 实现 GetPooledTransactionsPacket 的检查逻辑
	return p, nil
}

func checkPooledTransactionsPacket(p *PooledTransactionsPacket, state *OracleState) (*PooledTransactionsPacket, error) {
	if p == nil {
		return nil, errors.New("nil PooledTransactionsPacket")
	}

	if len(p.PooledTransactionsResponse) == 0 {
		return nil, errors.New("empty PooledTransactionsPacket")
	}

	validTxs := make([]*types.Transaction, 0, len(p.PooledTransactionsResponse))
	seenHashes := make(map[common.Hash]bool)

	for _, tx := range p.PooledTransactionsResponse {
		if tx == nil {
			continue // 跳过空交易
		}

		txHash := tx.Hash()
		if seenHashes[txHash] {
			continue // 跳过重复交易
		}
		seenHashes[txHash] = true

		validTxs = append(validTxs, tx)
	}

	if len(validTxs) == 0 {
		return nil, errors.New("no valid transactions in packet after filtering")
	}

	// 创建新的包，只包含非空且不重复的交易
	newPacket := &PooledTransactionsPacket{
		RequestId:                  p.RequestId,
		PooledTransactionsResponse: validTxs,
	}

	log.Printf("Processed PooledTransactionsPacket: %d/%d transactions after filtering",
		len(validTxs), len(p.PooledTransactionsResponse))

	return newPacket, nil
}

func checkGetReceiptsPacket(p *GetReceiptsPacket, state *OracleState) (*GetReceiptsPacket, error) {
	// 实现 GetReceiptsPacket 的检查逻辑
	return p, nil
}

func checkReceiptsPacket(p *ReceiptsPacket, state *OracleState) (*ReceiptsPacket, error) {
	if p == nil {
		return nil, errors.New("nil ReceiptsPacket")
	}

	if len(p.ReceiptsResponse) == 0 {
		return nil, errors.New("empty ReceiptsPacket")
	}

	validReceipts := make([][]*types.Receipt, 0, len(p.ReceiptsResponse))

	for blockIndex, blockReceipts := range p.ReceiptsResponse {
		if len(blockReceipts) == 0 {
			// 跳过空的区块收据
			continue
		}

		validBlockReceipts := make([]*types.Receipt, 0, len(blockReceipts))

		for txIndex, receipt := range blockReceipts {
			if receipt == nil {
				// 跳过空的收据
				continue
			}

			// 基本检查
			if receipt.TxHash == (common.Hash{}) {
				log.Printf("Invalid TxHash for receipt at block %d, tx %d", blockIndex, txIndex)
				continue
			}

			if receipt.BlockHash == (common.Hash{}) {
				log.Printf("Invalid BlockHash for receipt at block %d, tx %d", blockIndex, txIndex)
				continue
			}

			if receipt.BlockNumber == nil || receipt.BlockNumber.Sign() < 0 {
				log.Printf("Invalid BlockNumber for receipt at block %d, tx %d", blockIndex, txIndex)
				continue
			}

			if receipt.TransactionIndex != uint(txIndex) {
				log.Printf("Mismatched TransactionIndex for receipt at block %d, tx %d", blockIndex, txIndex)
				continue
			}

			validBlockReceipts = append(validBlockReceipts, receipt)
		}

		if len(validBlockReceipts) > 0 {
			validReceipts = append(validReceipts, validBlockReceipts)
		}
	}

	if len(validReceipts) == 0 {
		return nil, errors.New("no valid receipts in packet after filtering")
	}

	// 创建新的包，只包含有效的收据
	newPacket := &ReceiptsPacket{
		RequestId:        p.RequestId,
		ReceiptsResponse: validReceipts,
	}

	log.Printf("Processed ReceiptsPacket: %d/%d blocks with valid receipts",
		len(validReceipts), len(p.ReceiptsResponse))

	return newPacket, nil
}

// updateOracleState 根据检查后的包更新Oracle状态
func updateOracleState(packet interface{}, state *OracleState) error {
	switch p := packet.(type) {
	case *StatusPacket:
		return nil
	case *NewBlockHashesPacket:
		for _, block := range *p {
			// 更新最新块号
			if block.Number > state.LatestBlockNumber {
				state.LatestBlockNumber = block.Number
			}

			// 更新块哈希映射
			state.BlockHashes[block.Number] = block.Hash

			// 更新总难度（这里我们假设每个块增加固定难度？）
			difficulty := big.NewInt(1) // 假设每个块难度为1
			state.TotalDifficulty.Add(state.TotalDifficulty, difficulty)

			// 更新当前头部信息
			parentHeader := state.CurrentHeader
			state.CurrentHeader = &types.Header{
				ParentHash:  parentHeader.Hash(),
				UncleHash:   types.EmptyUncleHash,  // 假设没有叔块
				Coinbase:    parentHeader.Coinbase, // 保持不变
				Root:        parentHeader.Root,     // 保持不变，因为我们没有状态变化的信息
				TxHash:      types.EmptyRootHash,   // 假设没有交易
				ReceiptHash: types.EmptyRootHash,   // 假设没有收据
				Bloom:       types.Bloom{},         // 空的 Bloom 过滤器
				Difficulty:  new(big.Int).Add(parentHeader.Difficulty, common.Big1),
				Number:      new(big.Int).SetUint64(block.Number),
				GasLimit:    parentHeader.GasLimit, // 保持不变
				GasUsed:     0,                     // 新块初始 GasUsed 为 0
				Time:        uint64(time.Now().Unix()),
				Extra:       parentHeader.Extra,   // 保持不变
				MixDigest:   common.Hash{},        // 可以保持为空
				Nonce:       types.BlockNonce{},   // 可以保持为空
				BaseFee:     parentHeader.BaseFee, // 如果支持 EIP-1559，否则为 nil
			}

			// 使用包中提供的哈希
			state.CurrentHeader.Hash()

			// 其他可选字段保持不变
			if parentHeader.WithdrawalsHash != nil {
				state.CurrentHeader.WithdrawalsHash = parentHeader.WithdrawalsHash
			}
			if parentHeader.BlobGasUsed != nil {
				state.CurrentHeader.BlobGasUsed = new(uint64)
			}
			if parentHeader.ExcessBlobGas != nil {
				state.CurrentHeader.ExcessBlobGas = new(uint64)
			}
			if parentHeader.ParentBeaconRoot != nil {
				state.CurrentHeader.ParentBeaconRoot = parentHeader.ParentBeaconRoot
			}
		}
	case *TransactionsPacket:
		for _, tx := range *p {
			from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
			if err != nil {
				continue // 跳过无效签名的交易
			}

			// 更新 nonce
			if tx.Nonce() >= state.AccountNonces[from] {
				state.AccountNonces[from] = tx.Nonce() + 1
			}

			// 更新余额（预估）
			balance, ok := new(big.Int).SetString(state.AccountBalances[from], 10)
			if !ok {
				continue // 跳过无法解析余额的账户
			}
			cost := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas()))
			cost.Add(cost, tx.Value())
			newBalance := new(big.Int).Sub(balance, cost)
			if newBalance.Sign() >= 0 {
				state.AccountBalances[from] = newBalance.String()
			}

			// 更新接收方余额（如果有）
			if tx.To() != nil {
				toBalance, ok := new(big.Int).SetString(state.AccountBalances[*tx.To()], 10)
				if ok {
					newToBalance := new(big.Int).Add(toBalance, tx.Value())
					state.AccountBalances[*tx.To()] = newToBalance.String()
				}
			}

			// 将交易添加到模拟的交易池
			state.PendingTransactions = append(state.PendingTransactions, tx)
		}
	case *BlockHeadersPacket:
		//blockheader包不会改变链状态
		return nil
	case *BlockBodiesPacket:
		//blockheader包不会改变链状态
		return nil
	case *NewBlockPacket:
		// 更新最新块号
		if p.Block.NumberU64() > state.LatestBlockNumber {
			state.LatestBlockNumber = p.Block.NumberU64()
		}

		// 更新块哈希映射
		state.BlockHashes[p.Block.NumberU64()] = p.Block.Hash()

		// 更新总难度
		state.TotalDifficulty = new(big.Int).Set(p.TD)

		// 更新当前头部信息
		state.CurrentHeader = p.Block.Header()

		// 处理区块中的交易
		for _, tx := range p.Block.Transactions() {
			from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
			if err != nil {
				continue // 跳过无效签名的交易
			}

			// 更新 nonce
			if tx.Nonce() >= state.AccountNonces[from] {
				state.AccountNonces[from] = tx.Nonce() + 1
			}

			// 更新发送方余额
			balance, ok := new(big.Int).SetString(state.AccountBalances[from], 10)
			if !ok {
				continue // 跳过无法解析余额的账户
			}
			cost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
			cost.Add(cost, tx.Value())
			newBalance := new(big.Int).Sub(balance, cost)
			if newBalance.Sign() >= 0 {
				state.AccountBalances[from] = newBalance.String()
			}

			// 更新接收方余额（如果有）
			if tx.To() != nil {
				toBalance, ok := new(big.Int).SetString(state.AccountBalances[*tx.To()], 10)
				if ok {
					newToBalance := new(big.Int).Add(toBalance, tx.Value())
					state.AccountBalances[*tx.To()] = newToBalance.String()
				}
			}
		}

		// 更新 Gas Limit
		state.GasLimit = p.Block.GasLimit()

		// 从待处理交易池中移除已包含在此区块中的交易
		newPendingTxs := make([]*types.Transaction, 0)
		for _, pendingTx := range state.PendingTransactions {
			included := false
			for _, blockTx := range p.Block.Transactions() {
				if pendingTx.Hash() == blockTx.Hash() {
					included = true
					break
				}
			}
			if !included {
				newPendingTxs = append(newPendingTxs, pendingTx)
			}
		}
		state.PendingTransactions = newPendingTxs
	case *NewPooledTransactionHashesPacket:
		newHashesCount := 0
		for i, hash := range p.Hashes {
			if _, exists := state.PendingTransactionMap[hash]; !exists {
				// 我们只存储哈希和元数据，因为我们还没有完整的交易
				state.PendingTransactionMap[hash] = nil
				state.PendingTransactionTypes[hash] = p.Types[i]
				state.PendingTransactionSizes[hash] = p.Sizes[i]
				newHashesCount++
			}
		}

		log.Printf("Added %d new transaction hashes to pending pool. Total pending: %d",
			newHashesCount, len(state.PendingTransactionMap))

		// 调用简化的清理函数
		cleanupPendingTransactions(state)
	case *GetPooledTransactionsPacket:
		return nil
	case *PooledTransactionsPacket:
		return nil
	case *ReceiptsPacket:
		return nil
	// 其他包类型的状态更新...
	default:
		// 对于不需要更新状态的包类型，不做任何操作
	}

	return nil
}

func cleanupPendingTransactions(state *OracleState) {
	if len(state.PendingTransactionMap) <= maxPendingTransactions {
		return // 不需要清理
	}

	// 将所有交易哈希放入一个切片
	hashes := make([]common.Hash, 0, len(state.PendingTransactionMap))
	for hash := range state.PendingTransactionMap {
		hashes = append(hashes, hash)
	}

	// 计算需要删除的数量
	removeCount := len(hashes) - cleanupThreshold

	// 删除最旧的交易（假设最旧的交易在切片的前面）
	for i := 0; i < removeCount; i++ {
		hash := hashes[i]
		delete(state.PendingTransactionMap, hash)
		delete(state.PendingTransactionTypes, hash)
		delete(state.PendingTransactionSizes, hash)
	}

	// 更新 PendingTransactions 切片
	newPendingTxs := make([]*types.Transaction, 0, cleanupThreshold)
	for _, tx := range state.PendingTransactions {
		if _, exists := state.PendingTransactionMap[tx.Hash()]; exists {
			newPendingTxs = append(newPendingTxs, tx)
		}
	}
	state.PendingTransactions = newPendingTxs

	log.Printf("Cleaned up pending transactions. Removed: %d, New count: %d", removeCount, len(state.PendingTransactionMap))
}
