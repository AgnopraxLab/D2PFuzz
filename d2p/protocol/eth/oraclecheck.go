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
	"time"
)

// OracleState 用于维护Oracle的状态
type OracleState struct {
	LatestBlockNumber   uint64
	TotalDifficulty     *big.Int
	AccountBalances     map[common.Address]string
	AccountNonces       map[common.Address]uint64
	BlockHashes         map[uint64]common.Hash
	NetworkID           uint64
	ProtocolVersion     uint32
	GenesisHash         common.Hash
	PacketHistory       []interface{}
	GenesisConfig       *params.ChainConfig
	GenesisBlock        *types.Block
	GenesisAlloc        types.GenesisAlloc
	CurrentHeader       *types.Header
	Senders             map[common.Address]uint64
	PendingTransactions []*types.Transaction
}

// NewOracleState 创建一个新的OracleState
func NewOracleState() *OracleState {
	return &OracleState{
		TotalDifficulty:     new(big.Int),
		AccountBalances:     make(map[common.Address]string),
		AccountNonces:       make(map[common.Address]uint64),
		BlockHashes:         make(map[uint64]common.Hash),
		PacketHistory:       make([]interface{}, 0),
		Senders:             make(map[common.Address]uint64),
		PendingTransactions: make([]*types.Transaction, 0),
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
	// 实现 GetBlockHeadersPacket 的检查逻辑
	return p, nil
}

func checkBlockHeadersPacket(p *BlockHeadersPacket, state *OracleState) (*BlockHeadersPacket, error) {
	// 实现 BlockHeadersPacket 的检查逻辑
	return p, nil
}

func checkGetBlockBodiesPacket(p *GetBlockBodiesPacket, state *OracleState) (*GetBlockBodiesPacket, error) {
	// 实现 GetBlockBodiesPacket 的检查逻辑
	return p, nil
}

func checkBlockBodiesPacket(p *BlockBodiesPacket, state *OracleState) (*BlockBodiesPacket, error) {
	// 实现 BlockBodiesPacket 的检查逻辑
	return p, nil
}

func checkNewBlockPacket(p *NewBlockPacket, state *OracleState) (*NewBlockPacket, error) {
	// 实现 NewBlockPacket 的检查逻辑
	return p, nil
}

func checkNewPooledTransactionHashesPacket(p *NewPooledTransactionHashesPacket, state *OracleState) (*NewPooledTransactionHashesPacket, error) {
	// 实现 NewPooledTransactionHashesPacket 的检查逻辑
	return p, nil
}

func checkGetPooledTransactionsPacket(p *GetPooledTransactionsPacket, state *OracleState) (*GetPooledTransactionsPacket, error) {
	// 实现 GetPooledTransactionsPacket 的检查逻辑
	return p, nil
}

func checkPooledTransactionsPacket(p *PooledTransactionsPacket, state *OracleState) (*PooledTransactionsPacket, error) {
	// 实现 PooledTransactionsPacket 的检查逻辑
	return p, nil
}

func checkGetReceiptsPacket(p *GetReceiptsPacket, state *OracleState) (*GetReceiptsPacket, error) {
	// 实现 GetReceiptsPacket 的检查逻辑
	return p, nil
}

func checkReceiptsPacket(p *ReceiptsPacket, state *OracleState) (*ReceiptsPacket, error) {
	// 实现 ReceiptsPacket 的检查逻辑
	return p, nil
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

	case *NewBlockPacket:

	// 其他包类型的状态更新...
	default:
		// 对于不需要更新状态的包类型，不做任何操作
	}

	return nil
}

/*func MultiPacketCheck(state *OracleState) error {
	var firstStatusPacket *StatusPacket

	seenHashes := make(map[common.Hash]bool)
	var lastBlockNumber uint64

	seenTxHashes := make(map[common.Hash]bool)

	var lastBlockTime uint64

	for i, packet := range state.PacketHistory {
		switch p := packet.(type) {
		case *StatusPacket:
			if firstStatusPacket == nil {
				firstStatusPacket = p
			} else {
				// 修正不一致的字段
				if p.ProtocolVersion != firstStatusPacket.ProtocolVersion {
					p.ProtocolVersion = firstStatusPacket.ProtocolVersion
				}
				if p.NetworkID != firstStatusPacket.NetworkID {
					p.NetworkID = firstStatusPacket.NetworkID
				}
				if p.Genesis != firstStatusPacket.Genesis {
					p.Genesis = firstStatusPacket.Genesis
				}
			}
			// 更新状态
			state.ProtocolVersion = p.ProtocolVersion
			state.NetworkID = p.NetworkID
			state.GenesisHash = p.Genesis
		case *NewBlockHashesPacket:
			for j, block := range *p {
				// 检查区块号是否递增
				if block.Number <= lastBlockNumber {
					(*p)[j].Number = lastBlockNumber + 1
				}
				lastBlockNumber = (*p)[j].Number

				// 检查哈希是否唯一
				if seenHashes[block.Hash] {
					// 如果哈希已存在，生成一个新的唯一哈希?????
					newHash := generateUniqueHash(seenHashes)
					(*p)[j].Hash = newHash
				}
				seenHashes[(*p)[j].Hash] = true

				// 更新状态
				state.BlockHashes[(*p)[j].Number] = (*p)[j].Hash
			}
		case *TransactionsPacket:
			validTxs := make([]*types.Transaction, 0)
			for _, tx := range *p {
				from, err := types.Sender(types.NewEIP155Signer(big.NewInt(int64(state.NetworkID))), tx)
				if err != nil {
					continue
				}

				// 检查交易哈希是否重复（跨包检查）
				if seenTxHashes[tx.Hash()] {
					continue
				}

				if balance, ok := state.AccountBalances[from]; ok && balance.Cmp(tx.Value()) >= 0 {
					if nonce, ok := state.AccountNonces[from]; ok && tx.Nonce() == nonce+1 {
						state.AccountNonces[from] = tx.Nonce()
						state.AccountBalances[from] = new(big.Int).Sub(balance, tx.Value())
						validTxs = append(validTxs, tx)
						seenTxHashes[tx.Hash()] = true
					}
				}
			}
			*p = validTxs
		case *BlockHeadersPacket:
			//记录区块头
			for i, header := range p.BlockHeadersRequest {
				state.BlockHeaders[uint64(i)] = header
			}
			for j, header := range p.BlockHeadersRequest {
				// 检查区块号是否连续
				if header.Number.Uint64() <= lastBlockNumber {
					header.Number = new(big.Int).SetUint64(lastBlockNumber + 1)
				}
				lastBlockNumber = header.Number.Uint64()

				// 检查时间戳是否递增
				if header.Time <= lastBlockTime {
					header.Time = lastBlockTime + 1
				}
				lastBlockTime = header.Time

				// 检查区块哈希是否与之前看到的一致
				if existingHash, ok := state.BlockHashes[header.Number.Uint64()]; ok {
					if existingHash != header.Hash() {
						// 如果不一致，更新区块头的哈希
						newHeader := *header
						newHeader.Hash() // 重新计算哈希
						p.BlockHeadersRequest[j] = &newHeader
					}
				}

				// 更新状态
				state.BlockHashes[header.Number.Uint64()] = p.BlockHeadersRequest[j].Hash()
			}
		case *NewBlockPacket:

			lastBlockNumber = p.Block.NumberU64()

			// 检查总难度是否递增
			if p.TD.Cmp(state.TotalDifficulty) <= 0 {
				p.TD = new(big.Int).Add(state.TotalDifficulty, p.Block.Difficulty())
			}
			state.TotalDifficulty = p.TD

			// 检查区块中的交易有效性
			validTxs := make([]*types.Transaction, 0)
			for _, tx := range p.Block.Transactions() {
				// 检查交易哈希是否重复（跨包检查）
				if seenTxHashes[tx.Hash()] {
					continue
				}

				from, err := types.Sender(types.NewEIP155Signer(big.NewInt(int64(state.NetworkID))), tx)
				if err != nil {
					continue
				}
				if balance, ok := state.AccountBalances[from]; ok && balance.Cmp(tx.Value()) >= 0 {
					if nonce, ok := state.AccountNonces[from]; ok && tx.Nonce() == nonce+1 {
						state.AccountNonces[from] = tx.Nonce()
						state.AccountBalances[from] = new(big.Int).Sub(balance, tx.Value())
						validTxs = append(validTxs, tx)
						seenTxHashes[tx.Hash()] = true
					}
				}
			}

			// 创建一个新的区块，只包含有效的交易,可能有bug
			newBlock := types.NewBlock(
				p.Block.Header(),
				&types.Body{
					Transactions: validTxs,
					Uncles:       p.Block.Uncles(),
					Withdrawals:  p.Block.Withdrawals(),
				},
				nil, // receipts
				nil, // hasher
			)
			p.Block = newBlock
			// 更新状态
			state.BlockHashes[p.Block.NumberU64()] = p.Block.Hash()
		case *BlockBodiesPacket:
			checkedPacket, err := checkBlockBodiesPacket(p, state)
			if err != nil {
				return err
			}
			state.PacketHistory[i] = checkedPacket
		case *NewPooledTransactionHashesPacket:
			for j, hash := range p.Hashes {
				if existingType, ok := state.TransactionTypes[hash]; ok {
					if existingType != p.Types[j] {
						return fmt.Errorf("inconsistent transaction type for hash %s", hash.Hex())
					}
				}
				if existingSize, ok := state.TransactionSizes[hash]; ok {
					if existingSize != p.Sizes[j] {
						return fmt.Errorf("inconsistent transaction size for hash %s", hash.Hex())
					}
				}
			}

			checkedPacket, err := checkNewPooledTransactionHashesPacket(p, state)
			if err != nil {
				return err
			}
			state.PacketHistory[i] = checkedPacket
		case *GetPooledTransactionsPacket:
		for _, hash := range p.GetPooledTransactionsRequest {
			state.RequestedTxHashes[hash] = true
		}
		case *PooledTransactionsPacket:
			checkedPacket, err := checkPooledTransactionsPacket(p, state)
			if err != nil {
				return err
			}
			state.PacketHistory[i] = checkedPacket

			// 检查是否所有请求的交易都已返回
			for _, tx := range checkedPacket.PooledTransactionsResponse {
				delete(state.RequestedTxHashes, tx.Hash())
			}
		// 添加其他类型的包的检查和修正...
		default:
			//对于其他包直接返回
			return nil
		}
		// 更新修正后的包
		state.PacketHistory[i] = packet
	}
	if len(state.RequestedTxHashes) > 0 {
		return fmt.Errorf("some requested transactions were not returned")
	}
	return nil
}

func checkStatusPacket(p *StatusPacket, state *OracleState) (*StatusPacket, error) {
	if p.TD.Cmp(state.TotalDifficulty) <= 0 {
		p.TD = new(big.Int).Add(state.TotalDifficulty, big.NewInt(1))
	}
	state.TotalDifficulty = p.TD
	state.ProtocolVersion = p.ProtocolVersion
	state.NetworkID = p.NetworkID
	state.GenesisHash = p.Genesis
	return p, nil
}

func checkNewBlockHashesPacket(p *NewBlockHashesPacket, state *OracleState) (*NewBlockHashesPacket, error) {
	for i, block := range *p {
		if block.Number <= state.LatestBlockNumber {
			(*p)[i].Number = state.LatestBlockNumber + 1
		}
		state.LatestBlockNumber = (*p)[i].Number
		// 我们仍然更新 BlockHashes，但不在这里检查唯一性
		state.BlockHashes[(*p)[i].Number] = (*p)[i].Hash
	}
	return p, nil
}

// 辅助函数：生成唯一哈希
func generateUniqueHash(seenHashes map[common.Hash]bool) common.Hash {
	for {
		// 随机数生成器
		randomBytes := make([]byte, 32)
		_, err := rand.Read(randomBytes)
		if err != nil {
			panic("Failed to generate random bytes")
		}
		hash := common.BytesToHash(randomBytes)
		if !seenHashes[hash] {
			return hash
		}
	}
}

func checkTransactionsPacket(p *TransactionsPacket, state *OracleState) (*TransactionsPacket, error) {
	validTxs := make([]*types.Transaction, 0)
	for _, tx := range *p {
		from, err := types.Sender(types.NewEIP155Signer(big.NewInt(1)), tx)
		if err != nil {
			continue
		}
		if balance, ok := state.AccountBalances[from]; ok && balance.Cmp(tx.Value()) >= 0 {
			if nonce, ok := state.AccountNonces[from]; ok && tx.Nonce() > nonce {
				state.AccountNonces[from] = tx.Nonce()
				state.AccountBalances[from] = new(big.Int).Sub(balance, tx.Value())
				validTxs = append(validTxs, tx)
			}
		}
	}
	*p = validTxs
	return p, nil
}

func checkBlockHeadersPacket(p *BlockHeadersPacket, state *OracleState) (*BlockHeadersPacket, error) {
	for i, header := range p.BlockHeadersRequest {
		if i > 0 && header.Time <= p.BlockHeadersRequest[i-1].Time {
			header.Time = p.BlockHeadersRequest[i-1].Time + 1
		}
		state.BlockHashes[header.Number.Uint64()] = header.Hash()
	}
	return p, nil
}

func checkNewBlockPacket(p *NewBlockPacket, state *OracleState) (*NewBlockPacket, error) {
	if p.Block.NumberU64() <= state.LatestBlockNumber {
		p.Block.Header().Number = new(big.Int).SetUint64(state.LatestBlockNumber + 1)
	}
	state.LatestBlockNumber = p.Block.NumberU64()
	state.BlockHashes[p.Block.NumberU64()] = p.Block.Hash()

	if p.TD.Cmp(state.TotalDifficulty) <= 0 {
		p.TD = new(big.Int).Add(state.TotalDifficulty, p.Block.Difficulty())
	}
	state.TotalDifficulty = p.TD

	// 检查区块中的交易有效性
	validTxs := make([]*types.Transaction, 0)
	for _, tx := range p.Block.Transactions() {
		from, err := types.Sender(types.NewEIP155Signer(big.NewInt(int64(state.NetworkID))), tx)
		if err != nil {
			continue
		}
		if balance, ok := state.AccountBalances[from]; ok && balance.Cmp(tx.Value()) >= 0 {
			if nonce, ok := state.AccountNonces[from]; ok && tx.Nonce() == nonce+1 {
				state.AccountNonces[from] = tx.Nonce()
				state.AccountBalances[from] = new(big.Int).Sub(balance, tx.Value())
				validTxs = append(validTxs, tx)
			}
		}
	}
	// 创建一个新的区块，只包含有效的交易
	newBlock := types.NewBlock(
		p.Block.Header(),
		&types.Body{
			Transactions: validTxs,
			Uncles:       p.Block.Uncles(),
			Withdrawals:  p.Block.Withdrawals(),
		},
		nil, // receipts
		nil, // hasher
	)
	p.Block = newBlock

	return p, nil
}

func checkBlockBodiesPacket(p *BlockBodiesPacket, state *OracleState) (*BlockBodiesPacket, error) {
	nonceMap := make(map[common.Address]uint64)
	currentBlockNumber := uint64(0) // 假设我们知道起始区块号

	for i, body := range p.BlockBodiesResponse {
		// 检查叔块数量
		if len(body.Uncles) > 2 {
			return nil, fmt.Errorf("too many uncles (%d) for body at index %d", len(body.Uncles), i)
		}

		// 检查叔块深度
		for _, uncle := range body.Uncles {
			if currentBlockNumber-uncle.Number.Uint64() > 7 {
				return nil, fmt.Errorf("uncle too old for body at index %d", i)
			}
		}

		// 检查交易nonce
		for _, tx := range body.Transactions {
			from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
			if err != nil {
				return nil, fmt.Errorf("failed to get sender for transaction in body at index %d: %v", i, err)
			}

			// 检查nonce
			if nonce, exists := nonceMap[from]; exists {
				if tx.Nonce() <= nonce {
					return nil, fmt.Errorf("invalid nonce for transaction from %s in body at index %d", from.Hex(), i)
				}
			}
			nonceMap[from] = tx.Nonce()
		}

		currentBlockNumber++
	}

	return p, nil
}

// 辅助函数：计算交易列表的根哈希
func calcTxsHash(txs []*types.Transaction) common.Hash {
	var txHashes []common.Hash
	for _, tx := range txs {
		txHashes = append(txHashes, tx.Hash())
	}
	return common.BytesToHash(crypto.Keccak256(concatHashes(txHashes)))
}

// 辅助函数：计算提款列表的根哈希
func calcWithdrawalsHash(withdrawals types.Withdrawals) common.Hash {
	var buf []byte
	for _, w := range withdrawals {
		withdrawalRLP, err := rlp.EncodeToBytes(w)
		if err != nil {
			// 处理错误，这里简单地跳过
			continue
		}
		buf = append(buf, withdrawalRLP...)
	}
	return crypto.Keccak256Hash(buf)
}

// 辅助函数：连接哈希值
func concatHashes(hashes []common.Hash) []byte {
	var buf []byte
	for _, h := range hashes {
		buf = append(buf, h.Bytes()...)
	}
	return buf
}

func checkReceiptsPacket(p *ReceiptsPacket, state *OracleState) (*ReceiptsPacket, error) {
	for _, receipts := range p.ReceiptsResponse {
		for _, receipt := range receipts {
			if _, exists := state.TransactionHashes[receipt.TxHash]; !exists {
				state.TransactionHashes[receipt.TxHash] = true
			}
		}
	}
	return p, nil
}

func checkNewPooledTransactionHashesPacket(p *NewPooledTransactionHashesPacket, state *OracleState) (*NewPooledTransactionHashesPacket, error) {
	if len(p.Hashes) != len(p.Types) || len(p.Hashes) != len(p.Sizes) {
		return nil, errors.New("inconsistent lengths of hashes, types, and sizes")
	}

	uniqueHashes := make([]common.Hash, 0)
	uniqueTypes := make([]byte, 0)
	uniqueSizes := make([]uint32, 0)

	for i, hash := range p.Hashes {
		if _, exists := state.TransactionHashes[hash]; !exists {
			uniqueHashes = append(uniqueHashes, hash)
			uniqueTypes = append(uniqueTypes, p.Types[i])
			uniqueSizes = append(uniqueSizes, p.Sizes[i])
			state.TransactionHashes[hash] = true

			// 存储交易类型和大小
			state.TransactionTypes[hash] = p.Types[i]
			state.TransactionSizes[hash] = p.Sizes[i]
		}
	}

	p.Hashes = uniqueHashes
	p.Types = uniqueTypes
	p.Sizes = uniqueSizes

	return p, nil
}

func checkPooledTransactionsPacket(p *PooledTransactionsPacket, state *OracleState) (*PooledTransactionsPacket, error) {
	validTxs := make([]*types.Transaction, 0)
	for _, tx := range p.PooledTransactionsResponse {
		txHash := tx.Hash()

		// 检查交易是否是被请求的
		if !state.RequestedTxHashes[txHash] {
			return nil, fmt.Errorf("transaction %s was not requested", txHash.Hex())
		}

		// 检查交易是否重复
		if state.TransactionHashes[txHash] {
			continue
		}

		// 验证交易
		from, err := types.Sender(types.NewEIP155Signer(big.NewInt(int64(state.NetworkID))), tx)
		if err != nil {
			return nil, fmt.Errorf("invalid transaction %s: %v", txHash.Hex(), err)
		}

		// 检查nonce
		if tx.Nonce() != state.AccountNonces[from]+1 {
			return nil, fmt.Errorf("invalid nonce for transaction %s", txHash.Hex())
		}

		// 检查余额
		if state.AccountBalances[from].Cmp(tx.Value()) < 0 {
			return nil, fmt.Errorf("insufficient balance for transaction %s", txHash.Hex())
		}

		// 更新状态
		state.TransactionHashes[txHash] = true
		state.AccountNonces[from] = tx.Nonce()
		state.AccountBalances[from] = new(big.Int).Sub(state.AccountBalances[from], tx.Value())

		validTxs = append(validTxs, tx)
	}

	p.PooledTransactionsResponse = validTxs
	return p, nil
}

func checkGetBlockHeadersPacket(p *GetBlockHeadersPacket, state *OracleState) (*GetBlockHeadersPacket, error) {
	// 确保请求的区块号不超过当前最新区块号
	if p.Origin.Number > state.LatestBlockNumber {
		p.Origin.Number = state.LatestBlockNumber
	}
	return p, nil
}

func checkGetBlockBodiesPacket(p *GetBlockBodiesPacket, state *OracleState) (*GetBlockBodiesPacket, error) {
	// 确保请求的区块哈希存在
	validHashes := make([]common.Hash, 0)
	for _, hash := range p.GetBlockBodiesRequest {
		if _, exists := state.BlockHashes[state.LatestBlockNumber]; exists {
			validHashes = append(validHashes, hash)
		}
	}
	p.GetBlockBodiesRequest = validHashes
	return p, nil
}

func checkGetPooledTransactionsPacket(p *GetPooledTransactionsPacket, state *OracleState) (*GetPooledTransactionsPacket, error) {
	// 创建一个新的切片来存储有效的交易哈希
	validHashes := make([]common.Hash, 0)

	// 遍历请求的所有交易哈希
	for _, hash := range p.GetPooledTransactionsRequest {
		// 检查哈希是否为空
		if hash != (common.Hash{}) {
			validHashes = append(validHashes, hash)
		}
	}

	// 用非空的哈希更新请求
	p.GetPooledTransactionsRequest = validHashes

	// 如果没有有效的哈希，返回一个错误
	if len(validHashes) == 0 {
		return nil, fmt.Errorf("no valid transaction hashes in the request")
	}

	return p, nil
}

func checkTransaction(tx *types.Transaction, state *OracleState) (*types.Transaction, error) {
	from, err := types.Sender(types.NewEIP155Signer(big.NewInt(int64(state.NetworkID))), tx)
	if err != nil {
		return nil, err
	}
	if balance, ok := state.AccountBalances[from]; ok && balance.Cmp(tx.Value()) >= 0 {
		if nonce, ok := state.AccountNonces[from]; ok && tx.Nonce() > nonce {
			state.AccountNonces[from] = tx.Nonce()
			state.AccountBalances[from] = new(big.Int).Sub(balance, tx.Value())
			return tx, nil
		} else {
			// 修正nonce
			newNonce := nonce + 1
			var newTx *types.Transaction
			switch tx.Type() {
			case types.LegacyTxType:
				newTx = types.NewTransaction(newNonce, *tx.To(), tx.Value(), tx.Gas(), tx.GasPrice(), tx.Data())
			case types.AccessListTxType:
				newTx = types.NewTx(&types.AccessListTx{
					ChainID:    tx.ChainId(),
					Nonce:      newNonce,
					To:         tx.To(),
					Value:      tx.Value(),
					Gas:        tx.Gas(),
					GasPrice:   tx.GasPrice(),
					AccessList: tx.AccessList(),
					Data:       tx.Data(),
				})
			case types.DynamicFeeTxType:
				newTx = types.NewTx(&types.DynamicFeeTx{
					ChainID:    tx.ChainId(),
					Nonce:      newNonce,
					To:         tx.To(),
					Value:      tx.Value(),
					Gas:        tx.Gas(),
					GasFeeCap:  tx.GasFeeCap(),
					GasTipCap:  tx.GasTipCap(),
					AccessList: tx.AccessList(),
					Data:       tx.Data(),
				})
			default:
				return nil, fmt.Errorf("unsupported transaction type: %d", tx.Type())
			}
			state.AccountNonces[from] = newNonce
			return newTx, nil
		}
	}
	return nil, errors.New("insufficient balance or invalid nonce")
}*/
