package eth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// OracleState 用于维护Oracle的状态
type OracleState struct {
	LatestBlockNumber uint64
	TotalDifficulty   *big.Int
	AccountBalances   map[common.Address]*big.Int
	AccountNonces     map[common.Address]uint64
	BlockHashes       map[uint64]common.Hash
	TransactionHashes map[common.Hash]bool
	TransactionTypes  map[common.Hash]byte
	TransactionSizes  map[common.Hash]uint32
	ProtocolVersion   uint32
	NetworkID         uint64
	GenesisHash       common.Hash
	PacketHistory     []interface{}
	LatestHeader      *types.Header
	FirstStatusPacket *StatusPacket
	BlockHeaders      map[uint64]*types.Header
	RequestedTxHashes map[common.Hash]bool
}

// NewOracleState 创建一个新的OracleState
func NewOracleState() *OracleState {
	return &OracleState{
		TotalDifficulty:   big.NewInt(0),
		AccountBalances:   make(map[common.Address]*big.Int),
		AccountNonces:     make(map[common.Address]uint64),
		BlockHashes:       make(map[uint64]common.Hash),
		TransactionHashes: make(map[common.Hash]bool),
		TransactionTypes:  make(map[common.Hash]byte),
		TransactionSizes:  make(map[common.Hash]uint32),
		BlockHeaders:      make(map[uint64]*types.Header),
		RequestedTxHashes: make(map[common.Hash]bool),
	}
}

// OracleCheck 检查并修正生成的数据包
func OracleCheck(packet interface{}, state *OracleState) (interface{}, error) {
	switch p := packet.(type) {
	case *StatusPacket:
		return checkStatusPacket(p, state)
	case *NewBlockHashesPacket:
		return checkNewBlockHashesPacket(p, state)
	case *TransactionsPacket:
		return checkTransactionsPacket(p, state)
	case *BlockHeadersPacket:
		return checkBlockHeadersPacket(p, state)
	case *NewBlockPacket:
		return checkNewBlockPacket(p, state)
	case *BlockBodiesPacket:
		return checkBlockBodiesPacket(p, state)
	case *ReceiptsPacket:
		return checkReceiptsPacket(p, state)
	case *NewPooledTransactionHashesPacket:
		return checkNewPooledTransactionHashesPacket(p, state)
	case *PooledTransactionsPacket:
		return checkPooledTransactionsPacket(p, state)
	case *GetBlockHeadersPacket:
		return checkGetBlockHeadersPacket(p, state)
	case *GetBlockBodiesPacket:
		return checkGetBlockBodiesPacket(p, state)
	default:
		return packet, nil // 对于不需要检查的包，直接返回
	}
}

func MultiPacketCheck(state *OracleState) error {
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
			// 检查区块号是否递增
			if p.Block.NumberU64() <= lastBlockNumber {
				return errors.New("non-increasing block number")
			}
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
	// 确保我们有足够的区块头来匹配区块体
	if len(p.BlockBodiesResponse) > len(state.BlockHeaders) {
		return nil, fmt.Errorf("more block bodies than known headers")
	}

	for i, body := range p.BlockBodiesResponse {
		// 获取对应的区块头
		header := state.BlockHeaders[uint64(i)]
		if header == nil {
			return nil, fmt.Errorf("no matching block header for body at index %d", i)
		}

		// 检查交易根是否匹配
		txHash := calcTxsHash(body.Transactions)
		if txHash != header.TxHash {
			return nil, fmt.Errorf("transaction root mismatch for body at index %d", i)
		}

		// 检查叔块根是否匹配
		uncleHash := types.CalcUncleHash(body.Uncles)
		if uncleHash != header.UncleHash {
			return nil, fmt.Errorf("uncle root mismatch for body at index %d", i)
		}

		// 如果有提款字段，检查提款根是否匹配
		if header.WithdrawalsHash != nil {
			withdrawalHash := calcWithdrawalsHash(body.Withdrawals)
			if *header.WithdrawalsHash != withdrawalHash {
				return nil, fmt.Errorf("withdrawal root mismatch for body at index %d", i)
			}
		}
		// 更新交易哈希状态
		for _, tx := range body.Transactions {
			state.TransactionHashes[tx.Hash()] = true
		}
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
}
