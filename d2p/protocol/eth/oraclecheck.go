package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

// OracleState 用于维护Oracle的状态
type OracleState struct {
	LatestBlockNumber uint64
	TotalDifficulty   *big.Int
	AccountBalances   map[common.Address]*big.Int
	AccountNonces     map[common.Address]uint64
	BlockHashes       map[uint64]common.Hash
	TransactionHashes map[common.Hash]bool
}

// NewOracleState 创建一个新的OracleState
func NewOracleState() *OracleState {
	return &OracleState{
		TotalDifficulty:   big.NewInt(0),
		AccountBalances:   make(map[common.Address]*big.Int),
		AccountNonces:     make(map[common.Address]uint64),
		BlockHashes:       make(map[uint64]common.Hash),
		TransactionHashes: make(map[common.Hash]bool),
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
	default:
		return packet, nil // 对于不需要检查的包，直接返回
	}
}

func checkStatusPacket(p *StatusPacket, state *OracleState) (*StatusPacket, error) {
	if p.TD.Cmp(state.TotalDifficulty) <= 0 {
		p.TD = new(big.Int).Add(state.TotalDifficulty, big.NewInt(1))
	}
	state.TotalDifficulty = p.TD
	return p, nil
}

func checkNewBlockHashesPacket(p *NewBlockHashesPacket, state *OracleState) (*NewBlockHashesPacket, error) {
	for i, block := range *p {
		if block.Number <= state.LatestBlockNumber {
			(*p)[i].Number = state.LatestBlockNumber + 1
		}
		state.LatestBlockNumber = (*p)[i].Number
		state.BlockHashes[(*p)[i].Number] = (*p)[i].Hash
	}
	return p, nil
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
		p.Block.Header().Number = big.NewInt(int64(state.LatestBlockNumber + 1))
	}
	state.LatestBlockNumber = p.Block.NumberU64()
	state.BlockHashes[p.Block.NumberU64()] = p.Block.Hash()
	if p.TD.Cmp(state.TotalDifficulty) <= 0 {
		p.TD = new(big.Int).Add(state.TotalDifficulty, p.Block.Difficulty())
	}
	state.TotalDifficulty = p.TD
	return p, nil
}

func checkBlockBodiesPacket(p *BlockBodiesPacket, state *OracleState) (*BlockBodiesPacket, error) {
	for _, body := range p.BlockBodiesResponse {
		for _, tx := range body.Transactions {
			if _, exists := state.TransactionHashes[tx.Hash()]; !exists {
				state.TransactionHashes[tx.Hash()] = true
			}
		}
	}
	return p, nil
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
	uniqueHashes := make([]common.Hash, 0)
	for _, hash := range p.Hashes {
		if _, exists := state.TransactionHashes[hash]; !exists {
			uniqueHashes = append(uniqueHashes, hash)
			state.TransactionHashes[hash] = true
		}
	}
	p.Hashes = uniqueHashes
	p.Types = p.Types[:len(uniqueHashes)]
	p.Sizes = p.Sizes[:len(uniqueHashes)]
	return p, nil
}

func checkPooledTransactionsPacket(p *PooledTransactionsPacket, state *OracleState) (*PooledTransactionsPacket, error) {
	validTxs := make([]*types.Transaction, 0)
	for _, tx := range p.PooledTransactionsResponse {
		if _, exists := state.TransactionHashes[tx.Hash()]; !exists {
			state.TransactionHashes[tx.Hash()] = true
			validTxs = append(validTxs, tx)
		}
	}
	p.PooledTransactionsResponse = validTxs
	return p, nil
}
