package eth

import (
	"D2PFuzz/fuzzing"
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"math/big"
)

type Suite struct {
	DestList []*enode.Node
	chain    *Chain
	conn     *Conn
	pri      *ecdsa.PrivateKey
}

func NewSuite(dest []*enode.Node, chainDir string, pri *ecdsa.PrivateKey) (*Suite, error) {
	chain, err := NewChain(chainDir)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	return &Suite{
		DestList: dest,
		chain:    chain,
		pri:      pri,
	}, nil
}

func (s *Suite) GenPacket(packetType int) (Packet, error) {
	switch packetType {
	case StatusMsg:
		return &StatusPacket{
			ProtocolVersion: uint32(s.conn.negotiatedProtoVersion),
			NetworkID:       s.chain.config.ChainID.Uint64(),
			TD:              new(big.Int).SetBytes(fuzzing.RandBuff(2024)),
			Head:            s.chain.Head().Hash(),
			Genesis:         s.chain.GetBlock(0).Hash(),
			ForkID:          s.chain.ForkID(),
		}, nil
	case NewBlockHashesMsg:
		return &NewBlockHashesPacket{
			{
				Hash:   s.chain.GetBlock(0).Hash(),
				Number: 1,
			},
		}, nil
	case TransactionsMsg:
		txMsg := s.makeTxs()
		return &txMsg, nil
	case GetBlockHeadersMsg:
		return &GetBlockHeadersPacket{
			RequestId: 33,
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				Origin:  HashOrNumber{Hash: s.chain.blocks[1].Hash()},
				Amount:  2,
				Skip:    1,
				Reverse: false,
			},
		}, nil

	///////////////////////////////////
	case BlockHeadersMsg:
		// 假设我们想要返回链中的前3个区块头
		headers := make([]*types.Header, 0, 3)
		for i := 0; i < 3; i++ {
			block := s.chain.GetBlock(i)
			if block != nil {
				headers = append(headers, block.Header())
			}
		}

		return &BlockHeadersPacket{
			RequestId:           44, // 随机的请求ID
			BlockHeadersRequest: BlockHeadersRequest(headers),
		}, nil
	//////////////////////////////////

	case GetBlockBodiesMsg:
		return &GetBlockBodiesPacket{
			RequestId: 55,
			GetBlockBodiesRequest: GetBlockBodiesRequest{
				s.chain.blocks[54].Hash(),
				s.chain.blocks[75].Hash(),
			},
		}, nil

	/////////////////////////////////
	case BlockBodiesMsg:
		// 假设我们要返回前两个区块的内容
		bodies := make([]*BlockBody, 0, 2)
		for i := 0; i < 2; i++ {
			block := s.chain.GetBlock(i)
			if block != nil {
				body := &BlockBody{
					Transactions: block.Transactions(),
					Uncles:       block.Uncles(),
					Withdrawals:  block.Withdrawals(),
				}
				bodies = append(bodies, body)
			}
		}
		return &BlockBodiesPacket{
			RequestId:           66, // 随机的请求ID
			BlockBodiesResponse: bodies,
		}, nil
	//这个用区块头可以吗？
	case NewBlockMsg:
		return &NewBlockPacket{
			Block: s.chain.Head(),
			TD:    new(big.Int).SetBytes(fuzzing.RandBuff(2024)),
		}, nil
	case NewPooledTransactionHashesMsg:
		txs := s.makeTxs()
		packet := &NewPooledTransactionHashesPacket{
			Types:  make([]byte, len(txs)),
			Sizes:  make([]uint32, len(txs)),
			Hashes: make([]common.Hash, len(txs)),
		}
		for i, tx := range txs {
			packet.Types[i] = tx.Type()
			packet.Sizes[i] = uint32(tx.Size())
			packet.Hashes[i] = tx.Hash()
		}
		return packet, nil
	case GetPooledTransactionsMsg:
		return &GetPooledTransactionsPacket{
			RequestId: 99,
			GetPooledTransactionsRequest: GetPooledTransactionsRequest{
				s.chain.blocks[54].Transactions()[0].Hash(), // 假设我们要请求第54个区块的第一个交易
				s.chain.blocks[75].Transactions()[0].Hash(), // 假设我们要请求第75个区块的第一个交易
			},
		}, nil
	//不能这样，之后按照hash写
	case PooledTransactionsMsg:
		txs := s.makeTxs()

		// makeTxs() 返回的是 TransactionsPacket 类型，需要转换它
		pooledTxs := make([]*types.Transaction, len(txs))
		for i, tx := range txs {
			pooledTxs[i] = tx
		}

		packet := &PooledTransactionsPacket{
			RequestId:                  100,
			PooledTransactionsResponse: pooledTxs,
		}
		return packet, nil
	case GetReceiptsMsg:
		packet := &GetReceiptsPacket{
			RequestId: 110,
			GetReceiptsRequest: GetReceiptsRequest{
				s.chain.blocks[54].Hash(), // 请求第54个区块的收据
				s.chain.blocks[75].Hash(), // 请求第75个区块的收据
			},
		}
		return packet, nil
	case ReceiptsMsg:
		receipts := make([][]*types.Receipt, 0, 2)
		for i := 0; i < 2 && i < len(s.chain.blocks); i++ {
			block := s.chain.blocks[i]
			if block != nil {
				//Receipt调用的以太坊的type
				blockReceipts := make([]*types.Receipt, len(block.Transactions()))
				for j, tx := range block.Transactions() {
					// 这里模拟创建收据
					receipt := &types.Receipt{
						Type:             tx.Type(),
						TxHash:           tx.Hash(),
						ContractAddress:  crypto.CreateAddress(block.Header().Coinbase, tx.Nonce()),
						GasUsed:          21000, // 简化假设
						BlockHash:        block.Hash(),
						BlockNumber:      block.Number(),
						TransactionIndex: uint(j),
					}
					blockReceipts[j] = receipt
				}
				receipts = append(receipts, blockReceipts)
			}
		}
		packet := &ReceiptsPacket{
			RequestId:        110, // 在实际应用中，这应该匹配接收到的请求ID
			ReceiptsResponse: receipts,
		}
		return packet, nil
	/////////////////////////////////
	default:
		return nil, errors.New("unknown packet type")
	}

}

func (s *Suite) makeTxs() TransactionsPacket {
	// Generate many transactions to seed target with.
	var (
		from, nonce = s.chain.GetSender(1)
		count       = 2000
		txs         []*types.Transaction
		hashes      []common.Hash
		set         = make(map[common.Hash]struct{})
	)

	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   s.chain.config.ChainID,
			Nonce:     nonce + uint64(i),
			GasTipCap: common.Big1,
			GasFeeCap: s.chain.Head().BaseFee(),
			Gas:       75000,
		}
		tx, _ := s.chain.SignTx(from, types.NewTx(inner))
		txs = append(txs, tx)
		set[tx.Hash()] = struct{}{}
		hashes = append(hashes, tx.Hash())
	}

	return txs
}
