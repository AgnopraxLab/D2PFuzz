package eth

import (
	"crypto/ecdsa"
	"errors"

	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

type Suite struct {
	DestList *enode.Node
	chain    *Chain
	conn     *Conn
	pri      *ecdsa.PrivateKey
}

func NewSuite(dest *enode.Node, chainDir string, pri *ecdsa.PrivateKey) (*Suite, error) {
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

type PacketSpecification struct {
	BlockNumbers []int
	BlockHashes  []common.Hash
}

// func (s *Suite) GenPacket(packetType int, spec *PacketSpecification) (Packet, error) {
// 	switch packetType {
// 	case StatusMsg:
// 		buf := make([]byte, 2024)
// 		_, err := rand.Read(buf)
// 		if err != nil {
// 			fmt.Println("Error generating random bytes:", err)
// 		}
// 		return &StatusPacket{
// 			ProtocolVersion: uint32(s.conn.negotiatedProtoVersion),
// 			NetworkID:       s.chain.config.ChainID.Uint64(),
// 			TD:              new(big.Int).SetBytes(buf),
// 			Head:            s.chain.Head().Hash(),
// 			Genesis:         s.chain.GetBlock(0).Hash(),
// 			ForkID:          s.chain.ForkID(),
// 		}, nil
// 	case NewBlockHashesMsg:
// 		return &NewBlockHashesPacket{
// 			{
// 				Hash:   s.chain.GetBlock(0).Hash(),
// 				Number: 1,
// 			},
// 		}, nil
// 	case TransactionsMsg:
// 		txMsg := s.makeTxs()
// 		return &txMsg, nil
// 	case GetBlockHeadersMsg:
// 		return &GetBlockHeadersPacket{
// 			RequestId: 33,
// 			GetBlockHeadersRequest: &GetBlockHeadersRequest{
// 				Origin:  HashOrNumber{Hash: s.chain.blocks[1].Hash()},
// 				Amount:  2,
// 				Skip:    1,
// 				Reverse: false,
// 			},
// 		}, nil
// 	case BlockHeadersMsg:
// 		headers := make([]*types.Header, 0, len(spec.BlockNumbers))
// 		for _, blockNum := range spec.BlockNumbers {
// 			if blockNum < len(s.chain.blocks) {
// 				block := s.chain.GetBlock(blockNum)
// 				if block != nil {
// 					headers = append(headers, block.Header())
// 				}
// 			}
// 		}
// 		return &BlockHeadersPacket{
// 			RequestId:           44,
// 			BlockHeadersRequest: BlockHeadersRequest(headers),
// 		}, nil
// 	case GetBlockBodiesMsg:
// 		return &GetBlockBodiesPacket{
// 			RequestId: 55,
// 			GetBlockBodiesRequest: GetBlockBodiesRequest{
// 				s.chain.blocks[54].Hash(),
// 				s.chain.blocks[75].Hash(),
// 			},
// 		}, nil
// 	case BlockBodiesMsg:
// 		bodies := make([]*BlockBody, 0, len(spec.BlockNumbers))
// 		for _, blockNum := range spec.BlockNumbers {
// 			if blockNum < len(s.chain.blocks) {
// 				// 检查 blockNum 是否在 int 范围内
// 				block := s.chain.GetBlock(blockNum)
// 				if block != nil {
// 					body := &BlockBody{
// 						Transactions: block.Transactions(),
// 						Uncles:       block.Uncles(),
// 						Withdrawals:  block.Withdrawals(),
// 					}
// 					bodies = append(bodies, body)
// 				}
// 			}
// 		}
// 		return &BlockBodiesPacket{
// 			RequestId:           66,
// 			BlockBodiesResponse: bodies,
// 		}, nil
// 	case NewBlockMsg:
// 		buf := make([]byte, 2024)
// 		_, err := rand.Read(buf)
// 		if err != nil {
// 			fmt.Println("Error generating random bytes:", err)
// 		}
// 		return &NewBlockPacket{
// 			Block: s.chain.Head(),
// 			TD:    new(big.Int).SetBytes(buf),
// 		}, nil
// 	case NewPooledTransactionHashesMsg:
// 		txs := s.makeTxs()
// 		packet := &NewPooledTransactionHashesPacket{
// 			Types:  make([]byte, len(txs)),
// 			Sizes:  make([]uint32, len(txs)),
// 			Hashes: make([]common.Hash, len(txs)),
// 		}
// 		for i, tx := range txs {
// 			packet.Types[i] = tx.Type()
// 			packet.Sizes[i] = uint32(tx.Size())
// 			packet.Hashes[i] = tx.Hash()
// 		}
// 		return packet, nil
// 	case GetPooledTransactionsMsg:
// 		return &GetPooledTransactionsPacket{
// 			RequestId: 99,
// 			GetPooledTransactionsRequest: GetPooledTransactionsRequest{
// 				s.chain.blocks[54].Transactions()[0].Hash(), // 假设我们要请求第54个区块的第一个交易
// 				s.chain.blocks[75].Transactions()[0].Hash(), // 假设我们要请求第75个区块的第一个交易
// 			},
// 		}, nil
// 	case PooledTransactionsMsg:
// 		txs := s.makeTxs()
// 		pooledTxs := make([]*types.Transaction, 0, len(spec.BlockHashes))
// 		for _, hash := range spec.BlockHashes {
// 			for _, tx := range txs {
// 				if tx.Hash() == hash {
// 					pooledTxs = append(pooledTxs, tx)
// 					break
// 				}
// 			}
// 		}
// 		return &PooledTransactionsPacket{
// 			RequestId:                  100,
// 			PooledTransactionsResponse: pooledTxs,
// 		}, nil
// 	case GetReceiptsMsg:
// 		packet := &GetReceiptsPacket{
// 			RequestId: 110,
// 			GetReceiptsRequest: GetReceiptsRequest{
// 				s.chain.blocks[54].Hash(), // 请求第54个区块的收据
// 				s.chain.blocks[75].Hash(), // 请求第75个区块的收据
// 			},
// 		}
// 		return packet, nil
// 	case ReceiptsMsg:
// 		receipts := make([][]*types.Receipt, 0, len(spec.BlockNumbers))
// 		for _, blockNum := range spec.BlockNumbers {
// 			if blockNum < len(s.chain.blocks) {
// 				block := s.chain.blocks[blockNum]
// 				if block != nil {
// 					blockReceipts := make([]*types.Receipt, len(block.Transactions()))
// 					for j, tx := range block.Transactions() {
// 						receipt := &types.Receipt{
// 							Type:             tx.Type(),
// 							TxHash:           tx.Hash(),
// 							ContractAddress:  crypto.CreateAddress(block.Header().Coinbase, tx.Nonce()),
// 							GasUsed:          21000,
// 							BlockHash:        block.Hash(),
// 							BlockNumber:      block.Number(),
// 							TransactionIndex: uint(j),
// 						}
// 						blockReceipts[j] = receipt
// 					}
// 					receipts = append(receipts, blockReceipts)
// 				}
// 			}
// 		}
// 		return &ReceiptsPacket{
// 			RequestId:        110,
// 			ReceiptsResponse: receipts,
// 		}, nil
// 	default:
// 		return nil, errors.New("unknown packet type")
// 	}
// }

func (s *Suite) GenPacket(f *filler.Filler, packetType int, spec *PacketSpecification) (Packet, error) {
	switch packetType {
	case StatusMsg:
		return &StatusPacket{
			ProtocolVersion: f.FillProtocolVersion(),
			NetworkID:       f.FillNetworkID(),
			TD:              f.FillTD(),
			Head:            f.FillHash(),
			Genesis:         f.FillHash(),
			ForkID:          f.FillForkID(),
		}, nil
	case NewBlockHashesMsg:
		return &NewBlockHashesPacket{
			{
				Hash:   f.FillHash(),
				Number: f.FillRequestId(),
			},
		}, nil
	case TransactionsMsg:
		txMsg := s.makeTxs(f)
		return &txMsg, nil
	case GetBlockHeadersMsg:
		return &GetBlockHeadersPacket{
			RequestId: f.FillRequestId(),
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				Origin:  HashOrNumber{Hash: f.FillHash()},
				Amount:  f.FillAmount(),
				Skip:    f.FillAmount(),
				Reverse: f.Bool(),
			},
		}, nil
	case BlockHeadersMsg:
		// Filling based on provided specification (spec.BlockNumbers)
		headers := make([]*types.Header, 0, len(spec.BlockNumbers))
		for _, blockNum := range spec.BlockNumbers {
			if blockNum < len(s.chain.blocks) {
				block := s.chain.GetBlock(blockNum)
				if block != nil {
					headers = append(headers, block.Header())
				}
			}
		}
		return &BlockHeadersPacket{
			RequestId:           f.FillRequestId(),
			BlockHeadersRequest: BlockHeadersRequest(headers),
		}, nil
	case GetBlockBodiesMsg:
		return &GetBlockBodiesPacket{
			RequestId: f.FillRequestId(),
			GetBlockBodiesRequest: GetBlockBodiesRequest{
				f.FillHash(), f.FillHash(),
			},
		}, nil
	case BlockBodiesMsg:
		// Similar logic as BlockHeadersMsg with filler
		bodies := make([]*BlockBody, 0, len(spec.BlockNumbers))
		for _, blockNum := range spec.BlockNumbers {
			if blockNum < len(s.chain.blocks) {
				block := s.chain.GetBlock(blockNum)
				if block != nil {
					body := &BlockBody{
						Transactions: block.Transactions(),
						Uncles:       block.Uncles(),
						Withdrawals:  block.Withdrawals(),
					}
					bodies = append(bodies, body)
				}
			}
		}
		return &BlockBodiesPacket{
			RequestId:           f.FillRequestId(),
			BlockBodiesResponse: bodies,
		}, nil
	case NewBlockMsg:
		return &NewBlockPacket{
			Block: s.chain.Head(),
			TD:    f.FillTD(),
		}, nil
	case NewPooledTransactionHashesMsg:
		txs := s.makeTxs(f)
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
			RequestId: f.FillRequestId(),
			GetPooledTransactionsRequest: GetPooledTransactionsRequest{
				f.FillHash(), f.FillHash(),
			},
		}, nil
	case PooledTransactionsMsg:
		txs := s.makeTxs(f)
		pooledTxs := make([]*types.Transaction, 0, len(spec.BlockHashes))
		for _, hash := range spec.BlockHashes {
			for _, tx := range txs {
				if tx.Hash() == hash {
					pooledTxs = append(pooledTxs, tx)
					break
				}
			}
		}
		return &PooledTransactionsPacket{
			RequestId:                  f.FillRequestId(),
			PooledTransactionsResponse: pooledTxs,
		}, nil
	case GetReceiptsMsg:
		return &GetReceiptsPacket{
			RequestId: f.FillRequestId(),
			GetReceiptsRequest: GetReceiptsRequest{
				f.FillHash(), f.FillHash(),
			},
		}, nil
	case ReceiptsMsg:
		receipts := make([][]*types.Receipt, 0, len(spec.BlockNumbers))
		for _, blockNum := range spec.BlockNumbers {
			if blockNum < len(s.chain.blocks) {
				block := s.chain.blocks[blockNum]
				if block != nil {
					blockReceipts := make([]*types.Receipt, len(block.Transactions()))
					for j, tx := range block.Transactions() {
						receipt := &types.Receipt{
							Type:             tx.Type(),
							TxHash:           tx.Hash(),
							ContractAddress:  crypto.CreateAddress(block.Header().Coinbase, tx.Nonce()),
							GasUsed:          f.FillAmount(),
							BlockHash:        block.Hash(),
							BlockNumber:      block.Number(),
							TransactionIndex: uint(j),
						}
						blockReceipts[j] = receipt
					}
					receipts = append(receipts, blockReceipts)
				}
			}
		}
		return &ReceiptsPacket{
			RequestId:        f.FillRequestId(),
			ReceiptsResponse: receipts,
		}, nil
	default:
		return nil, errors.New("unknown packet type")
	}
}

func (s *Suite) makeTxs(f *filler.Filler) TransactionsPacket {
	// Generate many transactions to seed target with.
	var (
		from, nonce = s.chain.GetSender(1)
		count       = 2000
		txs         []*types.Transaction
		hashes      []common.Hash
		set         = make(map[common.Hash]struct{})
	)

	for i := 0; i < count; i++ {
		// Use filler to fill the fields for transaction
		gasTipCap := f.BigInt64() // Random big.Int for GasTipCap
		gasFeeCap := f.BigInt64() // Random big.Int for GasFeeCap
		gasLimit := f.Uint64()    // Random uint64 for Gas limit

		inner := &types.DynamicFeeTx{
			ChainID:   s.chain.config.ChainID,
			Nonce:     nonce + uint64(i),
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
		}
		tx, _ := s.chain.SignTx(from, types.NewTx(inner))
		txs = append(txs, tx)
		set[tx.Hash()] = struct{}{}
		hashes = append(hashes, tx.Hash())
	}

	return txs
}
