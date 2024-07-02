package eth

import (
	"D2PFuzz/fuzzing"
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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
	case GetBlockBodiesMsg:
		return &GetBlockBodiesPacket{
			RequestId: 55,
			GetBlockBodiesRequest: GetBlockBodiesRequest{
				s.chain.blocks[54].Hash(),
				s.chain.blocks[75].Hash(),
			},
		}, nil
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
