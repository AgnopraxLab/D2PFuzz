package eth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/snap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

type Suite struct {
	DestList *enode.Node
	conn     *Conn
	pri      *ecdsa.PrivateKey
	engine   *EngineClient
}

func NewSuite(dest *enode.Node, engineURL, jwt string) (*Suite, error) {
	engine, err := NewEngineClient(engineURL, jwt)
	if err != nil {
		return nil, err
	}

	return &Suite{
		DestList: dest,
		engine:   engine,
	}, nil
}

type PacketSpecification struct {
	BlockNumbers []int
	BlockHashes  []common.Hash
}

func (s *Suite) IsConnected() bool {
	return s.conn != nil
}

// Close 在 eth/suite.go 中添加
func (s *Suite) Close() error {
	// 检查连接是否存在
	if !s.IsConnected() {
		return nil // 如果连接已经关闭，直接返回
	}

	// 安全地关闭连接
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil // 确保连接对象被清理
		return err
	}

	return nil
}

func (s *Suite) GenPacket(packetType int) (Packet, error) {
	switch packetType {
	case GetBlockHeadersMsg:
		return &GetBlockHeadersPacket{
			RequestId: 33,
			GetBlockHeadersRequest: &GetBlockHeadersRequest{
				// Origin: HashOrNumber{Hash: s.chain.blocks[1].Hash()},
				Origin: HashOrNumber{Number: uint64(1)},
				// Origin:  HashOrNumber{Hash: s.chain.blocks[1].Hash(), Number: uint64(1)},
				Amount:  2,
				Skip:    1,
				Reverse: false,
			},
		}, nil
	default:
		return nil, errors.New("unknown packet type")
	}
}

var (
	acct   = common.HexToAddress("0x8bebc8ba651aee624937e7d897853ac30c95a067")
	ffHash = common.MaxHash
	zero   = common.Hash{}
)

// GenPacket 生成指定类型的 snap 协议数据包
func (s *Suite) GenSnapPacket(packetType int) (Packet, error) {
	switch packetType {
	// case snap.GetAccountRangeMsg:
	// 	return &snap.GetAccountRangePacket{
	// 		ID:     uint64(1),
	// 		Root:   s.chain.Head().Root(),
	// 		Origin: zero,
	// 		Limit:  ffHash,
	// 		Bytes:  4000,
	// 	}, nil

	case snap.AccountRangeMsg:
		accounts := []*snap.AccountData{
			{
				Hash: common.Hash{0x1},
				Body: []byte{0x1, 0x2, 0x3},
			},
			{
				Hash: common.Hash{0x2},
				Body: []byte{0x4, 0x5, 0x6},
			},
		}

		// 创建一些示例证明数据
		proofs := [][]byte{
			{0x1, 0x2, 0x3},
			{0x4, 0x5, 0x6},
		}

		return &snap.AccountRangePacket{
			ID:       uint64(1),
			Accounts: accounts,
			Proof:    proofs,
		}, nil

	// case snap.GetStorageRangesMsg:
	// 	return &snap.GetStorageRangesPacket{
	// 		ID:       uint64(1),
	// 		Root:     s.chain.Head().Root(),
	// 		Accounts: []common.Hash{common.BytesToHash(s.chain.state[acct].AddressHash)},
	// 		Origin:   zero[:],
	// 		Limit:    ffHash[:],
	// 		Bytes:    1000,
	// 	}, nil

	case snap.StorageRangesMsg:
		// 创建多个账户的存储槽数据
		slots := [][]*snap.StorageData{
			{ // 第一个账户的存储槽
				{
					Hash: common.Hash{0x1},
					Body: []byte{0x1, 0x2, 0x3},
				},
				{
					Hash: common.Hash{0x2},
					Body: []byte{0x4, 0x5, 0x6},
				},
			},
			{ // 第二个账户的存储槽
				{
					Hash: common.Hash{0x3},
					Body: []byte{0x7, 0x8, 0x9},
				},
				{
					Hash: common.Hash{0x4},
					Body: []byte{0xa, 0xb, 0xc},
				},
			},
		}

		// 创建一些示例证明数据
		proofs := [][]byte{
			{0x1, 0x2, 0x3},
			{0x4, 0x5, 0x6},
		}

		return &snap.StorageRangesPacket{
			ID:    uint64(1),
			Slots: slots,
			Proof: proofs, // 最后一个存储槽范围的默克尔证明
		}, nil

	// case snap.GetByteCodesMsg:
	// 	return &snap.GetByteCodesPacket{
	// 		ID:     uint64(1),
	// 		Hashes: s.chain.CodeHashes(),
	// 		Bytes:  10000,
	// 	}, nil

	case snap.ByteCodesMsg:
		// 创建一些示例合约字节码
		codes := [][]byte{
			// 一个简单的合约字节码
			{
				0x60, 0x80, 0x60, 0x40, 0x52, // PUSH1 80 PUSH1 40 MSTORE
				0x34, 0x80, 0x15, // CALLVALUE DUP1 ISZERO
				0x60, 0x04, // PUSH1 04
			},
			// 另一个合约字节码
			{
				0x60, 0x20, 0x60, 0x40, 0x52, // PUSH1 20 PUSH1 40 MSTORE
				0x60, 0x40, 0x51, // PUSH1 40 MLOAD
				0x80, 0x91, 0x03, // DUP1 SWAP2 SUB
			},
		}

		return &snap.ByteCodesPacket{
			ID:    uint64(1),
			Codes: codes, // 返回请求的合约字节码列表
		}, nil

	// case snap.GetTrieNodesMsg:
	// 	storageAcctHash := common.BytesToHash(s.chain.state[acct].AddressHash)
	// 	return &snap.GetTrieNodesPacket{
	// 		ID:   uint64(1),
	// 		Root: s.chain.Head().Root(),
	// 		Paths: []snap.TrieNodePathSet{
	// 			{
	// 				storageAcctHash[:],
	// 				[]byte{0},
	// 			},
	// 		},
	// 		Bytes: 5000,
	// 	}, nil

	case snap.TrieNodesMsg:
		// 创建一些示例 trie 节点数据
		nodes := [][]byte{
			// 第一个 trie 节点（分支节点示例）
			{
				0xf8, 0x91, // RLP 列表前缀
				0x80, // 空值
				0x80, // 空值
				0x80,
				0x94, 0x12, 0x34, // 某个分支的值
				0x80,
				0x80,
				0x80,
				0x80,
			},
			// 第二个 trie 节点（叶子节点示例）
			{
				0xe2,             // RLP 列表前缀
				0x20,             // 路径长度
				0x01, 0x02, 0x03, // 路径
				0x56, 0x78, // 值
			},
		}

		return &snap.TrieNodesPacket{
			ID:    uint64(1),
			Nodes: nodes, // 返回请求的 trie 节点列表
		}, nil

	default:
		return nil, fmt.Errorf("unknown snap packet type: %d", packetType)
	}
}

// Filler version
// func (s *Suite) GenPacket(f *filler.Filler, packetType int) (Packet, error) {
// 	switch packetType {
// 	case StatusMsg:
// 		return &StatusPacket{
// 			ProtocolVersion: f.FillProtocolVersion(),
// 			NetworkID:       f.FillNetworkID(),
// 			TD:              f.FillTD(),
// 			Head:            f.FillHash(),
// 			Genesis:         f.FillHash(),
// 			ForkID:          f.FillForkID(),
// 		}, nil
// 	case NewBlockHashesMsg:
// 		// 使用 crypto/rand 包生成随机哈希
// 		randomBytes := make([]byte, 32)
// 		if _, err := rand.Read(randomBytes); err != nil {
// 			return nil, fmt.Errorf("failed to generate random hash: %v", err)
// 		}
// 		return &NewBlockHashesPacket{
// 			{
// 				Hash:   f.FillHash(),
// 				Number: f.FillRequestId(),
// 			},
// 		}, nil
// 	case TransactionsMsg:
// 		txMsg := s.makeTxs(f)
// 		return &txMsg, nil
// 	case GetBlockHeadersMsg:
// 		return &GetBlockHeadersPacket{
// 			RequestId: f.FillRequestId(),
// 			GetBlockHeadersRequest: &GetBlockHeadersRequest{
// 				Origin:  HashOrNumber{Hash: f.FillHash()},
// 				Amount:  f.FillAmount(),
// 				Skip:    f.FillAmount(),
// 				Reverse: f.Bool(),
// 			},
// 		}, nil
// 	case BlockHeadersMsg:
// 		// Filling based on provided specification (spec.BlockNumbers)
// 		count := f.FillRequestId() % 256
// 		headers := make([]*types.Header, 0, count)

// 		for i := uint64(0); i < count; i++ {
// 			blockNum := int(f.FillRequestId() % uint64(len(s.chain.blocks)))
// 			block := s.chain.GetBlock(blockNum)
// 			if block != nil {
// 				headers = append(headers, block.Header())
// 			}
// 		}
// 		return &BlockHeadersPacket{
// 			RequestId:           f.FillRequestId(),
// 			BlockHeadersRequest: BlockHeadersRequest(headers),
// 		}, nil
// 	case GetBlockBodiesMsg:
// 		return &GetBlockBodiesPacket{
// 			RequestId: f.FillRequestId(),
// 			GetBlockBodiesRequest: GetBlockBodiesRequest{
// 				f.FillHash(), f.FillHash(),
// 			},
// 		}, nil
// 	case BlockBodiesMsg:
// 		// Similar logic as BlockHeadersMsg with filler
// 		count := f.FillRequestId() % 256
// 		bodies := make([]*BlockBody, 0, count)
// 		for i := uint64(0); i < count; i++ {
// 			blockNum := int(f.FillRequestId() % uint64(len(s.chain.blocks)))
// 			if blockNum < len(s.chain.blocks) {
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
// 			RequestId:           f.FillRequestId(),
// 			BlockBodiesResponse: bodies,
// 		}, nil
// 	case NewBlockMsg:
// 		// 生成交易
// 		txs := s.makeTxs(f)

// 		// 获取当前头部区块
// 		parentBlock := s.chain.blocks[len(s.chain.blocks)-1]
// 		parentHeader := parentBlock.Header()

// 		// 创建新的区块头
// 		newHeader := &types.Header{
// 			ParentHash:  parentHeader.Hash(),
// 			UncleHash:   types.EmptyUncleHash,
// 			Coinbase:    s.chain.genesis.Coinbase, // 使用创世块的 coinbase
// 			Root:        parentHeader.Root,        // 使用父区块的状态根
// 			TxHash:      types.EmptyRootHash,
// 			ReceiptHash: types.EmptyReceiptsHash,
// 			Bloom:       types.Bloom{},
// 			Difficulty:  new(big.Int).Add(parentHeader.Difficulty, common.Big1), // 简单地增加难度
// 			Number:      new(big.Int).Add(parentHeader.Number, common.Big1),
// 			GasLimit:    s.chain.genesis.GasLimit, // 使用创世块的 gas limit
// 			GasUsed:     0,                        // 将在后面更新
// 			Time:        uint64(time.Now().Unix()),
// 			Extra:       make([]byte, 32),
// 			MixDigest:   common.Hash{},
// 			Nonce:       types.BlockNonce{},
// 			BaseFee:     s.chain.genesis.BaseFee, // 使用创世块的 base fee，如果有的话
// 		}

// 		if s.chain.genesis.BaseFee != nil {
// 			newHeader.BaseFee = new(big.Int).Set(s.chain.genesis.BaseFee)
// 		}
// 		// 创建区块体
// 		body: = &types.Body{
// 			Transactions: txs,
// 			Uncles:       []*types.Header{},
// 			Withdrawals:  nil, // 如果不支持提款，保持为 nil
// 		}

// 		// 创建一个空的收据列表
// 		var receipts []*types.Receipt

// 		// 创建 hasher
// 		 := trie.NewStackTrie(nil)

// 		// 创建新区块
// 		newBlock: = types.NewBlock(newHeader, body, receipts, hasher)

// 		// 计算总难度
// 		td := calculateTotalDifficulty(s.chain)

// 		return &NewBlockPacket{
// 			Block: newBlock,
// 			TD:    td,
// 		}, nil
// 	case NewPooledTransactionHashesMsg:
// 		txs := s.makeTxs(f)
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
// 			RequestId: f.FillRequestId(),
// 			GetPooledTransactionsRequest: GetPooledTransactionsRequest{
// 				f.FillHash(), f.FillHash(),
// 			},
// 		}, nil
// 	case PooledTransactionsMsg:
// 		txs := s.makeTxs(f)
// 		count := int(f.FillRequestId() % 256)
// 		pooledTxs := make([]*types.Transaction, 0, count)
// 		for i := 0; i < count; i++ {
// 			for _, tx := range txs {
// 				if tx.Hash() == f.FillHash() {
// 					pooledTxs = append(pooledTxs, tx)
// 					break
// 				}
// 			}
// 		}
// 		return &PooledTransactionsPacket{
// 			RequestId:                  f.FillRequestId(),
// 			PooledTransactionsResponse: pooledTxs,
// 		}, nil
// 	case GetReceiptsMsg:
// 		return &GetReceiptsPacket{
// 			RequestId: f.FillRequestId(),
// 			GetReceiptsRequest: GetReceiptsRequest{
// 				f.FillHash(), f.FillHash(),
// 			},
// 		}, nil
// 	case ReceiptsMsg:
// 		count := int(f.FillRequestId() % 256)
// 		receipts := make([][]*types.Receipt, 0, count)
// 		for i := 0; i < count; i++ {
// 			if i < len(s.chain.blocks) {
// 				block := s.chain.blocks[i]
// 				if block != nil {
// 					blockReceipts := make([]*types.Receipt, len(block.Transactions()))
// 					for j, tx := range block.Transactions() {
// 						receipt := &types.Receipt{
// 							Type:             tx.Type(),
// 							TxHash:           tx.Hash(),
// 							ContractAddress:  crypto.CreateAddress(block.Header().Coinbase, tx.Nonce()),
// 							GasUsed:          f.FillAmount(),
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
// 			RequestId:        f.FillRequestId(),
// 			ReceiptsResponse: receipts,
// 		}, nil
// 	default:
// 		return nil, errors.New("unknown packet type")
// 	}
// }

// HeadersMatch headersMatch returns whether the received headers match the given request
func HeadersMatch(expected []*types.Header, headers []*types.Header) bool {
	return reflect.DeepEqual(expected, headers)
}

// 辅助函数：计算总 gas 使用量
/*func calculateGasUsed(txs types.Transactions) uint64 {
	var total uint64
	for _, tx := range txs {
		total += tx.Gas()
	}
	return total
}*/

// InitializeAndConnect 封装了初始化、连接和对等过程
func (s *Suite) InitializeAndConnect() error {
	conn, err := s.dial()
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	//defer func() {
	//	conn.Close()
	//}()
	//defer conn.Close()
	if err := conn.peer(nil); err != nil {
		return fmt.Errorf("peer failed: %v", err)
	}
	////

	///
	return nil
}

// InitializeAndConnect 封装了初始化、连接和对等过程
func (s *Suite) SnapInitializeAndConnect() error {
	conn, err := s.dialSnap()
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	//defer func() {
	//	conn.Close()
	//}()
	//defer conn.Close()
	if err := conn.peer(nil); err != nil {
		return fmt.Errorf("peer failed: %v", err)
	}
	////

	///
	return nil
}

// SendTxs sends the given transactions to the node and
// expects the node to accept and propagate them.
func (s *Suite) SendTxs(txs []*types.Transaction) error {
	// Open sending conning.
	sendConn, err := s.dial()
	if err != nil {
		return fmt.Errorf("建立发送连接失败: %v", err)
	}
	defer sendConn.Close()
	if err = sendConn.peer(nil); err != nil {
		return fmt.Errorf("sending peer failed: %v", err)
	}

	// Open receiving conn.
	recvConn, err := s.dial()
	if err != nil {
		return fmt.Errorf("建立接收连接失败: %v", err)
	}
	defer recvConn.Close()
	if err = recvConn.peer(nil); err != nil {
		return fmt.Errorf("receiving peer failed: %v", err)
	}

	if err = sendConn.Write(ethProto, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write message to connection: %v", err)
	}

	var (
		got = make(map[common.Hash]bool)
		end = time.Now().Add(timeout)
	)

	// Wait for the transaction announcements, make sure all txs ar propagated.
	for time.Now().Before(end) {
		msg, err := recvConn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read connection: %w", err)
		}
		switch msg := msg.(type) {
		case *TransactionsPacket:
			for _, tx := range *msg {
				got[tx.Hash()] = true
			}
		case *NewPooledTransactionHashesPacket68:
			for _, hash := range msg.Hashes {
				got[hash] = true
			}
		default:
			return fmt.Errorf("unexpected eth wire msg: %s", pretty.Sdump(msg))
		}

		// Check if all txs received.
		allReceived := func() bool {
			for _, tx := range txs {
				if !got[tx.Hash()] {
					return false
				}
			}
			return true
		}
		if allReceived() {
			return nil
		}
	}

	return fmt.Errorf("timed out waiting for txs")
}

// ReadEth reads an Eth sub-protocol wire message.
func (c *Conn) ReadEth() (any, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		code, data, _, err := c.Conn.Read()
		if err != nil {
			return nil, err
		}
		if code == pingMsg {
			c.Write(baseProto, pongMsg, []byte{})
			continue
		}
		if getProto(code) != ethProto {
			// Read until an eth message.
			continue
		}
		code -= baseProtoLen

		var msg any
		switch int(code) {
		case eth.StatusMsg:
			msg = new(StatusPacket)
		case eth.GetBlockHeadersMsg:
			msg = new(GetBlockHeadersPacket)
		case eth.BlockHeadersMsg:
			msg = new(BlockHeadersPacket)
		case eth.GetBlockBodiesMsg:
			msg = new(GetBlockBodiesPacket)
		case eth.BlockBodiesMsg:
			msg = new(BlockBodiesPacket)
		case eth.NewBlockMsg:
			msg = new(NewBlockPacket)
		case eth.NewBlockHashesMsg:
			msg = new(NewBlockHashesPacket)
		case eth.TransactionsMsg:
			msg = new(TransactionsPacket)
		case eth.NewPooledTransactionHashesMsg:
			msg = new(NewPooledTransactionHashesPacket68)
		case eth.GetPooledTransactionsMsg:
			msg = new(GetPooledTransactionsPacket)
		case eth.PooledTransactionsMsg:
			msg = new(PooledTransactionsPacket)
		default:
			panic(fmt.Sprintf("unhandled eth msg code %d", code))
		}
		if err := rlp.DecodeBytes(data, msg); err != nil {
			return nil, fmt.Errorf("unable to decode eth msg: %v", err)
		}
		return msg, nil
	}
}

func (s *Suite) SetupConn() error {
	s.conn, _ = s.dial()
	//defer s.conn.Close()
	if err := s.conn.Peer(nil); err != nil {
		return fmt.Errorf("peer failed: %v", err)
	}

	return nil
}

// Conn returns the connection of the suite
func (s *Suite) Conn() *Conn {
	return s.conn
}

func (s *Suite) SetupSnapConn() error {
	s.conn, _ = s.dialSnap()
	//defer s.conn.Close()
	if err := s.conn.Peer(nil); err != nil {
		return fmt.Errorf("peer failed: %v", err)
	}

	return nil
}
