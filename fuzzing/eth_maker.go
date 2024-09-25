// Copyright 2024 Fudong and Hosen
// This file is part of the D2PFuzz library.
//
// The D2PFuzz library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The D2PFuzz library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the D2PFuzz library. If not, see <http://www.gnu.org/licenses/>.

package fuzzing

import (
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	ethstate = []int{eth.StatusMsg, eth.GetReceiptsMsg}
)

type EthMaker struct {
	suiteList []*eth.Suite
	filler    filler.Filler

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

func NewEthMaker(f *filler.Filler, targetDir string, chain string) *EthMaker {
	var suiteList []*eth.Suite

	nodeList, _ := getList(targetDir)

	for _, node := range nodeList {
		suite, err := generator.Initeth(node, chain)
		if err != nil {
			fmt.Printf("failed to initialize eth clients: %v", err)
		}
		suiteList = append(suiteList, suite)
	}

	ethmaker := &EthMaker{
		suiteList: suiteList,
		testSeq:   generateEthTestSeq(),
		stateSeq:  ethstate,
	}
	return ethmaker
}

func (m *EthMaker) ToGeneralStateTest(name string) *GeneralStateTest {
	gst := make(GeneralStateTest)
	gst[name] = m.ToSubTest()
	return &gst
}

func (m *EthMaker) ToSubTest() *stJSON {
	st := &stJSON{}
	st.Ps = m.Series
	for _, fork := range m.forks {
		postState := make(map[string][]stPostState)
		postState[fork] = []stPostState{
			stPostState{
				Logs:    m.logs,
				Root:    m.root,
				Indexes: stIndex{Gas: 0, Value: 0, Data: 0},
			},
		}
		st.Post = postState
	}
	return st
}

func (m *EthMaker) Start(traceOutput io.Writer) error {
	for _, packet := range m.packets {
		if traceOutput != nil {
			fmt.Println(traceOutput, "Processing packet of type: %T\n", packet)
		}

		switch p := packet.(type) {
		case *eth.StatusPacket:
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

		case *eth.TransactionsPacket:
			// Nudge client out of syncing mode to accept pending txs.
			/*if err := m.client.SendForkchoiceUpdated(); err != nil {
				return fmt.Errorf("failed to send next block: %v", err)
			}*/
			if err := m.handleTransactionPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetBlockHeadersPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetBlockHeadersPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetBlockBodiesPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetBlockBodiesPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.NewBlockHashesPacket, *eth.BlockHeadersPacket, *eth.BlockBodiesPacket, *eth.NewBlockPacket, *eth.PooledTransactionsPacket, *eth.ReceiptsPacket:
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleSendOnlyPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.NewPooledTransactionHashesPacket:
			/*if err := m.client.SendForkchoiceUpdated(); err != nil {
				return fmt.Errorf("failed to send next block: %v", err)
			}*/
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}
			if err := m.handlePooledTransactionHashesPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetPooledTransactionsPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetPooledTransactionsPacket(p, traceOutput); err != nil {
				return err
			}
		case *eth.GetReceiptsPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetReceiptsPacket(p, traceOutput); err != nil {
				return err
			}
		// Add other packet types here as needed
		// case *eth.GetBlockBodiesPacket:
		//     if err := m.handleGetBlockBodiesPacket(p, traceOutput); err != nil {
		//         return err
		//     }
		// case *eth.GetReceiptsPacket:
		//     if err := m.handleGetReceiptsPacket(p, traceOutput); err != nil {
		//         return err
		//     }
		default:
			if traceOutput != nil {
				fmt.Println(traceOutput, "Unsupported packet type: %T\n", packet)
			}
		}

		// Sleep between packet processing to avoid overwhelming the network
		time.Sleep(time.Millisecond * 100)
	}

	return nil
}
func (m *EthMaker) handleSendOnlyPacket(packet interface{}, traceOutput io.Writer) error {
	var msgcode uint64

	switch packet.(type) {
	case *eth.NewBlockHashesPacket:
		msgcode = eth.NewBlockHashesMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending NewBlockHashesPacket")
		}
	case *eth.BlockHeadersPacket:
		msgcode = eth.BlockHeadersMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending BlockHeadersPacket")
		}
	case *eth.BlockBodiesPacket:
		msgcode = eth.BlockBodiesMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending BlockBodiesPacket")
		}
	case *eth.NewBlockPacket:
		msgcode = eth.NewBlockMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending NewBlockPacket")
		}
	case *eth.PooledTransactionsPacket:
		msgcode = eth.PooledTransactionsMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending PooledTransactionsPacket")
		}
	case *eth.ReceiptsPacket:
		msgcode = eth.ReceiptsMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending ReceiptsPacket")
		}
	default:
		return fmt.Errorf("unsupported packet type: %T", packet)
	}

	if err := m.client.SendMsg(eth.EthProto, msgcode, packet); err != nil {
		return fmt.Errorf("could not send %T: %v", packet, err)
	}

	return nil
}

func (m *EthMaker) handleTransactionPacket(p *eth.TransactionsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending transaction")
	}
	for i, tx := range *p {
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending transaction %d\n", i+1)
		}

		if err := m.client.SendTxs([]*types.Transaction{tx}); err != nil {
			return fmt.Errorf("failed to send transaction: %v", err)
		}

		if traceOutput != nil {
			fmt.Println(traceOutput, "Transaction %d sent successfully\n", i+1)
		}
	}
	return nil
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockHeadersPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockHeadersMsg: %v", err)
	}

	headers := new(eth.BlockHeadersPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return fmt.Errorf("error reading BlockHeadersMsg: %v", err)
	}

	if got, want := headers.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id: got %d, want %d", headers.RequestId, p.RequestId)
	}

	expected, err := m.client.GetHeaders(p)
	if err != nil {
		return fmt.Errorf("failed to get headers for given request: %v", err)
	}

	if !eth.HeadersMatch(expected, headers.BlockHeadersRequest) {
		return fmt.Errorf("header mismatch")
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received headers for request %d\n", headers.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockBodiesPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.BlockBodiesPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.BlockBodiesResponse
	if len(bodies) != len(p.GetBlockBodiesRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetBlockBodiesRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handlePooledTransactionHashesPacket(p *eth.NewPooledTransactionHashesPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending NewPooledTransactionHashesPacket")
	}

	if err := m.client.SendMsg(eth.EthProto, eth.NewPooledTransactionHashesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.GetPooledTransactionsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.GetPooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := len(resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
		return fmt.Errorf("unexpected number of txs requested: got %d, want %d", got, want)
	}
	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetPooledTransactionsPacket(p *eth.GetPooledTransactionsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetPooledTransactionsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.PooledTransactionsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.PooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.PooledTransactionsResponse
	if len(bodies) != len(p.GetPooledTransactionsRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetPooledTransactionsRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.ReceiptsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.ReceiptsResponse
	if len(bodies) != len(p.GetReceiptsRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetReceiptsRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func generateEthTestSeq() []int {
	options := []int{
		eth.StatusMsg, eth.NewBlockHashesMsg, eth.TransactionsMsg, eth.GetBlockHeadersMsg,
		eth.BlockHeadersMsg, eth.GetBlockBodiesMsg, eth.BlockBodiesMsg, eth.NewBlockMsg,
		eth.NewPooledTransactionHashesMsg, eth.GetPooledTransactionsMsg, eth.PooledTransactionsMsg,
		eth.GetReceiptsMsg, eth.ReceiptsMsg,
	}
	seq := make([]int, config.SequenceLength)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < config.SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}
