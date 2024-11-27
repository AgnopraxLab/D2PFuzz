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

package fuzzer

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	ethstate = []int{eth.StatusMsg, eth.GetReceiptsMsg}
)

type EthMaker struct {
	suiteList []*eth.Suite

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type ethSnapshot struct {
	state_1 *eth.StatusPacket
	state_2 *eth.ReceiptsPacket
	n       *enode.Node
}

type ethPacketTestResult struct {
	RequestType string
	Success     bool
	Response    eth.Packet
	Error       error
}

func NewEthMaker(targetDir string, chain string) *EthMaker {
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
			{
				Logs:    m.logs,
				Root:    m.root,
				Indexes: stIndex{Gas: 0, Value: 0, Data: 0},
			},
		}
		st.Post = postState
	}
	return st
}

func (m *EthMaker) PacketStart(traceOutput io.Writer) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []ethPacketTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	target := m.suiteList[0]

	// 初始化连接
	if err := target.InitializeAndConnect(); err != nil {
		if logger != nil {
			logger.Printf("Failed to initialize connection: %v", err)
		}
		return err
	}

	// 生成随机请求包
	req, _ := target.GenPacket(eth.StatusMsg)

	for i := 0; i < config.MutateCount; i++ {
		wg.Add(1)

		go func(iteration int, currentReq eth.Packet) {
			defer wg.Done()

			result := ethPacketTestResult{
				RequestType: fmt.Sprintf("%d", currentReq.Kind()),
			}

			// 发送并等待响应
			err := m.handlePacketWithResponse(currentReq, target, traceOutput)
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Success = true
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, req)

		time.Sleep(50 * time.Millisecond)
	}

	wg.Wait()

	// 分析结果
	analyzeEthResults(results, logger, config.SaveFlag, config.OutputDir)
	return nil
}

func (m *EthMaker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *ethSnapshot, len(m.suiteList))
		errorCh  = make(chan error, len(m.suiteList))
		logger   *log.Logger
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Iterate over each target object
	for _, target := range m.suiteList {
		wg.Add(1)
		go func(target *eth.Suite) {
			defer wg.Done()
			result := &ethSnapshot{
				n: target.DestList,
			}
			// First round: sending testSeq packets
			for i, packetType := range m.testSeq {
				req, _ := target.GenPacket(packetType)
				m.handlePacket(req, target, traceOutput)
				logger.Printf("Sent test packet to target: %s, packet: %v, using suite: %d", target.DestList.String(), req.Kind(), i)
			}
			// Round 2: sending stateSeq packets
			for i, packetType := range m.stateSeq {
				req, _ := target.GenPacket(packetType)
				m.handlePacket(req, target, traceOutput)
				logger.Printf("Sent state packet to target: %s, packet: %v, using suite: %d", target.DestList.String(), req.Kind(), i)
			}
			resultCh <- result
		}(target)
	}
	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(resultCh)
		close(errorCh)
	}()
	for err := range errorCh {
		if err != nil {
			return fmt.Errorf("error occurred during fuzzing: %v", err)
		}
	}
	// TODO: Need deal result
	var allSnapshot []*ethSnapshot
	for snapshot := range resultCh {
		allSnapshot = append(allSnapshot, snapshot)
	}
	// fmt.Printf("All results: %v\n", allSnapshot)

	return nil
}

func (m *EthMaker) handlePacket(req eth.Packet, suite *eth.Suite, traceOutput io.Writer) error {
	switch p := req.(type) {
	case *eth.StatusPacket:
		return suite.InitializeAndConnect()
	case *eth.TransactionsPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return fmt.Errorf("failed to send next block: %v", err)
		}
		return m.handleTransactionPacket(p, suite, traceOutput)
	case *eth.GetBlockHeadersPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleGetBlockHeadersPacket(p, suite, traceOutput)
	case *eth.GetBlockBodiesPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleGetBlockBodiesPacket(p, suite, traceOutput)
	case *eth.NewBlockHashesPacket, *eth.BlockHeadersPacket, *eth.BlockBodiesPacket, *eth.NewBlockPacket, *eth.PooledTransactionsPacket, *eth.ReceiptsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleSendOnlyPacket(p, suite, traceOutput)
	case *eth.NewPooledTransactionHashesPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return fmt.Errorf("failed to send next block: %v", err)
		}
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handlePooledTransactionHashesPacket(p, suite, traceOutput)
	case *eth.GetPooledTransactionsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleGetPooledTransactionsPacket(p, suite, traceOutput)
	case *eth.GetReceiptsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleGetReceiptsPacket(p, suite, traceOutput)
	default:
		if traceOutput != nil {
			_, err := fmt.Fprintf(traceOutput, "Unsupported packet type: %T\n", req)
			if err != nil {
				// Handle the error, maybe log it or return it
				log.Printf("Error writing to trace output: %v", err)
			}
		}
		return nil
	}
}

func (m *EthMaker) handleSendOnlyPacket(packet interface{}, suite *eth.Suite, traceOutput io.Writer) error {
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

	if err := suite.SendMsg(eth.EthProto, msgcode, packet); err != nil {
		return fmt.Errorf("could not send %T: %v", packet, err)
	}

	return nil
}

func (m *EthMaker) handleTransactionPacket(p *eth.TransactionsPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending transaction")
	}
	for i, tx := range *p {
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending transaction %d\n", i+1)
		}

		if err := suite.SendTxs([]*types.Transaction{tx}); err != nil {
			return fmt.Errorf("failed to send transaction: %v", err)
		}

		if traceOutput != nil {
			fmt.Println(traceOutput, "Transaction %d sent successfully\n", i+1)
		}
	}
	return nil
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockHeadersPacket with RequestId: %d\n", p.RequestId)
	}

	if err := suite.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockHeadersMsg: %v", err)
	}

	headers := new(eth.BlockHeadersPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return fmt.Errorf("error reading BlockHeadersMsg: %v", err)
	}

	if traceOutput != nil {
		fmt.Fprintf(traceOutput, "Received BlockHeaders packet: %+v\n", headers)
	}

	if got, want := headers.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id: got %d, want %d", headers.RequestId, p.RequestId)
	}

	expected, err := suite.GetHeaders(p)
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

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockBodiesPacket with RequestId: %d\n", p.RequestId)
	}

	if err := suite.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.BlockBodiesPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if traceOutput != nil {
		fmt.Fprintf(traceOutput, "Received BlockBodies packet: %+v\n", resp)
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

func (m *EthMaker) handlePooledTransactionHashesPacket(p *eth.NewPooledTransactionHashesPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending NewPooledTransactionHashesPacket")
	}

	if err := suite.SendMsg(eth.EthProto, eth.NewPooledTransactionHashesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.GetPooledTransactionsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.GetPooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if traceOutput != nil {
		fmt.Fprintf(traceOutput, "Received GetPooledTransactions packet: %+v\n", resp)
	}

	if got, want := len(resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
		return fmt.Errorf("unexpected number of txs requested: got %d, want %d", got, want)
	}
	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetPooledTransactionsPacket(p *eth.GetPooledTransactionsPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := suite.SendMsg(eth.EthProto, eth.GetPooledTransactionsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.PooledTransactionsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.PooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if traceOutput != nil {
		fmt.Fprintf(traceOutput, "Received GetPooledTransactions packet: %+v\n", resp)
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

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, suite *eth.Suite, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := suite.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.ReceiptsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if traceOutput != nil {
		fmt.Fprintf(traceOutput, "Received Receipts packet: %+v\n", resp)
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

// packet test deal data
func (m *EthMaker) handlePacketWithResponse(req eth.Packet, suite *eth.Suite, traceOutput io.Writer) error {
	switch p := req.(type) {
	case *eth.StatusPacket:
		return suite.InitializeAndConnect()
	case *eth.TransactionsPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return fmt.Errorf("failed to send forkchoice update: %v", err)
		}
		return m.handleTransactionPacket(p, suite, traceOutput)
	case *eth.GetBlockHeadersPacket:
		return m.handleGetBlockHeadersPacket(p, suite, traceOutput)
	case *eth.GetBlockBodiesPacket:
		return m.handleGetBlockBodiesPacket(p, suite, traceOutput)
	case *eth.GetPooledTransactionsPacket:
		return m.handleGetPooledTransactionsPacket(p, suite, traceOutput)
	case *eth.GetReceiptsPacket:
		return m.handleGetReceiptsPacket(p, suite, traceOutput)
	default:
		return m.handleSendOnlyPacket(p, suite, traceOutput)
	}
}

func analyzeEthResults(results []ethPacketTestResult, logger *log.Logger, saveToFile bool, outputDir string) error {
	if saveToFile {
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}

		// Generate filename (using timestamp)
		filename := filepath.Join(outputDir, "/eth", fmt.Sprintf("analysis_results_%s.json", time.Now().Format("2006-01-02_15-04-05")))

		// Save to file
		data, err := json.MarshalIndent(results, "", "    ")
		if err != nil {
			return fmt.Errorf("JSON serialization failed: %v", err)
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}

		logger.Printf("Results saved to file: %s\n", filename)
	} else {
		// Output to log
		logger.Printf("Number of results with: %d\n", len(results))
	}

	return nil
}
