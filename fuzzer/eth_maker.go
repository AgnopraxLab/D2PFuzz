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
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	// ethoptions = []int{eth.StatusMsg, eth.NewBlockHashesMsg, eth.TransactionsMsg, eth.GetBlockHeadersMsg,
	// 	eth.BlockHeadersMsg, eth.GetBlockBodiesMsg, eth.BlockBodiesMsg, eth.NewBlockMsg,
	// 	eth.NewPooledTransactionHashesMsg, eth.GetPooledTransactionsMsg, eth.PooledTransactionsMsg,
	// 	eth.GetReceiptsMsg, eth.ReceiptsMsg}
	ethoptions = []int{eth.GetBlockHeadersMsg, eth.GetBlockBodiesMsg, eth.GetReceiptsMsg}
	ethstate   = []int{eth.StatusMsg, eth.GetReceiptsMsg}
)

type EthMaker struct {
	SuiteList []*eth.Suite

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	PakcetSeed []eth.Packet // Use store packet seed to mutator

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
	PacketID     int
	RequestType  string
	Check        bool
	CheckResults []bool
	Success      bool
	Request      eth.Packet
	Response     eth.Packet
	Valid        bool
	Error        string `json:"error"`

	DiffCode []int // 新增差分编码字段
}

func NewEthMaker(targetDir string, chain string) *EthMaker {
	var suiteList []*eth.Suite

	nodeList, err := getList(targetDir)
	if err != nil {
		fmt.Printf("failed to read targetDir: %v", err)
		return nil
	}

	for _, node := range nodeList {
		suite, err := generator.Initeth(node, chain)
		if err != nil {
			fmt.Printf("failed to initialize eth clients: %v", err)
		}
		suiteList = append(suiteList, suite)
	}

	ethmaker := &EthMaker{
		SuiteList: suiteList,
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

func (m *EthMaker) PacketStart(traceOutput io.Writer, seed eth.Packet, stats *UDPPacketStats) error {
	var (
		logger *log.Logger
		mu     sync.Mutex
	)

	if len(m.SuiteList) == 0 {
		return fmt.Errorf("empty suite list")
	}

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))
	results := make([][]ethPacketTestResult, len(m.SuiteList))
	currentSeed := seed

	// 初始化 results 数组
	for i := range results {
		results[i] = make([]ethPacketTestResult, 0)
	}

	// 特殊连接处理
	if seed.Kind() == eth.GetBlockHeadersMsg ||
		seed.Kind() == eth.GetBlockBodiesMsg ||
		seed.Kind() == eth.GetReceiptsMsg {
		for i := 0; i < len(m.SuiteList); i++ {
			if err := m.SuiteList[i].SetupConn(); err != nil {
				return fmt.Errorf("failed to setup connection: %v", err)
			}
			defer m.SuiteList[i].Conn().Close()
		}
	}

	for i := 1; i <= MutateCount; i++ {
		fmt.Printf("Start Mutate count: %d\n", i)
		mutateSeed := cloneAndMutateEthPacket(mutator, currentSeed, m.SuiteList[0].Chain())

		// 创建一个新的 WaitGroup 用于当前迭代
		var wg sync.WaitGroup
		wg.Add(len(m.SuiteList)) // 在启动 goroutine 前添加计数

		for j := 0; j < len(m.SuiteList); j++ {
			go func(j int, currentReq eth.Packet, packetStats *UDPPacketStats) {
				defer wg.Done()

				result := ethPacketTestResult{
					PacketID:    i,
					RequestType: fmt.Sprintf("%d", currentReq.Kind()),
					Request:     currentReq,
				}

				result.CheckResults = m.checkRequestSemantics(currentReq, m.SuiteList[0].Chain())
				result.Check = allTrue(result.CheckResults)

				resp, success, valid, err := m.handlePacketWithResponse(currentReq, m.SuiteList[j])
				if err != nil {
					result.Error = err.Error()
					result.Success = false
					result.Valid = false
				} else {
					result.Response = resp
					if currentReq.Kind() == eth.StatusMsg {
						result.Success = success
					} else {
						result.Success = (resp != nil)
					}
					result.Valid = valid
				}

				result.DiffCode = ethRespToInts(resp)
				fmt.Printf("Client: %d, DiffCodeState: %v\n", j, result.DiffCode)

				mu.Lock()
				updateCoverage(&StateCoverage, result.DiffCode)
				if result.Check {
					if !result.Success {
						packetStats.CheckTrueFail++
						results[j] = append(results[j], result)
					} else if result.Valid {
						packetStats.CheckTruePass++
						results[j] = append(results[j], result)
					}
				} else {
					if result.Success {
						if result.Valid {
							packetStats.CheckFalsePassOK++
							results[j] = append(results[j], result)
						} else {
							packetStats.CheckFalsePassBad++
							results[j] = append(results[j], result)
						}
					}
				}
				mu.Unlock()
			}(j, mutateSeed, stats)
		}

		// 等待当前迭代的所有 goroutine 完成
		wg.Wait()
		currentSeed = mutateSeed
		time.Sleep(PacketSleepTime)
	}

	// 分析结果
	if SaveFlag {
		for i, result := range results {
			nodeOutputDir := filepath.Join(OutputDir, fmt.Sprintf("node_%d", i))
			analyzeResultsEth(result, logger, nodeOutputDir)
		}
	}

	return nil
}

// 辅助函数：打印results数组
// func printResults(results []ethPacketTestResult, logger *log.Logger) {
// 	for i, r := range results {
// 		resultBytes, err := json.MarshalIndent(r, "", "    ")
// 		if err != nil {
// 			logger.Printf("Error marshaling result %d: %v", i, err)
// 			continue
// 		}
// 		logger.Printf("Result %d:\n%s", i, string(resultBytes))
// 	}
// 	logger.Printf("Total results: %d\n", len(results))
// 	logger.Printf("=====================================")
// }

func (m *EthMaker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *ethSnapshot, len(m.SuiteList))
		errorCh  = make(chan error, len(m.SuiteList))
		logger   *log.Logger
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Iterate over each target object
	for _, target := range m.SuiteList {
		wg.Add(1)
		go func(target *eth.Suite) {
			defer wg.Done()
			result := &ethSnapshot{
				n: target.DestList,
			}
			// First round: sending testSeq packets
			for i, packetType := range m.testSeq {
				req, _ := target.GenPacket(packetType)
				m.handlePacket(req, target, logger)
				logger.Printf("Sent test packet to target: %s, packet: %v, using suite: %d", target.DestList.String(), req.Kind(), i)
			}
			// Round 2: sending stateSeq packets
			for i, packetType := range m.stateSeq {
				req, _ := target.GenPacket(packetType)
				m.handlePacket(req, target, logger)
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

func (m *EthMaker) handlePacket(req eth.Packet, suite *eth.Suite, logger *log.Logger) error {
	switch p := req.(type) {
	case *eth.StatusPacket:
		return suite.InitializeAndConnect()
	case *eth.TransactionsPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return fmt.Errorf("failed to send next block: %v", err)
		}
		result := m.handleTransactionPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle transaction packet: %v", result.Error)
		}
		return nil
	case *eth.GetBlockHeadersPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetBlockHeadersPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get block headers packet: %v", result.Error)
		}
		return nil
	case *eth.GetBlockBodiesPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetBlockBodiesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get block bodies packet: %v", result.Error)
		}
		return nil
	case *eth.NewBlockHashesPacket, *eth.BlockHeadersPacket, *eth.BlockBodiesPacket, *eth.NewBlockPacket, *eth.PooledTransactionsPacket, *eth.ReceiptsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleSendOnlyPacket(p, suite)
	case *eth.NewPooledTransactionHashesPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return fmt.Errorf("failed to send next block: %v", err)
		}
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handlePooledTransactionHashesPacket(p, suite, logger)
	case *eth.GetPooledTransactionsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetPooledTransactionsPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get pooled transactions packet: %v", result.Error)
		}
		return nil
	case *eth.GetReceiptsPacket:
		if err := suite.InitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetReceiptsPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get receipts packet: %v", result.Error)
		}
		return nil
	default:
		if logger != nil {
			_, err := fmt.Printf("Unsupported packet type: %T\n", req)
			if err != nil {
				// Handle the error, maybe log it or return it
				log.Printf("Error writing to trace output: %v", err)
			}
		}
		return nil
	}
}

func (m *EthMaker) handleStatusPacket(p *eth.StatusPacket, suite *eth.Suite) ethPacketTestResult {
	// First establish a correct connection as a control
	// if err := suite.SetupConn(); err != nil {
	//     return ethPacketTestResult{
	//         Error: fmt.Errorf("failed to setup control connection: %v", err).Error(),
	//     }
	// }

	// 1. Establish connection
	conn, err := suite.Dial()
	if err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("dial failed: %v", err).Error(),
			Success: false, // 连接失败，没有响应
			Valid:   false,
		}
	}
	defer conn.Close()

	// 2. Use our mutated status packet for peer connection
	if err := conn.Peer(suite.Chain(), p); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("peer failed: %v", err).Error(),
			Success: false, // 连接失败，没有响应
			Valid:   false,
		}
	}

	// 3. Send a GetReceipts packet to verify the connection
	testReq, _ := suite.GenPacket(eth.GetReceiptsMsg)
	resp, testValid, success, err := m.handlePacketWithResponse(testReq, suite)

	return ethPacketTestResult{
		Response: resp,
		Success:  success,                  // 使用handlePacketWithResponse返回的success值
		Valid:    testValid && resp != nil, // 需要有响应且响应有效
		Error:    err.Error(),
	}
}

func (m *EthMaker) handleSendOnlyPacket(packet interface{}, suite *eth.Suite) error {
	var msgcode uint64

	switch packet.(type) {
	case *eth.NewBlockHashesPacket:
		msgcode = eth.NewBlockHashesMsg
		//logger.Println(logger, "Sending NewBlockHashesPacket")
	case *eth.BlockHeadersPacket:
		msgcode = eth.BlockHeadersMsg
		//logger.Println(logger, "Sending BlockHeadersPacket")
	case *eth.BlockBodiesPacket:
		msgcode = eth.BlockBodiesMsg
		//logger.Println(logger, "Sending BlockBodiesPacket")
	case *eth.NewBlockPacket:
		msgcode = eth.NewBlockMsg
		//logger.Println(logger, "Sending NewBlockPacket")
	case *eth.PooledTransactionsPacket:
		msgcode = eth.PooledTransactionsMsg
		//logger.Println(logger, "Sending PooledTransactionsPacket")
	case *eth.ReceiptsPacket:
		msgcode = eth.ReceiptsMsg
		//logger.Println(logger, "Sending ReceiptsPacket")
	default:
		return fmt.Errorf("unsupported packet type: %T", packet)
	}

	if err := suite.SendMsg(eth.EthProto, msgcode, packet); err != nil {
		return fmt.Errorf("could not send %T: %v", packet, err)
	}

	return nil
}

func (m *EthMaker) handleTransactionPacket(p *eth.TransactionsPacket, suite *eth.Suite) ethPacketTestResult {
	if err := suite.SendForkchoiceUpdated(); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("failed to send forkchoice update: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}

	for _, tx := range *p {
		if err := suite.SendTxs([]*types.Transaction{tx}); err != nil {
			return ethPacketTestResult{
				Error:   fmt.Errorf("failed to send transaction: %v", err).Error(),
				Success: false,
				Valid:   false,
			}
		}
	}
	return ethPacketTestResult{
		Success: true, // 发送成功
		Valid:   true, // 交易被接受
	}
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, suite *eth.Suite) ethPacketTestResult {

	// 修改包内容进行测试
	// p.Origin.Number = 2944
	// p.Amount = 11
	// p.Skip = 18446744073709551615
	// //p.Skip = 18446744073709551615
	// p.Reverse = false
	// p.Origin.Hash = common.Hash{} // 确保使用Number而不是Hash

	// 先进行语义检查
	checkResults := checkGetBlockHeadersSemantics(p, suite.Chain())

	// 发送请求（无论检查是否通过都发送）
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetBlockHeadersMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 读取响应
	headers := new(eth.BlockHeadersPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading BlockHeadersMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 检查请求ID
	if got, want := headers.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response:     headers,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error:        fmt.Sprintf("unexpected request id: got %d, want %d", got, want),
		}
	}

	// 获取预期的headers
	expected, err := suite.GetHeaders(p)
	if err != nil {
		return ethPacketTestResult{
			Response:     headers,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error:        fmt.Sprintf("failed to get headers: %v", err),
		}
	}

	// 比较结果
	if !eth.HeadersMatch(expected, headers.BlockHeadersRequest) {
		return ethPacketTestResult{
			Response:     headers,
			Valid:        false,
			CheckResults: checkResults,
			Error:        "header mismatch",
		}
	}

	return ethPacketTestResult{
		Response:     headers,
		Valid:        true,
		CheckResults: checkResults,
	}
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, suite *eth.Suite) ethPacketTestResult {
	// 先进行语义检查
	checkResults := checkGetBlockBodiesSemantics(p, suite.Chain())

	// 发送请求
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetBlockBodiesMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 读取响应
	resp := new(eth.BlockBodiesPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading BlockBodiesMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 统计有效哈希数量
	validHashCount := 0
	blockHashes := make(map[common.Hash]bool)
	for _, block := range suite.Chain().Blocks() {
		blockHashes[block.Hash()] = true
	}

	for _, hash := range *p.GetBlockBodiesRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 检查响应数量是否与有效哈希数量完全匹配
	if len(resp.BlockBodiesResponse) != validHashCount {
		return ethPacketTestResult{
			Response:     resp,
			Valid:        false,
			CheckResults: checkResults,
			Error:        fmt.Sprintf("response count mismatch: got %d, expected %d", len(resp.BlockBodiesResponse), validHashCount),
		}
	}

	// 检查请求ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response:     resp,
			Valid:        false,
			CheckResults: checkResults,
			Error:        fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}

	// 所有检查通过
	return ethPacketTestResult{
		Response:     resp,
		Valid:        true,
		CheckResults: checkResults,
	}
}

func (m *EthMaker) handlePooledTransactionHashesPacket(p *eth.NewPooledTransactionHashesPacket, suite *eth.Suite, logger *log.Logger) error {

	logger.Println("Sending NewPooledTransactionHashesPacket")

	if err := suite.SendMsg(eth.EthProto, eth.NewPooledTransactionHashesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.GetPooledTransactionsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.GetPooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	logger.Printf("Received GetPooledTransactions packet: %+v\n", resp)

	if got, want := len(*resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
		return fmt.Errorf("unexpected number of txs requested: got %d, want %d", got, want)
	}
	logger.Printf("Received block bodies for request %d\n", resp.RequestId)

	return nil
}

func (m *EthMaker) handleGetPooledTransactionsPacket(p *eth.GetPooledTransactionsPacket, suite *eth.Suite) ethPacketTestResult {
	// 1. 发送 forkchoice updated
	if err := suite.SendForkchoiceUpdated(); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("failed to send forkchoice update: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}

	// 2. 生成交易
	var (
		from, nonce = suite.Chain().GetSender(1)
		count       = 10 // 先用较小数量测试
		txs         []*types.Transaction
		hashes      []common.Hash
		set         = make(map[common.Hash]struct{})
	)

	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   suite.Chain().Config().ChainID,
			Nonce:     nonce + uint64(i),
			GasTipCap: common.Big1,
			GasFeeCap: suite.Chain().Head().BaseFee(),
			Gas:       75000,
			To:        &common.Address{}, // 添加接收地址
		}
		tx, err := suite.Chain().SignTx(from, types.NewTx(inner))
		if err != nil {
			return ethPacketTestResult{
				Error:   fmt.Errorf("failed to sign transaction: %v", err).Error(),
				Success: false,
				Valid:   false,
			}
		}
		txs = append(txs, tx)
		set[tx.Hash()] = struct{}{}
		hashes = append(hashes, tx.Hash())
	}
	suite.Chain().IncNonce(from, uint64(count))

	// 3. 直接使用已有连接发送交易
	if err := suite.SendTxs(txs); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("failed to send txs: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}

	// 4. 等待交易确认
	if err := suite.SetupConn(); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("failed to setup connection: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}
	defer suite.Conn().Close()

	// Modify: Correctly construct GetPooledTransactionsPacket
	request := eth.GetPooledTransactionsRequest(hashes) // Convert hashes to GetPooledTransactionsRequest type
	newRequest := &eth.GetPooledTransactionsPacket{
		RequestId:                    p.RequestId,
		GetPooledTransactionsRequest: &request,
	}

	// Use new request to replace original request
	if err := suite.Conn().Write(eth.EthProto, eth.GetPooledTransactionsMsg, newRequest); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("could not write to conn: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}
	// Check that all received transactions match those that were sent to node.
	msg := new(eth.PooledTransactionsPacket)
	if err := suite.Conn().ReadMsg(eth.EthProto, eth.PooledTransactionsMsg, &msg); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("error reading from connection: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}
	if got, want := msg.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Request:  newRequest,
			Response: msg,
			Success:  true,  // 收到响应但内容不匹配
			Valid:    false, // 请求ID不匹配
			Error:    fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			return ethPacketTestResult{
				Request:  newRequest,
				Response: msg,
				Success:  true,  // 收到响应但内容不匹配
				Valid:    false, // 包含未知交易
				Error:    fmt.Sprintf("unexpected tx received: %v", got.Hash()),
			}
		}
	}

	// return ethPacketTestResult{
	// 	Response: msg,
	// 	Success:  true,
	// }

	return ethPacketTestResult{
		Request:  newRequest,
		Response: msg,
		Success:  true, // 收到响应
		Valid:    true, // 所有检查通过
	}
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, suite *eth.Suite) ethPacketTestResult {
	// 1. 语义检查
	checkResults := checkGetReceiptsSemantics(p, suite.Chain())

	// 2. 发送请求
	if err := suite.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetReceiptsMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 3. 读取响应
	resp := new(eth.ReceiptsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading ReceiptsMsg: %v", err).Error(),
			CheckResults: checkResults,
			Valid:        false,
		}
	}

	// 4. 统计有效哈希数量
	validHashCount := 0
	blockHashes := make(map[common.Hash]bool)
	for _, block := range suite.Chain().Blocks() {
		blockHashes[block.Hash()] = true
	}

	for _, hash := range *p.GetReceiptsRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 5. 检查响应数量是否与有效哈希数量完全匹配
	if len(resp.ReceiptsResponse) != validHashCount {
		return ethPacketTestResult{
			Response:     resp,
			Valid:        false,
			CheckResults: checkResults,
			Error:        fmt.Sprintf("response count mismatch: got %d, expected %d", len(resp.ReceiptsResponse), validHashCount),
		}
	}

	// 6. 检查请求ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response:     resp,
			Valid:        false,
			CheckResults: checkResults,
			Error:        fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}

	// 所有检查通过
	return ethPacketTestResult{
		Response:     resp,
		Valid:        true,
		CheckResults: checkResults,
	}
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
	seq := make([]int, SequenceLength)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}

// packet test deal data
func (m *EthMaker) handlePacketWithResponse(req eth.Packet, suite *eth.Suite) (eth.Packet, bool, bool, error) {
	switch p := req.(type) {
	case *eth.StatusPacket:
		result := m.handleStatusPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	case *eth.TransactionsPacket:
		result := m.handleTransactionPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	case *eth.GetBlockHeadersPacket:
		result := m.handleGetBlockHeadersPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	case *eth.GetBlockBodiesPacket:
		result := m.handleGetBlockBodiesPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	case *eth.GetPooledTransactionsPacket:
		result := m.handleGetPooledTransactionsPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	case *eth.GetReceiptsPacket:
		result := m.handleGetReceiptsPacket(p, suite)
		return result.Response, result.Success, result.Valid, nil
	default:
		if err := suite.SetupConn(); err != nil {
			return nil, false, false, fmt.Errorf("failed to setup connection: %v", err)
		}
		defer suite.Conn().Close()
		err := m.handleSendOnlyPacket(p, suite)
		return nil, false, false, err
	}
}

// checkRequestSemantics 检查请求的语义正确性
func (m *EthMaker) checkRequestSemantics(req eth.Packet, chain *eth.Chain) []bool {
	var results []bool

	switch p := req.(type) {
	case *eth.StatusPacket:
		results = checkStatusSemantics(p, chain)
	case *eth.GetBlockHeadersPacket:
		results = checkGetBlockHeadersSemantics(p, chain)
	case *eth.BlockHeadersPacket:
		results = checkBlockHeadersSemantics(p, chain)
	case *eth.GetBlockBodiesPacket:
		results = checkGetBlockBodiesSemantics(p, chain)
	case *eth.BlockBodiesPacket:
		results = checkBlockBodiesSemantics(p)
	case *eth.GetReceiptsPacket:
		results = checkGetReceiptsSemantics(p, chain)
	case *eth.TransactionsPacket:
		return checkTransactionsSemantics(p)
	case *eth.GetPooledTransactionsPacket:
		results = checkGetPooledTransactionsSemantics(p)
	case *eth.PooledTransactionsPacket:
		results = checkPooledTransactionsSemantics(p)
	case *eth.NewBlockHashesPacket:
		results = checkNewBlockHashesSemantics(p, chain)
	case *eth.NewBlockPacket:
		results = checkNewBlockSemantics(p, chain)
	case *eth.NewPooledTransactionHashesPacket:
		results = checkNewPooledTransactionHashesSemantics(p)
	default:
		// 对于其他类型的包，暂时返回true
		results = []bool{true}
	}

	return results
}

func checkStatusSemantics(p *eth.StatusPacket, chain *eth.Chain) []bool {
	results := make([]bool, 5) // 5个检查项

	// 1. 检查 Head 是否是有效的区块哈希
	blocks := chain.Blocks()
	headBlock := blocks[len(blocks)-1]
	results[0] = p.Head == headBlock.Hash()

	// 2. 检查 TD (Total Difficulty) 是否正确
	results[1] = p.TD != nil && p.TD.Cmp(chain.TD()) == 0

	// 3. 检查 ForkID 是否匹配
	expectedForkID := chain.ForkID()
	results[2] = reflect.DeepEqual(p.ForkID, expectedForkID)

	// 4. 检查协议版本是否在有效范围内
	results[3] = p.ProtocolVersion >= 64 && p.ProtocolVersion <= 68

	// 5. 检查 Genesis 哈希是否正确
	genesisBlock := blocks[0]
	results[4] = p.Genesis == genesisBlock.Hash()

	return results
}

// checkGetBlockHeadersSemantics 检查GetBlockHeaders请求的语义正确性
func checkGetBlockHeadersSemantics(p *eth.GetBlockHeadersPacket, chain *eth.Chain) []bool {
	results := make([]bool, 4)
	chainLen := uint64(chain.Len())

	// 检查1: Origin 的有效性
	if p.Origin.Hash != (common.Hash{}) {
		found := false
		for _, block := range chain.Blocks() {
			if block.Hash() == p.Origin.Hash {
				found = true
				break
			}
		}
		results[0] = found && p.Origin.Number == 0
	} else {
		results[0] = p.Origin.Number < chainLen
	}

	// 检查2: Amount 必须大于0且合理
	results[1] = p.Amount > 0 && p.Amount <= 1024

	// 如果Amount无效，后续检查都失败
	if !results[1] {
		results[2] = false
		results[3] = false
		return results
	}

	// 检查3: Skip和范围检查
	if p.Amount == 1 {
		// Amount为1时，Skip值不影响结果
		results[2] = true
	} else if p.Skip >= chainLen {
		results[2] = false
	} else if p.Reverse {
		// 检查是否有足够的前置区块
		minRequired := (p.Amount - 1) * (p.Skip + 1)
		results[2] = p.Origin.Number >= minRequired
	} else {
		// 检查是否超出链长度
		maxRequired := p.Origin.Number + (p.Amount-1)*(p.Skip+1)
		results[2] = maxRequired < chainLen
	}

	// 检查4: 预估响应大小
	estimatedSize := p.Amount * 500         // 每个区块头约500字节
	results[3] = estimatedSize <= 1024*1024 // 限制在1MB以内

	return results
}

func checkBlockHeadersSemantics(p *eth.BlockHeadersPacket, chain *eth.Chain) []bool {
	results := make([]bool, 4) // 4个检查项

	// 检查1: 请求不能为空
	if p == nil || len(p.BlockHeadersRequest) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 区块头的数量不能超过限制
	const MAX_HEADERS = 512 // 最大区块头数量限制
	results[1] = len(p.BlockHeadersRequest) <= MAX_HEADERS

	// 检查3: 区块头必须按序号排序且不能超过链长度
	results[2] = true
	chainLen := chain.Len()
	var lastNumber uint64
	for i, header := range p.BlockHeadersRequest {
		if header == nil {
			results[2] = false
			break
		}

		// 检查区块号
		currentNumber := header.Number.Uint64()
		if currentNumber >= uint64(chainLen) {
			results[2] = false
			break
		}

		// 检查序号递增（第一个区块除外）
		if i > 0 && currentNumber <= lastNumber {
			results[2] = false
			break
		}
		lastNumber = currentNumber
	}

	// 检查4: 每个区块头的基本字段有效性
	results[3] = true
	for _, header := range p.BlockHeadersRequest {
		// 检查必要字段不为空
		if header.ParentHash == (common.Hash{}) ||
			header.UncleHash == (common.Hash{}) ||
			header.Root == (common.Hash{}) ||
			header.TxHash == (common.Hash{}) ||
			header.ReceiptHash == (common.Hash{}) ||
			header.Number == nil ||
			header.GasLimit == 0 {
			results[3] = false
			break
		}

		// 检查Gas相关字段
		if header.GasUsed > header.GasLimit {
			results[3] = false
			break
		}
	}

	return results
}

func checkGetBlockBodiesSemantics(p *eth.GetBlockBodiesPacket, chain *eth.Chain) []bool {
	results := make([]bool, 1)

	// 检查1: 请求不能为空
	if p.GetBlockBodiesRequest == nil || len(*p.GetBlockBodiesRequest) == 0 {
		results[0] = false
		return results
	}

	// 构建区块哈希映射
	blockHashes := make(map[common.Hash]bool)
	for _, block := range chain.Blocks() {
		blockHashes[block.Hash()] = true
	}

	// 计算有效哈希数量
	validHashCount := 0
	for _, hash := range *p.GetBlockBodiesRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 所有哈希都无效时返回false
	results[0] = validHashCount > 0
	return results
}

func checkBlockBodiesSemantics(p *eth.BlockBodiesPacket) []bool {
	results := make([]bool, 4) // 4个检查项

	// 检查1: 请求不能为空
	if p == nil || len(p.BlockBodiesResponse) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 区块体的数量不能超过限制
	const MAX_BODIES = 256 // 最大区块体数量限制
	results[1] = len(p.BlockBodiesResponse) <= MAX_BODIES

	// 检查3: 每个区块体的基本字段有效性
	results[2] = true
	for _, body := range p.BlockBodiesResponse {
		// 检查交易列表
		if body.Transactions == nil {
			results[2] = false
			break
		}

		// 检查每个交易的有效性
		for _, tx := range body.Transactions {
			if !isValidTransaction(tx) {
				results[2] = false
				break
			}
		}

		// 检查叔块列表
		if body.Uncles != nil {
			for _, uncle := range body.Uncles {
				if uncle == nil || uncle.Number == nil ||
					uncle.GasLimit == 0 || uncle.GasUsed > uncle.GasLimit {
					results[2] = false
					break
				}
			}
		}

		// 检查提款列表（如果存在）
		if body.Withdrawals != nil {
			for _, withdrawal := range body.Withdrawals {
				if withdrawal == nil ||
					withdrawal.Address == (common.Address{}) ||
					withdrawal.Amount == 0 {
					results[2] = false
					break
				}
			}
		}
	}

	// 检查4: 资源限制检查
	results[3] = true
	var totalTxs, totalUncles, totalWithdrawals int
	for _, body := range p.BlockBodiesResponse {
		totalTxs += len(body.Transactions)
		if body.Uncles != nil {
			totalUncles += len(body.Uncles)
		}
		if body.Withdrawals != nil {
			totalWithdrawals += len(body.Withdrawals)
		}
	}

	// 设置合理的资源限制
	const (
		MAX_TXS_PER_RESPONSE         = 4096 // 每个响应最大交易数
		MAX_UNCLES_PER_RESPONSE      = 512  // 每个响应最大叔块数
		MAX_WITHDRAWALS_PER_RESPONSE = 1024 // 每个响应最大提款数
	)

	results[3] = totalTxs <= MAX_TXS_PER_RESPONSE &&
		totalUncles <= MAX_UNCLES_PER_RESPONSE &&
		totalWithdrawals <= MAX_WITHDRAWALS_PER_RESPONSE

	return results
}

func checkGetReceiptsSemantics(p *eth.GetReceiptsPacket, chain *eth.Chain) []bool {
	results := make([]bool, 1) // 只需要一个检查项

	// 检查1: 请求不能为空
	if p.GetReceiptsRequest == nil || len(*p.GetReceiptsRequest) == 0 {
		results[0] = false
		return results
	}

	// 构建区块哈希映射
	blockHashes := make(map[common.Hash]bool)
	for _, block := range chain.Blocks() {
		blockHashes[block.Hash()] = true
	}

	// 计算有效哈希数量
	validHashCount := 0
	for _, hash := range *p.GetReceiptsRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 只要有有效哈希就认为请求是有效的
	results[0] = validHashCount > 0
	return results
}

func checkTransactionsSemantics(p *eth.TransactionsPacket) []bool {
	results := make([]bool, 3)

	// 检查1: 请求不能为空
	if p == nil {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 每个交易必须有效
	results[1] = true
	for _, tx := range *p {
		if !isValidTransaction(tx) {
			results[1] = false
			break
		}
	}

	// 检查3: 总大小限制
	totalSize := uint64(0)
	for _, tx := range *p {
		totalSize += tx.Size()
	}
	results[2] = totalSize <= 4*1024*1024 // 4MB限制

	return results
}

func isValidTransaction(tx *types.Transaction) bool {
	if tx == nil {
		return false
	}

	// 基本字段检查
	if tx.Gas() == 0 ||
		tx.GasPrice().Sign() < 0 ||
		tx.Value().Sign() < 0 {
		return false
	}

	// 根据交易类型进行特定检查
	switch tx.Type() {
	case types.DynamicFeeTxType:
		if tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 {
			return false
		}
	case types.BlobTxType:
		if tx.BlobGasFeeCap() == nil {
			return false
		}
	}

	return true
}

func checkGetPooledTransactionsSemantics(p *eth.GetPooledTransactionsPacket) []bool {
	results := make([]bool, 3) // 3个检查项

	// 检查1: 请求不能为空
	if p == nil || p.GetPooledTransactionsRequest == nil || len(*p.GetPooledTransactionsRequest) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 请求的哈希数量不能超过限制
	const MAX_HASHES = 256 // 最大请求哈希数量限制
	results[1] = len(*p.GetPooledTransactionsRequest) <= MAX_HASHES

	// 检查3: 每个哈希的有效性
	results[2] = true
	for _, hash := range *p.GetPooledTransactionsRequest {
		// 检查哈希不为空
		if hash == (common.Hash{}) {
			results[2] = false
			break
		}
	}

	return results
}

func checkPooledTransactionsSemantics(p *eth.PooledTransactionsPacket) []bool {
	results := make([]bool, 4) // 4个检查项

	// 检查1: 请求不能为空
	if p == nil || len(p.PooledTransactionsResponse) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 交易数量不能超过限制
	const MAX_TRANSACTIONS = 256 // 最大交易数量限制
	results[1] = len(p.PooledTransactionsResponse) <= MAX_TRANSACTIONS

	// 检查3: 每个交易的有效性
	results[2] = true
	for _, tx := range p.PooledTransactionsResponse {
		if !isValidTransaction(tx) {
			results[2] = false
			break
		}
	}

	// 检查4: 总大小限制
	results[3] = true
	var totalSize uint64
	for _, tx := range p.PooledTransactionsResponse {
		totalSize += tx.Size()
		// 限制总大小不超过4MB
		if totalSize > 4*1024*1024 {
			results[3] = false
			break
		}
	}

	return results
}

func checkNewBlockHashesSemantics(p *eth.NewBlockHashesPacket, chain *eth.Chain) []bool {
	results := make([]bool, 4) // 4个检查项

	// 检查1: 请求不能为空
	if p == nil || len(*p) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 区块号必须是递增的
	results[1] = true
	for i := 1; i < len(*p); i++ {
		if (*p)[i].Number <= (*p)[i-1].Number {
			results[1] = false
			break
		}
	}

	// 检查3: 区块号不能超过当前链的长度
	results[2] = true
	chainLen := uint64(chain.Len())
	for _, announcement := range *p {
		if announcement.Number >= chainLen {
			results[2] = false
			break
		}
	}

	// 检查4: 检查公告数量是否在合理范围内(不超过MAX_HASHES)
	const MAX_HASHES = 128 // 最大公告数量限制
	results[3] = len(*p) <= MAX_HASHES

	return results
}

func checkNewBlockSemantics(p *eth.NewBlockPacket, chain *eth.Chain) []bool {
	results := make([]bool, 5) // 5个检查项

	// 检查1: 请求不能为空
	if p == nil || p.Block == nil {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 区块头的有效性
	header := p.Block.Header()
	results[1] = header != nil &&
		header.ParentHash != (common.Hash{}) &&
		header.UncleHash != (common.Hash{}) &&
		header.Root != (common.Hash{}) &&
		header.TxHash != (common.Hash{}) &&
		header.ReceiptHash != (common.Hash{}) &&
		header.Number != nil &&
		header.GasLimit != 0 &&
		header.GasUsed <= header.GasLimit

	// 检查3: 区块号和父区块的一致性
	results[2] = true
	if header.Number.Uint64() > 0 {
		parentNumber := header.Number.Uint64() - 1
		found := false
		for _, block := range chain.Blocks() {
			if block.NumberU64() == parentNumber && block.Hash() == header.ParentHash {
				found = true
				break
			}
		}
		results[2] = found
	}

	// 检查4: 交易的有效性
	results[3] = true
	txs := p.Block.Transactions()
	for _, tx := range txs {
		if !isValidTransaction(tx) {
			results[3] = false
			break
		}
		// 检查交易的gas使用总和不超过区块gas限制
		if tx.Gas() > header.GasLimit {
			results[3] = false
			break
		}
	}

	// 检查5: 总难度的有效性
	results[4] = p.TD != nil && p.TD.Sign() > 0 // 总难度必须为正数
	if results[4] && header.Number.Uint64() > 0 {
		// 如果不是创世区块，总难度必须大于父区块的总难度
		parentTD := chain.TD()
		if parentTD != nil {
			results[4] = p.TD.Cmp(parentTD) > 0
		}
	}

	return results
}

func checkNewPooledTransactionHashesSemantics(p *eth.NewPooledTransactionHashesPacket) []bool {
	results := make([]bool, 4) // 4个检查项

	// 检查1: 请求不能为空
	if p == nil || len(p.Hashes) == 0 {
		results[0] = false
		return results
	}
	results[0] = true

	// 检查2: 三个数组的长度必须相等
	results[1] = len(p.Types) == len(p.Hashes) &&
		len(p.Sizes) == len(p.Hashes)

	// 检查3: 数量不能超过限制
	const MAX_HASHES = 1024 // 最大交易哈希数量限制
	results[2] = len(p.Hashes) <= MAX_HASHES

	// 检查4: 字段有效性检查
	results[3] = true
	for i, hash := range p.Hashes {
		// 检查哈希不为空
		if hash == (common.Hash{}) {
			results[3] = false
			break
		}

		// 检查类型值是否有效 (目前支持的类型: 0-2)
		if i < len(p.Types) && p.Types[i] > 2 {
			results[3] = false
			break
		}

		// 检查size是否合理 (不能为0或过大)
		if i < len(p.Sizes) && (p.Sizes[i] == 0 || p.Sizes[i] > 128*1024) { // 128KB作为单个交易的最大限制
			results[3] = false
			break
		}
	}

	return results
}

// analyzeResultsEth 分析测试结果并保存到文件
func analyzeResultsEth(results []ethPacketTestResult, logger *log.Logger, outputDir string) error {
	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fullPath := filepath.Join(outputDir, "eth")
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create eth directory: %v", err)
	}

	filename := filepath.Join(fullPath, fmt.Sprintf("analysis_results_%s.json", time.Now().Format("2006-01-02_15-04-05")))

	//Save to file
	data, err := json.MarshalIndent(results, "", "    ")
	if err != nil {
		return fmt.Errorf("JSON serialization failed: %v", err)
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	logger.Printf("Results saved to file: %s\n", filename)

	return nil
}

// cloneAndMutateV4Packet clones and mutates the packet
func cloneAndMutateEthPacket(mutator *fuzzing.Mutator, seed eth.Packet, chain *eth.Chain) eth.Packet {
	switch p := seed.(type) {
	case *eth.StatusPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateStatusPacket(mutator, &newPacket)
	case *eth.NewBlockHashesPacket:
		newPacket := *p
		return mutateNewBlockHashesPacket(mutator, &newPacket)
	case *eth.TransactionsPacket:
		// 创建深拷贝
		newPacket := make(eth.TransactionsPacket, len(*p))
		copy(newPacket, *p)
		return mutateTransactionsPacket(mutator, &newPacket)
	case *eth.GetBlockHeadersPacket:
		// 创建深拷贝
		newPacket := *p
		newRequest := *p.GetBlockHeadersRequest
		newPacket.GetBlockHeadersRequest = &newRequest
		return mutateGetBlockHeadersPacket(mutator, &newPacket, chain)
	case *eth.BlockHeadersPacket:
		newPacket := *p
		return mutateBlockHeadersPacket(mutator, &newPacket, chain)
	case *eth.GetBlockBodiesPacket:
		newPacket := *p
		newRequest := *p.GetBlockBodiesRequest
		newPacket.GetBlockBodiesRequest = &newRequest
		return mutateGetBlockBodiesPacket(mutator, &newPacket, chain)
	case *eth.BlockBodiesPacket:
		newPacket := *p
		return mutateBlockBodiesPacket(mutator, &newPacket)
	case *eth.NewBlockPacket:
		newPacket := *p
		return mutateNewBlockPacket(mutator, &newPacket)
	case *eth.NewPooledTransactionHashesPacket:
		newPacket := *p
		return mutateNewPooledTransactionHashesPacket(mutator, &newPacket)
	case *eth.GetPooledTransactionsPacket:
		newPacket := *p
		newRequest := *p.GetPooledTransactionsRequest
		newPacket.GetPooledTransactionsRequest = &newRequest
		return mutateGetPooledTransactionsPacket(mutator, &newPacket, chain)
	case *eth.PooledTransactionsPacket:
		newPacket := *p
		return mutatePooledTransactionsPacket(mutator, &newPacket)
	case *eth.GetReceiptsPacket:
		newPacket := *p
		newRequest := *p.GetReceiptsRequest
		newPacket.GetReceiptsRequest = &newRequest
		return mutateGetReceiptsPacket(mutator, &newPacket, chain)
	case *eth.ReceiptsPacket:
		newPacket := *p
		return mutateReceiptsPacket(mutator, &newPacket)
	default:
		return seed
	}
}

func mutateStatusPacket(mutator *fuzzing.Mutator, original *eth.StatusPacket) *eth.StatusPacket {
	mutated := *original

	// 各字段有30%的概率进行变异
	if rand.Float32() < 0.3 {
		mutated.ProtocolVersion = mutator.MutateProtocolVersion()
	}
	if rand.Float32() < 0.3 {
		mutated.NetworkID = mutator.MutateNetworkID()
	}
	if rand.Float32() < 0.3 {
		mutated.TD = mutator.MutateTotalDifficulty()
	}
	if rand.Float32() < 0.3 {
		mutated.Head = mutator.MutateHash()
	}
	if rand.Float32() < 0.3 {
		mutated.Genesis = mutator.MutateHash()
	}
	if rand.Float32() < 0.3 {
		mutated.ForkID = mutator.MutateForkID()
	}

	return &mutated
}

func mutateNewBlockHashesPacket(mutator *fuzzing.Mutator, original *eth.NewBlockHashesPacket) eth.Packet {
	mutated := *original

	// 各字段有30%的概率进行变异
	// 变异现有元素
	if rand.Float32() < 0.3 && len(mutated) > 0 {
		idx := mutator.RandRange(0, uint64(len(mutated)))
		if mutator.Bool() {
			// 变异哈希
			mutated[idx].Hash = mutator.MutateHash()
		} else {
			// 变异区块号
			mutated[idx].Number = mutator.RandRange(0, 1000000)
		}
	}

	// 添加新元素
	if rand.Float32() < 0.3 {
		mutated = append(mutated, struct {
			Hash   common.Hash
			Number uint64
		}{
			Hash:   mutator.MutateHash(),
			Number: mutator.RandRange(0, 1000000),
		})
	}

	// 删除随机元素
	if rand.Float32() < 0.3 && len(mutated) > 1 {
		idx := mutator.RandRange(0, uint64(len(mutated)))
		mutated = append(mutated[:idx], mutated[idx+1:]...)
	}

	return &mutated
}

func mutateTransactionsPacket(mutator *fuzzing.Mutator, original *eth.TransactionsPacket) eth.Packet {
	// Decide whether to modify existing transactions or create new ones
	if original == nil || len(*original) == 0 || mutator.Bool() {
		// Create new transactions
		count := mutator.Rand(5) + 1 // 1-5 transactions
		newTxs := make(eth.TransactionsPacket, count)
		for i := 0; i < count; i++ {
			newTxs[i] = mutator.MutateTransaction(nil)
		}
		return &newTxs
	}

	// Modify existing transactions
	mutated := make(eth.TransactionsPacket, len(*original))
	for i, tx := range *original {
		if mutator.Bool() {
			mutated[i] = mutator.MutateTransaction(tx)
		} else {
			mutated[i] = tx
		}
	}
	return &mutated
}

func mutateGetBlockHeadersPacket(mutator *fuzzing.Mutator, original *eth.GetBlockHeadersPacket, chain *eth.Chain) *eth.GetBlockHeadersPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)
	// 各字段有30%的概率进行变异
	if rand.Float32() < 1 {
		// 简单地生成一个随机区块号
		maxNumber := uint64(chain.Len() * 2) // 允许超出链长度
		mutated.Origin.Number = mutator.RandRange(0, maxNumber)
		mutated.Origin.Hash = common.Hash{} // 清空Hash，使用Number
	}
	if rand.Float32() < 1 {
		switch mutator.RandChoice(3) {
		case 0:
			// 生成一个较小的值
			mutated.Amount = mutator.RandRange(1, 100)
		case 1:
			// 生成一个较大的值
			mutated.Amount = mutator.RandRange(100, 10100)
		case 2:
			// 边界值
			mutated.Amount = mutator.RandRange(0, 2) // 0 或 1
		}
	}
	if rand.Float32() < 1 {
		switch mutator.RandChoice(3) {
		case 0:
			// 小值
			mutated.Skip = mutator.RandRange(0, 10)
		case 1:
			// 大值
			mutated.Skip = mutator.RandRange(100, 1100)
		case 2:
			// 极端值
			if mutator.Bool() {
				mutated.Skip = 0
			} else {
				mutated.Skip = mutator.MaxUint64()
			}
		}
	}
	if rand.Float32() < 1 {
		mutator.MutateReverse(&mutated.Reverse)
	}

	return &mutated
}

func mutateBlockHeadersPacket(mutator *fuzzing.Mutator, original *eth.BlockHeadersPacket, chain *eth.Chain) *eth.BlockHeadersPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// 变异随机区块头
	if rand.Float32() < 0.3 && len(mutated.BlockHeadersRequest) > 0 {
		idx := mutator.Rand(len(mutated.BlockHeadersRequest))
		mutator.MutateBlockHeader(mutated.BlockHeadersRequest[idx])
	}

	// 添加新的区块头
	if rand.Float32() < 0.3 {
		gasLimit := mutator.RandRange(0, 1000000)
		newHeader := &types.Header{
			ParentHash:  mutator.MutateHash(),
			UncleHash:   mutator.MutateHash(),
			Coinbase:    mutator.MutateAddress(),
			Root:        mutator.MutateHash(),
			TxHash:      mutator.MutateHash(),
			ReceiptHash: mutator.MutateHash(),
			Number:      new(big.Int).SetUint64(mutator.RandRange(0, 1000000)),
			GasLimit:    gasLimit,
			GasUsed:     mutator.RandRange(0, gasLimit),
			Time:        mutator.RandRange(0, 1000000),
		}
		mutated.BlockHeadersRequest = append(mutated.BlockHeadersRequest, newHeader)
	}
	// 删除随机区块头
	if rand.Float32() < 0.3 {
		if len(mutated.BlockHeadersRequest) > 1 {
			idx := mutator.Rand(len(mutated.BlockHeadersRequest))
			mutated.BlockHeadersRequest = append(
				mutated.BlockHeadersRequest[:idx],
				mutated.BlockHeadersRequest[idx+1:]...,
			)
		}
	}

	return &mutated
}

func mutateGetBlockBodiesPacket(mutator *fuzzing.Mutator, original *eth.GetBlockBodiesPacket, chain *eth.Chain) *eth.GetBlockBodiesPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)
	if rand.Float32() < 1 {
		switch mutator.RandChoice(2) {
		case 0:
			// 空列表
			*mutated.GetBlockBodiesRequest = eth.GetBlockBodiesRequest{}

		// case 1:
		// 	// 随机选择1-5个有效哈希
		// 	count := mutator.RandRange(1, 6)
		// 	hashes := make(eth.GetBlockBodiesRequest, 0, count)
		// 	blocks := chain.Blocks()
		// 	for i := uint64(0); i < count; i++ {
		// 		if len(blocks) > 0 {
		// 			idx := mutator.RandRange(0, uint64(len(blocks)))
		// 			hashes = append(hashes, blocks[idx].Hash())
		// 		}
		// 	}
		// 	*mutated.GetBlockBodiesRequest = hashes

		case 1:
			// 生成1-5个随机哈希
			count := mutator.RandRange(1, 6)
			hashes := make(eth.GetBlockBodiesRequest, 0, count)
			for i := uint64(0); i < count; i++ {
				hashes = append(hashes, mutator.MutateHash())
			}
			*mutated.GetBlockBodiesRequest = hashes
			// case 3:
			// 	// 混合有效和无效哈希
			// 	count := mutator.RandRange(1, 6)
			// 	hashes := make(eth.GetBlockBodiesRequest, 0, count)
			// 	blocks := chain.Blocks()
			// 	for i := uint64(0); i < count; i++ {
			// 		if mutator.Bool() && len(blocks) > 0 {
			// 			idx := mutator.RandRange(0, uint64(len(blocks)))
			// 			hashes = append(hashes, blocks[idx].Hash())
			// 		} else {
			// 			hashes = append(hashes, mutator.MutateHash())
			// 		}
			// 	}
			// 	*mutated.GetBlockBodiesRequest = hashes
		}
	}

	return &mutated
}

func mutateBlockBodiesPacket(mutator *fuzzing.Mutator, original *eth.BlockBodiesPacket) *eth.BlockBodiesPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}
	// 变异随机区块体
	if rand.Float32() < 0.3 && len(mutated.BlockBodiesResponse) > 0 {
		idx := mutator.RandRange(0, uint64(len(mutated.BlockBodiesResponse)))
		body := mutated.BlockBodiesResponse[idx]

		// 变异交易列表
		if mutator.Bool() && len(body.Transactions) > 0 {
			txIdx := mutator.RandRange(0, uint64(len(body.Transactions)))
			body.Transactions[txIdx] = mutator.MutateTransaction(body.Transactions[txIdx])
		}

		// 变异叔块列表
		if mutator.Bool() && len(body.Uncles) > 0 {
			uncleIdx := mutator.RandRange(0, uint64(len(body.Uncles)))
			mutator.MutateBlockHeader(body.Uncles[uncleIdx])
		}

		// 变异提款列表
		if mutator.Bool() && len(body.Withdrawals) > 0 {
			withdrawalIdx := mutator.RandRange(0, uint64(len(body.Withdrawals)))
			mutator.MutateWithdrawal(body.Withdrawals[withdrawalIdx])
		}
	}
	// 添加新的区块体
	if rand.Float32() < 0.3 {
		// 创建新的区块体
		newBody := &eth.BlockBody{
			Transactions: make([]*types.Transaction, mutator.RandRange(1, 6)), // 1-5个交易
			Uncles:       make([]*types.Header, mutator.RandRange(0, 2)),      // 0-1个叔块
			Withdrawals:  make([]*types.Withdrawal, mutator.RandRange(0, 3)),  // 0-2个提款
		}

		// 填充交易
		for i := range newBody.Transactions {
			newBody.Transactions[i] = mutator.MutateTransaction(nil)
		}

		// 填充叔块
		for i := range newBody.Uncles {
			uncle := &types.Header{}
			mutator.MutateBlockHeader(uncle)
			newBody.Uncles[i] = uncle
		}

		// 填充提款
		for i := range newBody.Withdrawals {
			withdrawal := &types.Withdrawal{}
			mutator.MutateWithdrawal(withdrawal)
			newBody.Withdrawals[i] = withdrawal
		}

		mutated.BlockBodiesResponse = append(mutated.BlockBodiesResponse, newBody)
	}
	// 删除随机区块体
	if rand.Float32() < 0.3 {
		if len(mutated.BlockBodiesResponse) > 1 {
			idx := mutator.RandRange(0, uint64(len(mutated.BlockBodiesResponse)))
			mutated.BlockBodiesResponse = append(
				mutated.BlockBodiesResponse[:idx],
				mutated.BlockBodiesResponse[idx+1:]...,
			)
		}
	}

	return &mutated
}

func mutateNewBlockPacket(mutator *fuzzing.Mutator, original *eth.NewBlockPacket) *eth.NewBlockPacket {
	mutated := *original

	// 变异区块
	if rand.Float32() < 0.5 {
		mutator.MutateNewBlock(mutated.Block)
	}

	// 变异总难度
	if rand.Float32() < 0.3 {
		mutated.TD = mutator.MutateTotalDifficulty()
	}

	return &mutated
}

func mutateNewPooledTransactionHashesPacket(mutator *fuzzing.Mutator, original *eth.NewPooledTransactionHashesPacket) *eth.NewPooledTransactionHashesPacket {
	mutated := *original

	// 变异随机交易哈希
	if rand.Float32() < 0.3 {
		if len(mutated.Hashes) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.Hashes)))
			mutated.Hashes[idx] = mutator.MutateHash()
		}
	}

	// 添加新的交易哈希
	if rand.Float32() < 0.3 {
		mutated.Hashes = append(mutated.Hashes, mutator.MutateHash())
	}

	// 删除随机交易哈希
	if rand.Float32() < 0.3 {
		if len(mutated.Hashes) > 1 {
			idx := mutator.RandRange(0, uint64(len(mutated.Hashes)))
			mutated.Hashes = append(
				mutated.Hashes[:idx],
				mutated.Hashes[idx+1:]...,
			)
		}
	}

	return &mutated
}

func mutateGetPooledTransactionsPacket(mutator *fuzzing.Mutator, original *eth.GetPooledTransactionsPacket, chain *eth.Chain) *eth.GetPooledTransactionsPacket {
	mutated := *original

	if rand.Float32() < 0.5 {
		request := *original.GetPooledTransactionsRequest

		switch mutator.RandChoice(4) {
		case 0:
			// 空列表
			request = eth.GetPooledTransactionsRequest{}

		case 1:
			// 随机选择1-5个有效哈希
			blocks := chain.Blocks() // 使用区块中的交易
			if len(blocks) == 0 {
				// 如果没有区块，生成随机哈希
				count := uint64(mutator.RandRange(1, 6))
				hashes := make(eth.GetPooledTransactionsRequest, count)
				for i := uint64(0); i < count; i++ {
					hashes[i] = mutator.MutateHash()
				}
				request = hashes
			} else {
				count := uint64(mutator.RandRange(1, 6))
				hashes := make(eth.GetPooledTransactionsRequest, count)
				for i := uint64(0); i < count; i++ {
					block := blocks[mutator.RandRange(0, uint64(len(blocks)))]
					txs := block.Transactions()
					if len(txs) > 0 {
						hashes[i] = txs[mutator.RandRange(0, uint64(len(txs)))].Hash()
					} else {
						hashes[i] = mutator.MutateHash()
					}
				}
				request = hashes
			}

		case 2:
			// 生成1-5个随机哈希
			count := uint64(mutator.RandRange(1, 6))
			hashes := make(eth.GetPooledTransactionsRequest, count)
			for i := uint64(0); i < count; i++ {
				hashes[i] = mutator.MutateHash()
			}
			request = hashes

		case 3:
			// 混合有效和无效哈希
			blocks := chain.Blocks()
			count := uint64(mutator.RandRange(1, 6))
			hashes := make(eth.GetPooledTransactionsRequest, count)
			for i := uint64(0); i < count; i++ {
				if mutator.Bool() && len(blocks) > 0 {
					block := blocks[mutator.RandRange(0, uint64(len(blocks)))]
					txs := block.Transactions()
					if len(txs) > 0 {
						hashes[i] = txs[mutator.RandRange(0, uint64(len(txs)))].Hash()
					} else {
						hashes[i] = mutator.MutateHash()
					}
				} else {
					hashes[i] = mutator.MutateHash()
				}
			}
			request = hashes
		}

		mutated.GetPooledTransactionsRequest = &request
	}

	return &mutated
}

func mutatePooledTransactionsPacket(mutator *fuzzing.Mutator, original *eth.PooledTransactionsPacket) *eth.PooledTransactionsPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// 变异随机交易
	if rand.Float32() < 0.3 {
		if len(mutated.PooledTransactionsResponse) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.PooledTransactionsResponse)))
			mutated.PooledTransactionsResponse[idx] = mutator.MutateTransaction(
				mutated.PooledTransactionsResponse[idx],
			)
		}
	}

	// 添加新的交易
	if rand.Float32() < 0.3 {
		newTx := mutator.MutateTransaction(nil)
		mutated.PooledTransactionsResponse = append(
			mutated.PooledTransactionsResponse,
			newTx,
		)
	}

	// 删除随机交易
	if rand.Float32() < 0.3 {
		if len(mutated.PooledTransactionsResponse) > 1 {
			idx := mutator.RandRange(0, uint64(len(mutated.PooledTransactionsResponse)))
			mutated.PooledTransactionsResponse = append(
				mutated.PooledTransactionsResponse[:idx],
				mutated.PooledTransactionsResponse[idx+1:]...,
			)
		}
	}

	return &mutated
}

func mutateGetReceiptsPacket(mutator *fuzzing.Mutator, original *eth.GetReceiptsPacket, chain *eth.Chain) *eth.GetReceiptsPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)

	if rand.Float32() < 1 {
		switch mutator.RandChoice(2) {
		case 0:
			// 空列表
			*mutated.GetReceiptsRequest = eth.GetReceiptsRequest{}

		// case 1:
		// 	// 随机选择1-5个有效哈希
		// 	count := mutator.RandRange(1, 6)
		// 	hashes := make(eth.GetReceiptsRequest, 0, count)
		// 	blocks := chain.Blocks()
		// 	for i := uint64(0); i < count; i++ {
		// 		if len(blocks) > 0 {
		// 			idx := mutator.RandRange(0, uint64(len(blocks)))
		// 			hashes = append(hashes, blocks[idx].Hash())
		// 		}
		// 	}
		// 	*mutated.GetReceiptsRequest = hashes

		case 1:
			// 生成1-5个随机哈希
			count := mutator.RandRange(1, 6)
			hashes := make(eth.GetReceiptsRequest, 0, count)
			for i := uint64(0); i < count; i++ {
				hashes = append(hashes, mutator.MutateHash())
			}
			*mutated.GetReceiptsRequest = hashes
			// case 3:
			// 	// 混合有效和无效哈希
			// 	count := mutator.RandRange(1, 6)
			// 	hashes := make(eth.GetReceiptsRequest, 0, count)
			// 	blocks := chain.Blocks()
			// 	for i := uint64(0); i < count; i++ {
			// 		if mutator.Bool() && len(blocks) > 0 {
			// 			idx := mutator.RandRange(0, uint64(len(blocks)))
			// 			hashes = append(hashes, blocks[idx].Hash())
			// 		} else {
			// 			hashes = append(hashes, mutator.MutateHash())
			// 		}
			// 	}
			// 	*mutated.GetReceiptsRequest = hashes
		}
	}

	return &mutated
}

func mutateReceiptsPacket(mutator *fuzzing.Mutator, original *eth.ReceiptsPacket) *eth.ReceiptsPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// 变异随机收据
	if rand.Float32() < 0.3 {
		if len(mutated.ReceiptsResponse) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.ReceiptsResponse)))
			if len(mutated.ReceiptsResponse[idx]) > 0 {
				mutator.MutateReceipt(mutated.ReceiptsResponse[idx][0])
			}
		}
	}

	// 添加新的收据
	if rand.Float32() < 0.3 {
		gasUsed := mutator.RandRange(0, 1000000)
		newReceipt := &types.Receipt{
			Status:            mutator.RandRange(0, 2),
			CumulativeGasUsed: gasUsed,
			GasUsed:           mutator.RandRange(0, gasUsed+1),
			Bloom:             types.BytesToBloom(mutator.MutateHash().Bytes()),
			TxHash:            mutator.MutateHash(),
			ContractAddress:   mutator.MutateAddress(),
		}
		mutated.ReceiptsResponse = append(
			mutated.ReceiptsResponse,
			[]*types.Receipt{newReceipt},
		)
	}

	// 删除随机收据
	if rand.Float32() < 0.3 {
		if len(mutated.ReceiptsResponse) > 1 {
			idx := mutator.RandRange(0, uint64(len(mutated.ReceiptsResponse)))
			mutated.ReceiptsResponse = append(
				mutated.ReceiptsResponse[:idx],
				mutated.ReceiptsResponse[idx+1:]...,
			)
		}
	}

	return &mutated
}
