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
	ethoptions = []int{eth.StatusMsg, eth.NewBlockHashesMsg, eth.TransactionsMsg, eth.GetBlockHeadersMsg,
		eth.BlockHeadersMsg, eth.GetBlockBodiesMsg, eth.BlockBodiesMsg, eth.NewBlockMsg,
		eth.NewPooledTransactionHashesMsg, eth.GetPooledTransactionsMsg, eth.PooledTransactionsMsg,
		eth.GetReceiptsMsg, eth.ReceiptsMsg}
	ethstate = []int{eth.StatusMsg, eth.GetReceiptsMsg}
)

type EthMaker struct {
	SuiteList []*eth.Suite

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	PakcetSeed [][]eth.Packet // Use store packet seed to mutator

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
	Error        string `json:"error"`
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
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []ethPacketTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))
	currentSeed := seed

	// 只有三个 get 消息类型需要特殊处理连接
	if seed.Kind() == eth.GetBlockHeadersMsg ||
		seed.Kind() == eth.GetBlockBodiesMsg ||
		seed.Kind() == eth.GetReceiptsMsg {
		if err := m.SuiteList[0].SetupConn(); err != nil {
			return fmt.Errorf("failed to setup connection: %v", err)
		}
		defer m.SuiteList[0].Conn().Close()
	}

	for i := 0; i < MutateCount; i++ {
		//for i := 0; i < 2; i++ {
		wg.Add(1)

		mutateSeed := cloneAndMutateEthPacket(mutator, currentSeed, m.SuiteList[0].Chain())
		//mutateSeed := seed
		go func(iteration int, currentReq eth.Packet, packetStats *UDPPacketStats) {
			defer wg.Done()

			result := ethPacketTestResult{
				PacketID:    iteration,
				RequestType: fmt.Sprintf("%d", currentReq.Kind()),
				Request:     currentReq,
			}

			result.CheckResults = m.checkRequestSemantics(currentReq, m.SuiteList[0].Chain())
			result.Check = allTrue(result.CheckResults)

			// 发送并等待响应
			resp, err, newCheck := m.handlePacketWithResponse(currentReq, m.SuiteList[0], traceOutput)
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Response = resp
				result.Success = true
				result.Check = newCheck
			}

			if result.Check && !result.Success {
				mu.Lock()
				packetStats.CheckTrueFail = packetStats.CheckTrueFail + 1
				// m.PakcetSeed = append(m.PakcetSeed, originalSeed)
				results = append(results, result)
				mu.Unlock()
			} else if !result.Check && result.Success {
				mu.Lock()
				packetStats.CheckFalsePass = packetStats.CheckFalsePass + 1
				// m.PakcetSeed = append(m.PakcetSeed, originalSeed)
				results = append(results, result)
				mu.Unlock()
			} else if result.Check && result.Success {
				mu.Lock()
				packetStats.CheckTruePass = packetStats.CheckTruePass + 1
				results = append(results, result)
				mu.Unlock()
			}

		}(i, mutateSeed, stats)
		currentSeed = mutateSeed
		time.Sleep(PacketSleepTime)
	}

	wg.Wait()

	// 分析结果
	if SaveFlag {
		analyzeResultsEth(results, logger, OutputDir)
	}

	return nil
}

// 辅助函数：打印results数组
func printResults(results []ethPacketTestResult, logger *log.Logger) {
	for i, r := range results {
		resultBytes, err := json.MarshalIndent(r, "", "    ")
		if err != nil {
			logger.Printf("Error marshaling result %d: %v", i, err)
			continue
		}
		logger.Printf("Result %d:\n%s", i, string(resultBytes))
	}
	logger.Printf("Total results: %d\n", len(results))
	logger.Printf("=====================================")
}

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

func (m *EthMaker) handleStatusPacket(p *eth.StatusPacket, suite *eth.Suite) ethPacketTestResult {
	// // 0. 先建立一个正确的连接作为对照
	// if err := suite.SetupConn(); err != nil {
	// 	return ethPacketTestResult{
	// 		Error: fmt.Errorf("failed to setup control connection: %v", err).Error(),
	// 	}
	// }
	//suite.Conn().Close()

	// 1. 建立连接
	conn, err := suite.Dial()
	if err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("dial failed: %v", err).Error(),
		}
	}
	defer conn.Close()

	// 2. 使用我们变异的状态包进行对等连接
	if err := conn.Peer(suite.Chain(), p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("peer failed: %v", err).Error(),
		}
	}

	// 3. 检查状态包的语义
	checkResults := checkStatusSemantics(p, suite.Chain())
	allPassed := true
	for _, result := range checkResults {
		if !result {
			allPassed = false
			break
		}
	}

	// 4. 发送一个 GetReceipts 包来验证连接是否真正建立
	testReq, _ := suite.GenPacket(eth.GetReceiptsMsg)
	resp, err, _ := m.handlePacketWithResponse(testReq, suite, nil)

	// 5. 根据语义检查结果和响应情况判断成功与否
	if allPassed {
		// 语义正确，应该能收到正常响应
		if err != nil {
			return ethPacketTestResult{
				Error:        fmt.Errorf("correct status but failed to get response: %v", err).Error(),
				CheckResults: checkResults,
				Check:        true,
				Success:      false,
			}
		}
	} else {
		// 语义错误，不应该收到正常响应
		if err == nil {
			return ethPacketTestResult{
				Response:     resp,
				CheckResults: checkResults,
				Check:        false,
				Success:      false,
			}
		}
	}

	return ethPacketTestResult{
		Response:     resp,
		Success:      allPassed && (err == nil),
		CheckResults: checkResults,
		Check:        true,
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

func (m *EthMaker) handleTransactionPacket(p *eth.TransactionsPacket, suite *eth.Suite) ethPacketTestResult {
	if err := suite.SendForkchoiceUpdated(); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to send forkchoice update: %v", err).Error(),
		}
	}

	for _, tx := range *p {
		if err := suite.SendTxs([]*types.Transaction{tx}); err != nil {
			return ethPacketTestResult{
				Error: fmt.Errorf("failed to send transaction: %v", err).Error(),
			}
		}
	}
	return ethPacketTestResult{}
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, suite *eth.Suite) ethPacketTestResult {
	// 修改包内容进行测试
	// p.Origin.Number = 300
	// p.Amount = 3000
	// p.Skip = 200
	// //p.Skip = 18446744073709551615
	// p.Reverse = false
	// p.Origin.Hash = common.Hash{} // 确保使用Number而不是Hash

	// 先进行语义检查
	checkResults := checkGetBlockHeadersSemantics(p, suite.Chain())

	// 记录是否通过所有检查
	checkPassed := true
	for _, passed := range checkResults {
		if !passed {
			checkPassed = false
			break
		}
	}

	// 发送请求（无论检查是否通过都发送）
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetBlockHeadersMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        false,
			Success:      false,
		}
	}

	// 读取响应
	headers := new(eth.BlockHeadersPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading BlockHeadersMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        checkPassed,
			Success:      false,
		}
	}

	// 处理检查未通过的情况
	if !checkPassed {
		// 如果是无效请求且返回空响应，这是正确的处理
		if len(headers.BlockHeadersRequest) == 0 {
			return ethPacketTestResult{
				Response:     headers,
				Success:      true,
				CheckResults: checkResults,
				Check:        true,
			}
		}
		// 如果返回了非空响应，这是错误的处理
		return ethPacketTestResult{
			Response:     headers,
			Success:      false,
			CheckResults: checkResults,
			Check:        false,
		}
	}

	// 以下是检查通过的正常处理流程
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
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error:        "header mismatch",
		}
	}

	return ethPacketTestResult{
		Response:     headers,
		Success:      true,
		CheckResults: checkResults,
		Check:        true,
	}
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, suite *eth.Suite) ethPacketTestResult {
	// 先进行语义检查
	checkResults := checkGetBlockBodiesSemantics(p, suite.Chain())

	// 记录是否通过所有检查
	checkPassed := true
	for _, passed := range checkResults {
		if !passed {
			checkPassed = false
			break
		}
	}

	// 发送请求
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetBlockBodiesMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        false,
			Success:      false,
		}
	}

	// 读取响应
	resp := new(eth.BlockBodiesPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading BlockBodiesMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        checkPassed,
			Success:      false,
		}
	}

	// 计算请求中有效哈希的数量
	blockHashes := make(map[common.Hash]bool)
	for _, block := range suite.Chain().Blocks() {
		blockHashes[block.Hash()] = true
	}
	validHashCount := 0
	for _, hash := range *p.GetBlockBodiesRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 检查响应数量是否与有效哈希数量匹配
	if len(resp.BlockBodiesResponse) != validHashCount {
		return ethPacketTestResult{
			Response:     resp,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error: fmt.Sprintf("response count mismatch: got %d, expected %d valid hashes",
				len(resp.BlockBodiesResponse), validHashCount),
		}
	}

	// 检查请求ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response:     resp,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error:        fmt.Sprintf("unexpected request id: got %d, want %d", got, want),
		}
	}

	return ethPacketTestResult{
		Response:     resp,
		Success:      true,
		CheckResults: checkResults,
		Check:        true,
	}
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

	if got, want := len(*resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
		return fmt.Errorf("unexpected number of txs requested: got %d, want %d", got, want)
	}
	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetPooledTransactionsPacket(p *eth.GetPooledTransactionsPacket, suite *eth.Suite) ethPacketTestResult {
	// 1. 发送 forkchoice updated
	if err := suite.SendForkchoiceUpdated(); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to send forkchoice update: %v", err).Error(),
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
				Error: fmt.Errorf("failed to sign transaction: %v", err).Error(),
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
			Error: fmt.Errorf("failed to send txs: %v", err).Error(),
		}
	}

	// 4. 等待交易确认
	if err := m.SuiteList[0].SetupConn(); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to setup connection: %v", err).Error(),
		}
	}
	defer m.SuiteList[0].Conn().Close()

	if err := m.SuiteList[0].Conn().Write(eth.EthProto, eth.GetPooledTransactionsMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not write to conn: %v", err).Error(),
		}
	}
	// Check that all received transactions match those that were sent to node.
	msg := new(eth.PooledTransactionsPacket)
	if err := m.SuiteList[0].Conn().ReadMsg(eth.EthProto, eth.PooledTransactionsMsg, &msg); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading from connection: %v", err).Error(),
		}
	}
	if got, want := msg.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected request id in response: got %d, want %d", got, want).Error(),
		}
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			return ethPacketTestResult{
				Error: fmt.Errorf("unexpected tx received: %v", got.Hash()).Error(),
			}
		}
	}

	return ethPacketTestResult{
		Response: msg,
		Success:  true,
	}
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, suite *eth.Suite) ethPacketTestResult {
	// 先进行语义检查
	checkResults := checkGetReceiptsSemantics(p, suite.Chain())

	// 记录是否通过所有检查
	checkPassed := true
	for _, passed := range checkResults {
		if !passed {
			checkPassed = false
			break
		}
	}

	// 发送请求
	if err := suite.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("could not send GetReceiptsMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        false,
			Success:      false,
		}
	}

	// 读取响应
	resp := new(eth.ReceiptsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return ethPacketTestResult{
			Error:        fmt.Errorf("error reading ReceiptsMsg: %v", err).Error(),
			CheckResults: checkResults,
			Check:        checkPassed,
			Success:      false,
		}
	}

	// 计算请求中有效哈希的数量
	blockHashes := make(map[common.Hash]bool)
	for _, block := range suite.Chain().Blocks() {
		blockHashes[block.Hash()] = true
	}
	validHashCount := 0
	for _, hash := range *p.GetReceiptsRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 检查响应数量是否与有效哈希数量匹配
	if len(resp.ReceiptsResponse) != validHashCount {
		return ethPacketTestResult{
			Response:     resp,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error: fmt.Sprintf("response count mismatch: got %d, expected %d valid hashes",
				len(resp.ReceiptsResponse), validHashCount),
		}
	}

	// 检查请求ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response:     resp,
			Success:      false,
			CheckResults: checkResults,
			Check:        true,
			Error:        fmt.Sprintf("unexpected request id: got %d, want %d", got, want),
		}
	}

	return ethPacketTestResult{
		Response:     resp,
		Success:      true,
		CheckResults: checkResults,
		Check:        true,
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
func (m *EthMaker) handlePacketWithResponse(req eth.Packet, suite *eth.Suite, traceOutput io.Writer) (eth.Packet, error, bool) {
	switch p := req.(type) {
	case *eth.StatusPacket:
		result := m.handleStatusPacket(p, suite)
		return result.Response, nil, result.Check
	case *eth.TransactionsPacket:
		result := m.handleTransactionPacket(p, suite)
		return result.Response, nil, result.Check
	case *eth.GetBlockHeadersPacket:
		result := m.handleGetBlockHeadersPacket(p, suite)
		return result.Response, nil, result.Check
	case *eth.GetBlockBodiesPacket:
		result := m.handleGetBlockBodiesPacket(p, suite)
		return result.Response, nil, result.Check
	case *eth.GetPooledTransactionsPacket:
		result := m.handleGetPooledTransactionsPacket(p, suite)
		return result.Response, nil, result.Check
	case *eth.GetReceiptsPacket:
		result := m.handleGetReceiptsPacket(p, suite)
		return result.Response, nil, result.Check
	default:
		err := m.handleSendOnlyPacket(p, suite, traceOutput)
		return nil, err, false
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
	case *eth.GetBlockBodiesPacket:
		results = checkGetBlockBodiesSemantics(p, chain)
	case *eth.GetReceiptsPacket:
		results = checkGetReceiptsSemantics(p, chain)
	case *eth.TransactionsPacket:
		return checkTransactionsSemantics(p)
	case *eth.GetPooledTransactionsPacket:
		// TODO: 实现GetPooledTransactions语义检查
		results = []bool{true} // 临时返回
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
	case *eth.GetBlockBodiesPacket:
		newPacket := *p
		newRequest := *p.GetBlockBodiesRequest
		newPacket.GetBlockBodiesRequest = &newRequest
		return mutateGetBlockBodiesPacket(mutator, &newPacket, chain)
	case *eth.GetPooledTransactionsPacket:
		newPacket := *p
		newRequest := *p.GetPooledTransactionsRequest
		newPacket.GetPooledTransactionsRequest = &newRequest
		return mutateGetPooledTransactionsPacket(mutator, &newPacket)
	case *eth.GetReceiptsPacket:
		newPacket := *p
		newRequest := *p.GetReceiptsRequest
		newPacket.GetReceiptsRequest = &newRequest
		return mutateGetReceiptsPacket(mutator, &newPacket, chain)
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

func mutateTransactionsPacket(mutator *fuzzing.Mutator, p *eth.TransactionsPacket) eth.Packet {
	// 决定是修改现有交易还是创建新交易
	if p == nil || len(*p) == 0 || mutator.Bool() {
		// 创建新交易
		count := mutator.Rand(5) + 1 // 1-5个交易
		newTxs := make(eth.TransactionsPacket, count)
		for i := 0; i < count; i++ {
			newTxs[i] = mutator.MutateTransaction(nil)
		}
		return &newTxs
	}

	// 修改现有交易
	mutated := make(eth.TransactionsPacket, len(*p))
	for i, tx := range *p {
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

	// 各字段有30%的概率进行变异
	if rand.Float32() < 0.3 {
		mutator.MutateOrigin(&mutated.Origin, mutated.Amount, mutated.Skip, mutated.Reverse, chain)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateAmount(&mutated.Amount, mutated.Origin.Number, mutated.Skip, mutated.Reverse, chain)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSkip(&mutated.Skip, chain)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateReverse(&mutated.Reverse)
	}

	return &mutated
}

func mutateGetBlockBodiesPacket(mutator *fuzzing.Mutator, original *eth.GetBlockBodiesPacket, chain *eth.Chain) *eth.GetBlockBodiesPacket {
	mutated := *original

	// 各字段有30%的概率进行变异
	if rand.Float32() < 0.5 {
		mutator.MutateBlockBodiesRequest(mutated.GetBlockBodiesRequest, chain)
	}

	return &mutated
}

func mutateGetPooledTransactionsPacket(mutator *fuzzing.Mutator, p *eth.GetPooledTransactionsPacket) eth.Packet {
	panic("unimplemented")
}

func mutateGetReceiptsPacket(mutator *fuzzing.Mutator, original *eth.GetReceiptsPacket, chain *eth.Chain) *eth.GetReceiptsPacket {
	mutated := *original

	// 各字段有30%的概率进行变异
	if rand.Float32() < 0.3 {
		mutator.MutateReceiptsRequest(mutated.GetReceiptsRequest, chain)
	}

	return &mutated
}
