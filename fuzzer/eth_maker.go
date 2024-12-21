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

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
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
	PacketID    int
	RequestType string
	Check       bool
	Success     bool
	Request     eth.Packet
	Response    eth.Packet
	Error       string `json:"error"`
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

func (m *EthMaker) PacketStart(traceOutput io.Writer, seed eth.Packet) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []ethPacketTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// 根据不同的包类型进行处理
	switch seed.Kind() {
	case eth.StatusMsg:
		// TODO: 实现 Status 处理函数
		//return m.handleStatusOnly(seed.(*eth.StatusPacket))

	case eth.GetBlockHeadersMsg, eth.GetBlockBodiesMsg, eth.GetReceiptsMsg:
		// 这些消息类型需要建立连接并在结束时关闭
		if err := m.SuiteList[0].SetupConn(); err != nil {
			return fmt.Errorf("failed to setup connection: %v", err)
		}
		defer m.SuiteList[0].Conn().Close()

	case eth.TransactionsMsg, eth.GetPooledTransactionsMsg:
		// 这些消息类型不需要在这里建立连接
		// 连接管理由各自的处理函数负责

	default:
		// 其他消息类型的默认处理
		if err := m.SuiteList[0].SetupConn(); err != nil {
			return fmt.Errorf("failed to setup connection: %v", err)
		}
		defer m.SuiteList[0].Conn().Close()
	}

	for i := 0; i < 2; i++ {
		wg.Add(1)

		go func(iteration int, currentReq eth.Packet) {
			defer wg.Done()

			result := ethPacketTestResult{
				PacketID:    iteration,
				RequestType: fmt.Sprintf("%x", currentReq.Kind()),
				Request:     currentReq,
			}

			// 发送并等待响应
			err := func() error {
				resp, err := m.handlePacketWithResponse(currentReq, m.SuiteList[0], traceOutput)
				if err != nil {
					return err
				}
				result.Response = resp
				return nil
			}()
			if err != nil {
				result.Error = err.Error()
				result.Success = false
			} else {
				result.Success = true
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, seed)

		time.Sleep(PacketSleepTime)
	}

	wg.Wait()

	// 分析结果
	if SaveFlag {
		analyzeResultsEth(results, logger, OutputDir)
	}

	return nil
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

	if err := suite.SendMsg(eth.EthProto, eth.StatusMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send StatusMsg: %v", err).Error(),
		}
	}

	resp := new(eth.StatusPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.StatusMsg, resp); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading StatusMsg: %v", err).Error(),
		}
	}

	if resp.NetworkID != p.NetworkID {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected network ID: got %d, want %d", resp.NetworkID, p.NetworkID).Error(),
		}
	}

	if resp.Genesis != p.Genesis {
		return ethPacketTestResult{
			Error: fmt.Errorf("genesis hash mismatch: got %x, want %x", resp.Genesis, p.Genesis).Error(),
		}
	}
	return ethPacketTestResult{
		Response: resp,
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
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetBlockHeadersMsg: %v", err).Error(),
		}
	}
	headers := new(eth.BlockHeadersPacket)

	if err := suite.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading BlockHeadersMsg: %v", err).Error(),
		}
	}

	if got, want := headers.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected request id: got %d, want %d", headers.RequestId, p.RequestId).Error(),
		}
	}

	expected, err := suite.GetHeaders(p)
	if err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to get headers for given request: %v", err).Error(),
		}
	}

	if !eth.HeadersMatch(expected, headers.BlockHeadersRequest) {
		return ethPacketTestResult{
			Error: fmt.Errorf("header mismatch").Error(),
		}
	}

	return ethPacketTestResult{
		Response: headers,
	}
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, suite *eth.Suite) ethPacketTestResult {
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetBlockBodiesMsg: %v", err).Error(),
		}
	}

	resp := new(eth.BlockBodiesPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading BlockBodiesMsg: %v", err).Error(),
		}
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected request id in response: got %d, want %d", got, want).Error(),
		}
	}

	bodies := resp.BlockBodiesResponse
	if len(bodies) != len(p.GetBlockBodiesRequest) {
		return ethPacketTestResult{
			Error: fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetBlockBodiesRequest), len(bodies)).Error(),
		}
	}

	return ethPacketTestResult{
		Response: resp,
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

	if got, want := len(resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
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
	if err := suite.Conn().Write(eth.EthProto, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to write transactions: %v", err).Error(),
		}
	}

	// 4. 等待交易确认
	var (
		got = make(map[common.Hash]bool)
		end = time.Now().Add(30 * time.Second) // 30秒超时
	)

	for time.Now().Before(end) {
		msg, err := suite.Conn().ReadEth()
		if err != nil {
			return ethPacketTestResult{
				Error: fmt.Errorf("failed to read response: %v", err).Error(),
			}
		}

		switch msg := msg.(type) {
		case *eth.TransactionsPacket:
			for _, tx := range *msg {
				got[tx.Hash()] = true
			}
		case *eth.NewPooledTransactionHashesPacket68:
			for _, hash := range msg.Hashes {
				got[hash] = true
			}
		}

		// 检查是否所有交易都已确认
		allReceived := true
		for _, tx := range txs {
			if !got[tx.Hash()] {
				allReceived = false
				break
			}
		}
		if allReceived {
			break
		}
	}

	// 5. 等待一小段时间让交易进入池
	time.Sleep(100 * time.Millisecond)

	// 6. 发送 GetPooledTransactions 请求
	p.GetPooledTransactionsRequest = hashes
	if err := suite.Conn().Write(eth.EthProto, eth.GetPooledTransactionsMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to send GetPooledTransactions request: %v", err).Error(),
		}
	}

	// 7. 读取响应
	msg, err := suite.Conn().ReadEth()
	if err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("failed to read PooledTransactions response: %v", err).Error(),
		}
	}

	resp, ok := msg.(*eth.PooledTransactionsPacket)
	if !ok {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected response type: %T", msg).Error(),
		}
	}

	return ethPacketTestResult{
		Response: resp,
		Success:  true,
	}
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, suite *eth.Suite) ethPacketTestResult {

	if err := suite.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetBlockBodiesMsg: %v", err).Error(),
		}
	}

	resp := new(eth.ReceiptsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading BlockBodiesMsg: %v", err).Error(),
		}
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Error: fmt.Errorf("unexpected request id in response: got %d, want %d", got, want).Error(),
		}
	}

	bodies := resp.ReceiptsResponse
	if len(bodies) != len(p.GetReceiptsRequest) {
		return ethPacketTestResult{
			Error: fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetReceiptsRequest), len(bodies)).Error(),
		}
	}

	return ethPacketTestResult{
		Response: resp,
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
func (m *EthMaker) handlePacketWithResponse(req eth.Packet, suite *eth.Suite, traceOutput io.Writer) (eth.Packet, error) {
	switch p := req.(type) {
	case *eth.StatusPacket:
		result := m.handleStatusPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	case *eth.TransactionsPacket:
		if err := suite.SendForkchoiceUpdated(); err != nil {
			return nil, fmt.Errorf("failed to send forkchoice update: %v", err)
		}
		result := m.handleTransactionPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	case *eth.GetBlockHeadersPacket:
		result := m.handleGetBlockHeadersPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	case *eth.GetBlockBodiesPacket:
		result := m.handleGetBlockBodiesPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	case *eth.GetPooledTransactionsPacket:
		result := m.handleGetPooledTransactionsPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	case *eth.GetReceiptsPacket:
		result := m.handleGetReceiptsPacket(p, suite)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return result.Response, nil
	default:
		err := m.handleSendOnlyPacket(p, suite, traceOutput)
		return nil, err
	}
}

func analyzeResultsEth(results []ethPacketTestResult, logger *log.Logger, outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fullPath := filepath.Join(outputDir, "eth")
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create eth directory: %v", err)
	}

	filename := filepath.Join(fullPath, fmt.Sprintf("analysis_results_%s.json", time.Now().Format("2006-01-02_15-04-05")))

	// Save to file
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
