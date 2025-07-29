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
	ethoptions   = []int{eth.GetBlockHeadersMsg, eth.GetBlockBodiesMsg, eth.GetReceiptsMsg}
	ethstate     = []int{eth.StatusMsg, eth.GetReceiptsMsg}
	elCorpusList = []*BlockCorpus{}
)

type EthMaker struct {
	SuiteList []*eth.Suite

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	PakcetSeed []eth.Packet // Use store packet seed to mutator

	Series []StateSeries
	forks  []string

	// State corpus for Generator
	BlockCorpus  *BlockCorpus
	NetworkState *NetworkState

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

	DiffCode []int // Added differential encoding field
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

// QueryStart implements connection to dynamic nodes and sends fixed packets to obtain and save node states
func (m *EthMaker) QueryStart(traceOutput io.Writer) error {
	var (
		logger *log.Logger
		wg     sync.WaitGroup
		mu     sync.Mutex
	)
	if len(m.SuiteList) == 0 {
		return fmt.Errorf("empty suite list")
	}

	if traceOutput != nil {
		logger = log.New(traceOutput, "QUERY: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	wg.Add(len(m.SuiteList))
	// fmt.Println("m.SuiteList: ", m.SuiteList)
	// for i, suite := range m.SuiteList {
	// 	jsonData, err := json.MarshalIndent(suite, "", "  ")
	// 	if err != nil {
	// 		fmt.Printf("could not marshal suite %d: %v\n", i, err)
	// 		continue
	// 	}
	// 	fmt.Printf("Suite %d details:\n%s\n", i, string(jsonData))
	// }

	for i, suite := range m.SuiteList {
		go func(nodeIndex int, nodeSuite *eth.Suite) {
			defer wg.Done()

			// Establish connection
			if err := nodeSuite.SetupConn(); err != nil {
				if logger != nil {
					logger.Printf("Node %d connection failed: %v", nodeIndex, err)
				}
				return
			}
			defer nodeSuite.Conn().Close()

			if logger != nil {
				logger.Printf("Node %d connected: %s", nodeIndex, nodeSuite.DestList.String())
			}

			packet, err := suite.GenPacket(eth.GetBlockHeadersMsg)
			if err != nil {
				if logger != nil {
					logger.Printf("Node %d failed to generate packet: %v", nodeIndex, err)
				}
				return
			}

			// Send packet and get response
			resp, _, _, err := m.handlePacketWithResponse(packet, nodeSuite)
			if err != nil {
				if logger != nil {
					logger.Printf("Node %d query failed: %v", nodeIndex, err)
				}
				return
			}

			// Process response data and convert to BlockCorpus
			if resp != nil {
				fmt.Printf("resp.(type): %T\n", resp)
				switch r := resp.(type) {
				case *eth.BlockHeadersPacket:
					// Create a BlockCorpus instance
					blockCorpus := NewBlockCorpus()
					// Add the block header in the response to BlockCorpus
					fmt.Printf("Node %d received %d headers\n", nodeIndex, len(r.BlockHeadersRequest))
					blockCorpus.AddHeaders(r.BlockHeadersRequest)
					// 只有当 blockCorpus 不为空时才添加到 elCorpusList
					if len(blockCorpus.AllHeaders()) > 0 {
						// 使用互斥锁保护对 elCorpusList 的并发访问
						mu.Lock()
						elCorpusList = append(elCorpusList, blockCorpus)
						mu.Unlock()
					} else {
						fmt.Printf("Node %d returned empty headers, skipping\n", nodeIndex)
					}
					// fmt.Println("blockCorpus.headers-len:", len(blockCorpus.headers))
					// // Format and output all properties of blockCorpus
					// fmt.Printf("=== BlockCorpus Properties ===\n")
					// fmt.Printf("Type: *BlockCorpus\n")
					// fmt.Printf("Address: %p\n", blockCorpus)

					// // Access headers map (need to lock for safe access)
					// blockCorpus.mu.RLock()
					// fmt.Printf("Headers map size: %d\n", len(blockCorpus.headers))
					// fmt.Printf("Headers map contents:\n")
					// for blockNum, header := range blockCorpus.headers {
					// 	if header != nil {
					// 		fmt.Printf("  Block %d: Hash=%s, Number=%d, ParentHash=%s, Time=%d\n",
					// 			blockNum,
					// 			header.Hash().Hex(),
					// 			header.Number.Uint64(),
					// 			header.ParentHash.Hex(),
					// 			header.Time)
					// 	} else {
					// 		fmt.Printf("  Block %d: <nil header>\n", blockNum)
					// 	}
					// }
					// blockCorpus.mu.RUnlock()

					// // Show mutex state (read-only info)
					// fmt.Printf("Mutex: sync.RWMutex (internal state not directly accessible)\n")

					// // Show all headers using the AllHeaders() method
					// allHeaders := blockCorpus.AllHeaders()
					// fmt.Printf("Total headers via AllHeaders(): %d\n", len(allHeaders))
					// for i, header := range allHeaders {
					// 	if header != nil {
					// 		fmt.Printf("  Header[%d]: Block=%d, Hash=%s\n",
					// 			i,
					// 			header.Number.Uint64(),
					// 			header.Hash().Hex())
					// 	}
					// }
					// fmt.Printf("=== End BlockCorpus Properties ===\n\n")

				default:
					fmt.Printf("Wrong response type received!\n")
				}
			} else {
				fmt.Printf("No response received (nil)\n")
			}

			if logger != nil {
				logger.Printf("Node %d query completed", nodeIndex)
			}

		}(i, suite)
	}

	// wait for all goroutines finished
	wg.Wait()

	return nil
}

func (m *EthMaker) PrintCorpus() {
	fmt.Println("PrintCorpus======Start")
	fmt.Println("elCorpusList====Len:", len(elCorpusList))
	for _, corpus := range elCorpusList {
		fmt.Println("corpus: ", corpus)
	}
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

	// Initialize results array
	for i := range results {
		results[i] = make([]ethPacketTestResult, 0)
	}

	// Special connection handling
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
		mutateSeed := cloneAndMutateEthPacket(mutator, currentSeed)

		// Create a new WaitGroup for current iteration
		var wg sync.WaitGroup
		wg.Add(len(m.SuiteList)) // Add count before starting goroutines

		for j := 0; j < len(m.SuiteList); j++ {
			go func(j int, currentReq eth.Packet, packetStats *UDPPacketStats) {
				defer wg.Done()

				result := ethPacketTestResult{
					PacketID:    i,
					RequestType: fmt.Sprintf("%d", currentReq.Kind()),
					Request:     currentReq,
				}

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

		// Wait for all goroutines in current iteration to complete
		wg.Wait()
		currentSeed = mutateSeed
		time.Sleep(PacketSleepTime)
	}

	// Analyze results
	if SaveFlag {
		for i, result := range results {
			nodeOutputDir := filepath.Join(OutputDir, fmt.Sprintf("node_%d", i))
			analyzeResultsEth(result, logger, nodeOutputDir)
		}
	}

	return nil
}

// Helper function: print results array
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
	if err := conn.Peer(p); err != nil {
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
		Success:  success,                  // Use success value returned by handlePacketWithResponse
		Valid:    testValid && resp != nil, // Need response and response must be valid
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
		Success: true, // Send successful
		Valid:   true, // Transaction accepted
	}
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, suite *eth.Suite) ethPacketTestResult {

	// Modify packet content for testing
	// p.Origin.Number = 2944
	// p.Amount = 11
	// p.Skip = 18446744073709551615
	// p.Reverse = false
	// p.Origin.Hash = common.Hash{} // 确保使用Number而不是Hash

	// Send request (send regardless of whether check passes)
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetBlockHeadersMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// Read response
	headers := new(eth.BlockHeadersPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading BlockHeadersMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// Check request ID
	if got, want := headers.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response: headers,
			Success:  false,
			Check:    true,
			Error:    fmt.Sprintf("unexpected request id: got %d, want %d", got, want),
		}
	}

	return ethPacketTestResult{
		Response: headers,
		Valid:    true,
	}
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, suite *eth.Suite) ethPacketTestResult {

	// Send request
	if err := suite.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetBlockBodiesMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// Read response
	resp := new(eth.BlockBodiesPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading BlockBodiesMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// Count valid hashes
	validHashCount := 0
	blockHashes := make(map[common.Hash]bool)

	for _, hash := range *p.GetBlockBodiesRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// Check if response count exactly matches valid hash count
	if len(resp.BlockBodiesResponse) != validHashCount {
		return ethPacketTestResult{
			Response: resp,
			Valid:    false,
			Error:    fmt.Sprintf("response count mismatch: got %d, expected %d", len(resp.BlockBodiesResponse), validHashCount),
		}
	}

	// Check request ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response: resp,
			Valid:    false,
			Error:    fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}

	// All checks passed
	return ethPacketTestResult{
		Response: resp,
		Valid:    true,
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
	// 2. Generate transactions
	var (
		txs    []*types.Transaction
		hashes []common.Hash
		set    = make(map[common.Hash]struct{})
	)

	if err := suite.SendTxs(txs); err != nil {
		return ethPacketTestResult{
			Error:   fmt.Errorf("failed to send txs: %v", err).Error(),
			Success: false,
			Valid:   false,
		}
	}

	// 4. Wait for transaction confirmation
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
			Success:  true,  // Received response but content doesn't match
			Valid:    false, // Request ID mismatch
			Error:    fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			return ethPacketTestResult{
				Request:  newRequest,
				Response: msg,
				Success:  true,  // Received response but content doesn't match
				Valid:    false, // Contains unknown transaction
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
		Success:  true, // Received response
		Valid:    true, // All checks passed
	}
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, suite *eth.Suite) ethPacketTestResult {
	// 2. Send request
	if err := suite.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("could not send GetReceiptsMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// 3. Read response
	resp := new(eth.ReceiptsPacket)
	if err := suite.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return ethPacketTestResult{
			Error: fmt.Errorf("error reading ReceiptsMsg: %v", err).Error(),
			Valid: false,
		}
	}

	// 4. Count valid hashes
	validHashCount := 0
	blockHashes := make(map[common.Hash]bool)

	for _, hash := range *p.GetReceiptsRequest {
		if blockHashes[hash] {
			validHashCount++
		}
	}

	// 5. Check if response count exactly matches valid hash count
	if len(resp.ReceiptsResponse) != validHashCount {
		return ethPacketTestResult{
			Response: resp,
			Valid:    false,
			Error:    fmt.Sprintf("response count mismatch: got %d, expected %d", len(resp.ReceiptsResponse), validHashCount),
		}
	}

	// 6. Check request ID
	if got, want := resp.RequestId, p.RequestId; got != want {
		return ethPacketTestResult{
			Response: resp,
			Valid:    false,
			Error:    fmt.Sprintf("request ID mismatch: got %d, want %d", got, want),
		}
	}

	// All checks passed
	return ethPacketTestResult{
		Response: resp,
		Valid:    true,
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

func isValidTransaction(tx *types.Transaction) bool {
	if tx == nil {
		return false
	}

	// Basic field checks
	if tx.Gas() == 0 ||
		tx.GasPrice().Sign() < 0 ||
		tx.Value().Sign() < 0 {
		return false
	}

	// Perform specific checks based on transaction type
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

// analyzeResultsEth analyzes test results and saves to file
func analyzeResultsEth(results []ethPacketTestResult, logger *log.Logger, outputDir string) error {
	// Create output directory
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

// cloneAndMutateEthPacket clones and mutates the packet
func cloneAndMutateEthPacket(mutator *fuzzing.Mutator, seed eth.Packet) eth.Packet {
	switch p := seed.(type) {
	case *eth.StatusPacket:
		// Create deep copy
		newPacket := *p
		return mutateStatusPacket(mutator, &newPacket)
	case *eth.NewBlockHashesPacket:
		newPacket := *p
		return mutateNewBlockHashesPacket(mutator, &newPacket)
	case *eth.TransactionsPacket:
		// Create deep copy
		newPacket := make(eth.TransactionsPacket, len(*p))
		copy(newPacket, *p)
		return mutateTransactionsPacket(mutator, &newPacket)
	case *eth.GetBlockHeadersPacket:
		// Create deep copy
		newPacket := *p
		newRequest := *p.GetBlockHeadersRequest
		newPacket.GetBlockHeadersRequest = &newRequest
		return mutateGetBlockHeadersPacket(mutator, &newPacket)
	case *eth.BlockHeadersPacket:
		newPacket := *p
		return mutateBlockHeadersPacket(mutator, &newPacket)
	case *eth.GetBlockBodiesPacket:
		newPacket := *p
		newRequest := *p.GetBlockBodiesRequest
		newPacket.GetBlockBodiesRequest = &newRequest
		return mutateGetBlockBodiesPacket(mutator, &newPacket)
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
		return mutateGetPooledTransactionsPacket(mutator, &newPacket)
	case *eth.PooledTransactionsPacket:
		newPacket := *p
		return mutatePooledTransactionsPacket(mutator, &newPacket)
	case *eth.GetReceiptsPacket:
		newPacket := *p
		newRequest := *p.GetReceiptsRequest
		newPacket.GetReceiptsRequest = &newRequest
		return mutateGetReceiptsPacket(mutator, &newPacket)
	case *eth.ReceiptsPacket:
		newPacket := *p
		return mutateReceiptsPacket(mutator, &newPacket)
	default:
		return seed
	}
}

func mutateStatusPacket(mutator *fuzzing.Mutator, original *eth.StatusPacket) *eth.StatusPacket {
	mutated := *original

	// Each field has 30% probability of mutation
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

	// Each field has 30% probability of mutation
	// Mutate existing elements
	if rand.Float32() < 0.3 && len(mutated) > 0 {
		idx := mutator.RandRange(0, uint64(len(mutated)))
		if mutator.Bool() {
			// Mutate hash
			mutated[idx].Hash = mutator.MutateHash()
		} else {
			// Mutate block number
			mutated[idx].Number = mutator.RandRange(0, 1000000)
		}
	}

	// Add new element
	if rand.Float32() < 0.3 {
		mutated = append(mutated, struct {
			Hash   common.Hash
			Number uint64
		}{
			Hash:   mutator.MutateHash(),
			Number: mutator.RandRange(0, 1000000),
		})
	}

	// Remove random element
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

func mutateGetBlockHeadersPacket(mutator *fuzzing.Mutator, original *eth.GetBlockHeadersPacket) *eth.GetBlockHeadersPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)
	// Each field has 30% probability of mutation
	if rand.Float32() < 1 {
		// Simply generate a random block number
		mutated.Origin.Number = mutator.RandRange(0, 999)
		mutated.Origin.Hash = common.Hash{} // Clear Hash, use Number
	}
	if rand.Float32() < 1 {
		switch mutator.RandChoice(3) {
		case 0:
			// Generate a smaller value
			mutated.Amount = mutator.RandRange(1, 100)
		case 1:
			// Generate a larger value
			mutated.Amount = mutator.RandRange(100, 10100)
		case 2:
			// Boundary value
			mutated.Amount = mutator.RandRange(0, 2) // 0 or 1
		}
	}
	if rand.Float32() < 1 {
		switch mutator.RandChoice(3) {
		case 0:
			// Small value
			mutated.Skip = mutator.RandRange(0, 10)
		case 1:
			// Large value
			mutated.Skip = mutator.RandRange(100, 1100)
		case 2:
			// Extreme value
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

func mutateBlockHeadersPacket(mutator *fuzzing.Mutator, original *eth.BlockHeadersPacket) *eth.BlockHeadersPacket {
	mutated := *original

	// Mutate request ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// Mutate random block header
	if rand.Float32() < 0.3 && len(mutated.BlockHeadersRequest) > 0 {
		idx := mutator.Rand(len(mutated.BlockHeadersRequest))
		mutator.MutateBlockHeader(mutated.BlockHeadersRequest[idx])
	}

	// Add new block header
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
	// Remove random block header
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

func mutateGetBlockBodiesPacket(mutator *fuzzing.Mutator, original *eth.GetBlockBodiesPacket) *eth.GetBlockBodiesPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)
	if rand.Float32() < 1 {
		switch mutator.RandChoice(2) {
		case 0:
			// Empty list
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
			// Generate 1-5 random hashes
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

	// Mutate request ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}
	// Mutate random block body
	if rand.Float32() < 0.3 && len(mutated.BlockBodiesResponse) > 0 {
		idx := mutator.RandRange(0, uint64(len(mutated.BlockBodiesResponse)))
		body := mutated.BlockBodiesResponse[idx]

		// Mutate transaction list
		if mutator.Bool() && len(body.Transactions) > 0 {
			txIdx := mutator.RandRange(0, uint64(len(body.Transactions)))
			body.Transactions[txIdx] = mutator.MutateTransaction(body.Transactions[txIdx])
		}

		// Mutate uncle block list
		if mutator.Bool() && len(body.Uncles) > 0 {
			uncleIdx := mutator.RandRange(0, uint64(len(body.Uncles)))
			mutator.MutateBlockHeader(body.Uncles[uncleIdx])
		}

		// Mutate withdrawal list
		if mutator.Bool() && len(body.Withdrawals) > 0 {
			withdrawalIdx := mutator.RandRange(0, uint64(len(body.Withdrawals)))
			mutator.MutateWithdrawal(body.Withdrawals[withdrawalIdx])
		}
	}
	// Add new block body
	if rand.Float32() < 0.3 {
		// Create new block body
		newBody := &eth.BlockBody{
			Transactions: make([]*types.Transaction, mutator.RandRange(1, 6)), // 1-5 transactions
			Uncles:       make([]*types.Header, mutator.RandRange(0, 2)),      // 0-1 uncle blocks
			Withdrawals:  make([]*types.Withdrawal, mutator.RandRange(0, 3)),  // 0-2 withdrawals
		}

		// Fill transactions
		for i := range newBody.Transactions {
			newBody.Transactions[i] = mutator.MutateTransaction(nil)
		}

		// Fill uncle blocks
		for i := range newBody.Uncles {
			uncle := &types.Header{}
			mutator.MutateBlockHeader(uncle)
			newBody.Uncles[i] = uncle
		}

		// Fill withdrawals
		for i := range newBody.Withdrawals {
			withdrawal := &types.Withdrawal{}
			mutator.MutateWithdrawal(withdrawal)
			newBody.Withdrawals[i] = withdrawal
		}

		mutated.BlockBodiesResponse = append(mutated.BlockBodiesResponse, newBody)
	}
	// Remove random block body
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

	// Mutate block
	if rand.Float32() < 0.5 {
		mutator.MutateNewBlock(mutated.Block)
	}

	// Mutate total difficulty
	if rand.Float32() < 0.3 {
		mutated.TD = mutator.MutateTotalDifficulty()
	}

	return &mutated
}

func mutateNewPooledTransactionHashesPacket(mutator *fuzzing.Mutator, original *eth.NewPooledTransactionHashesPacket) *eth.NewPooledTransactionHashesPacket {
	mutated := *original

	// Mutate random transaction hash
	if rand.Float32() < 0.3 {
		if len(mutated.Hashes) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.Hashes)))
			mutated.Hashes[idx] = mutator.MutateHash()
		}
	}

	// Add new transaction hash
	if rand.Float32() < 0.3 {
		mutated.Hashes = append(mutated.Hashes, mutator.MutateHash())
	}

	// Remove random transaction hash
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

func mutateGetPooledTransactionsPacket(mutator *fuzzing.Mutator, original *eth.GetPooledTransactionsPacket) *eth.GetPooledTransactionsPacket {
	mutated := *original

	if rand.Float32() < 0.5 {
		request := *original.GetPooledTransactionsRequest

		switch mutator.RandChoice(2) {
		case 0:
			// Empty list
			request = eth.GetPooledTransactionsRequest{}

		case 1:
			// Generate 1-5 random hashes
			count := uint64(mutator.RandRange(1, 6))
			hashes := make(eth.GetPooledTransactionsRequest, count)
			for i := uint64(0); i < count; i++ {
				hashes[i] = mutator.MutateHash()
			}
			request = hashes
		}

		mutated.GetPooledTransactionsRequest = &request
	}

	return &mutated
}

func mutatePooledTransactionsPacket(mutator *fuzzing.Mutator, original *eth.PooledTransactionsPacket) *eth.PooledTransactionsPacket {
	mutated := *original

	// Mutate request ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// Mutate random transaction
	if rand.Float32() < 0.3 {
		if len(mutated.PooledTransactionsResponse) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.PooledTransactionsResponse)))
			mutated.PooledTransactionsResponse[idx] = mutator.MutateTransaction(
				mutated.PooledTransactionsResponse[idx],
			)
		}
	}

	// Add new transaction
	if rand.Float32() < 0.3 {
		newTx := mutator.MutateTransaction(nil)
		mutated.PooledTransactionsResponse = append(
			mutated.PooledTransactionsResponse,
			newTx,
		)
	}

	// Remove random transaction
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

func mutateGetReceiptsPacket(mutator *fuzzing.Mutator, original *eth.GetReceiptsPacket) *eth.GetReceiptsPacket {
	mutated := *original

	mutator.MutateRequestId(&mutated.RequestId)

	if rand.Float32() < 1 {
		switch mutator.RandChoice(2) {
		case 0:
			// Empty list
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
			// Generate 1-5 random hashes
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

	// Mutate request ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.RequestId)
	}

	// Mutate random receipt
	if rand.Float32() < 0.3 {
		if len(mutated.ReceiptsResponse) > 0 {
			idx := mutator.RandRange(0, uint64(len(mutated.ReceiptsResponse)))
			if len(mutated.ReceiptsResponse[idx]) > 0 {
				mutator.MutateReceipt(mutated.ReceiptsResponse[idx][0])
			}
		}
	}

	// Add new receipt
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

	// Remove random receipt
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
