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

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/snap"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
	"github.com/AgnopraxLab/D2PFuzz/generator"
	"github.com/ethereum/go-ethereum/common"
)

var (
	snapoptions = []int{snap.GetAccountRangeMsg, snap.AccountRangeMsg, snap.GetStorageRangesMsg, snap.StorageRangesMsg,
		snap.GetByteCodesMsg, snap.ByteCodesMsg, snap.GetTrieNodesMsg, snap.TrieNodesMsg}
	snapstate = []int{snap.GetAccountRangeMsg, snap.AccountRangeMsg}
)

type SnapMaker struct {
	SuiteList []*eth.Suite

	testSeq  []int // testcase sequence
	stateSeq []int // steate sequence

	PakcetSeed []snap.Packet // Use store packet seed to mutator

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type snapPacketTestResult struct {
	PacketID     int
	RequestType  string
	Check        bool
	CheckResults []bool
	Success      bool
	Request      snap.Packet
	Response     snap.Packet
	Valid        bool
	Error        string `json:"error"`
}

func NewSnapMaker(targetDir string, chain string) *SnapMaker {
	var suiteList []*eth.Suite

	nodeList, err := getList(targetDir)
	if err != nil {
		fmt.Printf("failed to read targetDir: %v", err)
		return nil
	}

	for _, node := range nodeList {
		suite, err := generator.Initsnap(node, chain)
		if err != nil {
			fmt.Printf("failed to initialize snap clients: %v", err)
		}
		suiteList = append(suiteList, suite)
	}

	snapmaker := &SnapMaker{
		SuiteList: suiteList,
		testSeq:   generateSnapTestSeq(),
		stateSeq:  snapstate,
	}
	return snapmaker
}

func (m *SnapMaker) ToGeneralStateTest(name string) *GeneralStateTest {
	gst := make(GeneralStateTest)
	gst[name] = m.ToSubTest()
	return &gst
}

func (m *SnapMaker) ToSubTest() *stJSON {
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

func (m *SnapMaker) PacketStart(traceOutput io.Writer, seed snap.Packet, stats *UDPPacketStats) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []snapPacketTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))
	currentSeed := seed

	if err := m.SuiteList[0].SetupSnapConn(); err != nil {
		return fmt.Errorf("failed to setup connection: %v", err)
	}
	defer m.SuiteList[0].Conn().Close()

	for i := 0; i < MutateCount; i++ {
		//for i := 0; i < 2; i++ {
		wg.Add(1)

		mutateSeed := cloneAndMutateSnapPacket(mutator, currentSeed, m.SuiteList[0].Chain())
		//mutateSeed := seed
		go func(iteration int, currentReq snap.Packet, packetStats *UDPPacketStats) {
			defer wg.Done()

			result := snapPacketTestResult{
				PacketID:    iteration,
				RequestType: fmt.Sprintf("%d", currentReq.Kind()),
				Request:     currentReq,
			}

			result.CheckResults = m.checkRequestSemantics(currentReq, m.SuiteList[0].Chain())
			result.Check = allTrue(result.CheckResults)

			// 发送并等待响应
			resp, err, success, valid := m.handlePacketWithResponse(currentReq, m.SuiteList[0], logger)
			if err != nil {
				result.Error = err.Error()
				result.Success = false
				result.Valid = false
			} else {
				result.Response = resp
				result.Success = success
				result.Valid = valid
			}

			if result.Check { // 语义检查正确
				if !result.Success { // 没有收到响应
					mu.Lock()
					packetStats.CheckTrueFail = packetStats.CheckTrueFail + 1
					results = append(results, result)
					mu.Unlock()
				} else if result.Valid { // 收到有效响应
					mu.Lock()
					packetStats.CheckTruePass = packetStats.CheckTruePass + 1
					results = append(results, result)
					mu.Unlock()
				}
			} else { // 语义检查错误
				if result.Success { // 收到响应
					if result.Valid { // 响应有效
						mu.Lock()
						packetStats.CheckFalsePassOK = packetStats.CheckFalsePassOK + 1
						results = append(results, result)
						mu.Unlock()
					} else { // 响应无效
						mu.Lock()
						packetStats.CheckFalsePassBad = packetStats.CheckFalsePassBad + 1
						results = append(results, result)
						mu.Unlock()
					}
				}
			}

		}(i, mutateSeed, stats)
		currentSeed = mutateSeed
		time.Sleep(PacketSleepTime)
	}

	wg.Wait()

	// 分析结果
	if SaveFlag {
		analyzeResultsSnap(results, logger, OutputDir)
	}

	return nil
}

func (m *SnapMaker) Start(traceOutput io.Writer) error {
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
				req, _ := target.GenSnapPacket(packetType)
				m.handlePacket(req, target, logger)
				logger.Printf("Sent test packet to target: %s, packet: %v, using suite: %d", target.DestList.String(), req.Kind(), i)
			}
			// Round 2: sending stateSeq packets
			for i, packetType := range m.stateSeq {
				req, _ := target.GenSnapPacket(packetType)
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

func (m *SnapMaker) handlePacket(req snap.Packet, suite *eth.Suite, logger *log.Logger) error {
	switch p := req.(type) {
	case *snap.GetAccountRangePacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetAccountRangePacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get account range packet: %v", result.Error)
		}
		return nil

	case *snap.AccountRangePacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleAccountRangePacket(p, suite, logger)

	case *snap.GetStorageRangesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetStorageRangesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get storage ranges packet: %v", result.Error)
		}
		return nil

	case *snap.StorageRangesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleStorageRangesPacket(p, suite, logger)

	case *snap.GetByteCodesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetByteCodesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get bytecodes packet: %v", result.Error)
		}
		return nil

	case *snap.ByteCodesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleByteCodesPacket(p, suite, logger)

	case *snap.GetTrieNodesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		result := m.handleGetTrieNodesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle get trie nodes packet: %v", result.Error)
		}
		return nil

	case *snap.TrieNodesPacket:
		if err := suite.SnapInitializeAndConnect(); err != nil {
			return fmt.Errorf("initialization and connection failed: %v", err)
		}
		return m.handleTrieNodesPacket(p, suite, logger)

	default:
		if logger != nil {
			_, err := fmt.Printf("Unsupported snap packet type: %T\n", req)
			if err != nil {
				log.Printf("Error writing to trace output: %v", err)
			}
		}
		return nil
	}
}

// 处理 GetAccountRange 请求
func (m *SnapMaker) handleGetAccountRangePacket(p *snap.GetAccountRangePacket, suite *eth.Suite) *snapPacketTestResult {
	// TODO: 实现具体逻辑
	return &snapPacketTestResult{}
}

// 处理 AccountRange 响应
func (m *SnapMaker) handleAccountRangePacket(p *snap.AccountRangePacket, suite *eth.Suite, logger *log.Logger) error {
	// TODO: 实现具体逻辑
	return nil
}

// 处理 GetStorageRanges 请求
func (m *SnapMaker) handleGetStorageRangesPacket(p *snap.GetStorageRangesPacket, suite *eth.Suite) *snapPacketTestResult {
	// TODO: 实现具体逻辑
	return &snapPacketTestResult{}
}

// 处理 StorageRanges 响应
func (m *SnapMaker) handleStorageRangesPacket(p *snap.StorageRangesPacket, suite *eth.Suite, logger *log.Logger) error {
	// TODO: 实现具体逻辑
	return nil
}

// 处理 GetByteCodes 请求
func (m *SnapMaker) handleGetByteCodesPacket(p *snap.GetByteCodesPacket, suite *eth.Suite) *snapPacketTestResult {
	// TODO: 实现具体逻辑
	return &snapPacketTestResult{}
}

// 处理 ByteCodes 响应
func (m *SnapMaker) handleByteCodesPacket(p *snap.ByteCodesPacket, suite *eth.Suite, logger *log.Logger) error {
	// TODO: 实现具体逻辑
	return nil
}

// 处理 GetTrieNodes 请求
func (m *SnapMaker) handleGetTrieNodesPacket(p *snap.GetTrieNodesPacket, suite *eth.Suite) *snapPacketTestResult {
	// TODO: 实现具体逻辑
	return &snapPacketTestResult{}
}

// 处理 TrieNodes 响应
func (m *SnapMaker) handleTrieNodesPacket(p *snap.TrieNodesPacket, suite *eth.Suite, logger *log.Logger) error {
	// TODO: 实现具体逻辑
	return nil
}

func generateSnapTestSeq() []int {
	options := []int{
		snap.GetAccountRangeMsg, snap.AccountRangeMsg, snap.GetStorageRangesMsg, snap.StorageRangesMsg,
		snap.GetByteCodesMsg, snap.ByteCodesMsg, snap.GetTrieNodesMsg, snap.TrieNodesMsg,
	}
	seq := make([]int, SequenceLength)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}

// packet test deal data
func (m *SnapMaker) handlePacketWithResponse(req snap.Packet, suite *eth.Suite, logger *log.Logger) (snap.Packet, error, bool, bool) {
	switch p := req.(type) {
	case *snap.GetAccountRangePacket:
		result := m.handleGetAccountRangePacket(p, suite)
		return result.Response, nil, result.Success, result.Valid
	case *snap.GetStorageRangesPacket:
		result := m.handleGetStorageRangesPacket(p, suite)
		return result.Response, nil, true, result.Valid
	case *snap.GetByteCodesPacket:
		result := m.handleGetByteCodesPacket(p, suite)
		return result.Response, nil, true, result.Valid
	case *snap.GetTrieNodesPacket:
		result := m.handleGetTrieNodesPacket(p, suite)
		return result.Response, nil, true, result.Valid
	default:
		return nil, nil, false, false
	}
}

// checkRequestSemantics 检查请求的语义正确性
func (m *SnapMaker) checkRequestSemantics(req snap.Packet, chain *eth.Chain) []bool {
	var results []bool

	switch p := req.(type) {
	case *snap.GetAccountRangePacket:
		results = checkGetAccountRangeSemantics(p, chain)
	case *snap.GetStorageRangesPacket:
		results = checkGetStorageRangesSemantics(p, chain)
	case *snap.GetByteCodesPacket:
		results = checkGetByteCodesSemantics(p, chain)
	case *snap.GetTrieNodesPacket:
		results = checkGetTrieNodesSemantics(p, chain)
	default:
		// 对于响应类型的包，返回true
		results = []bool{true}
	}

	return results
}

// 检查 GetAccountRange 请求的语义
func checkGetAccountRangeSemantics(p *snap.GetAccountRangePacket, chain *eth.Chain) []bool {
	// TODO: 实现语义检查
	// 1. 检查 Root 是否有效
	// 2. 检查 Origin 和 Limit 是否合法
	// 3. 检查 Bytes 是否在合理范围内
	return []bool{true}
}

// 检查 GetStorageRanges 请求的语义
func checkGetStorageRangesSemantics(p *snap.GetStorageRangesPacket, chain *eth.Chain) []bool {
	// TODO: 实现语义检查
	// 1. 检查 Root 是否有效
	// 2. 检查 Accounts 是否存在
	// 3. 检查 Origin 和 Limit 是否合法
	// 4. 检查 Bytes 是否在合理范围内
	return []bool{true}
}

// 检查 GetByteCodes 请求的语义
func checkGetByteCodesSemantics(p *snap.GetByteCodesPacket, chain *eth.Chain) []bool {
	// TODO: 实现语义检查
	// 1. 检查 Hashes 是否有效
	// 2. 检查 Bytes 是否在合理范围内
	return []bool{true}
}

// 检查 GetTrieNodes 请求的语义
func checkGetTrieNodesSemantics(p *snap.GetTrieNodesPacket, chain *eth.Chain) []bool {
	// TODO: 实现语义检查
	// 1. 检查 Root 是否有效
	// 2. 检查 Paths 是否合法
	// 3. 检查 Bytes 是否在合理范围内
	return []bool{true}
}

// analyzeResultsEth 分析测试结果并保存到文件
func analyzeResultsSnap(results []snapPacketTestResult, logger *log.Logger, outputDir string) error {
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

// cloneAndMutateSnapPacket clones and mutates the packet
func cloneAndMutateSnapPacket(mutator *fuzzing.Mutator, seed snap.Packet, chain *eth.Chain) snap.Packet {
	switch p := seed.(type) {
	case *snap.GetAccountRangePacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetAccountRangePacket(mutator, &newPacket, chain)

	case *snap.GetStorageRangesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetStorageRangesPacket(mutator, &newPacket, chain)

	case *snap.GetByteCodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetByteCodesPacket(mutator, &newPacket, chain)

	case *snap.GetTrieNodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetTrieNodesPacket(mutator, &newPacket, chain)

	default:
		return seed
	}
}

// mutateGetAccountRangePacket 变异 GetAccountRange 请求包
func mutateGetAccountRangePacket(mutator *fuzzing.Mutator, p *snap.GetAccountRangePacket, chain *eth.Chain) snap.Packet {
	// TODO: 实现变异逻辑
	// 1. 变异 Root
	// 2. 变异 Origin 和 Limit
	// 3. 变异 Bytes
	return p
}

// mutateGetStorageRangesPacket 变异 GetStorageRanges 请求包
func mutateGetStorageRangesPacket(mutator *fuzzing.Mutator, p *snap.GetStorageRangesPacket, chain *eth.Chain) snap.Packet {
	// TODO: 实现变异逻辑
	// 1. 变异 Root
	// 2. 变异 Accounts
	// 3. 变异 Origin 和 Limit
	// 4. 变异 Bytes
	return p
}

// mutateGetByteCodesPacket 变异 GetByteCodes 请求包
func mutateGetByteCodesPacket(mutator *fuzzing.Mutator, p *snap.GetByteCodesPacket, chain *eth.Chain) snap.Packet {
	// TODO: 实现变异逻辑
	// 1. 变异 Hashes
	// 2. 变异 Bytes
	return p
}

// mutateGetTrieNodesPacket 变异 GetTrieNodes 请求包
func mutateGetTrieNodesPacket(mutator *fuzzing.Mutator, p *snap.GetTrieNodesPacket, chain *eth.Chain) snap.Packet {
	// TODO: 实现变异逻辑
	// 1. 变异 Root
	// 2. 变异 Paths
	// 3. 变异 Bytes
	return p
}
