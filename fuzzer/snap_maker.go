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
	"bytes"
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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie/trienode"
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

	DiffCode []int // 新增差分编码字段
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
		wg     sync.WaitGroup
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
	results := make([][]snapPacketTestResult, len(m.SuiteList))
	currentSeed := seed

	for i := 0; i < len(m.SuiteList); i++ {
		if err := m.SuiteList[i].SetupSnapConn(); err != nil {
			return fmt.Errorf("failed to setup connection: %v", err)
		}
		defer m.SuiteList[i].Conn().Close()
		results[i] = make([]snapPacketTestResult, 0)
	}

	for i := 1; i <= MutateCount; i++ {
		wg.Add(1)
		fmt.Printf("Start Mutate count: %d\n", i)

		mutateSeed := cloneAndMutateSnapPacket(mutator, currentSeed)
		//mutateSeed := seed
		for j := 0; j < len(m.SuiteList); j++ {
			go func(currentReq snap.Packet, packetStats *UDPPacketStats) {
				defer wg.Done()

				result := snapPacketTestResult{
					PacketID:    i,
					RequestType: fmt.Sprintf("%d", currentReq.Kind()),
					Request:     currentReq,
				}

				// 发送并等待响应
				resp, err, success, valid := m.handlePacketWithResponse(currentReq, m.SuiteList[j])
				if err != "" {
					result.Error = err
					result.Success = false
					result.Valid = false
				} else {
					result.Response = resp
					result.Success = success
					result.Valid = valid
				}

				// different testing for clients
				result.DiffCode = snapRespToInts(resp)

				fmt.Printf("Client: %d, DiffCodeState: %v\n", j, result.DiffCode)

				if result.Check { // 语义检查正确
					if !result.Success { // 没有收到响应
						mu.Lock()
						packetStats.CheckTrueFail = packetStats.CheckTrueFail + 1
						results[j] = append(results[j], result)
						mu.Unlock()
					} else if result.Valid { // 收到有效响应
						mu.Lock()
						packetStats.CheckTruePass = packetStats.CheckTruePass + 1
						results[j] = append(results[j], result)
						mu.Unlock()
					}
				} else { // 语义检查错误
					if result.Success { // 收到响应
						if result.Valid { // 响应有效
							mu.Lock()
							packetStats.CheckFalsePassOK = packetStats.CheckFalsePassOK + 1
							results[j] = append(results[j], result)
							mu.Unlock()
						} else { // 响应无效
							mu.Lock()
							packetStats.CheckFalsePassBad = packetStats.CheckFalsePassBad + 1
							results[j] = append(results[j], result)
							mu.Unlock()
						}
					}
				}

			}(mutateSeed, stats)
		}
		currentSeed = mutateSeed
		time.Sleep(PacketSleepTime)
	}

	wg.Wait()

	// 分析结果
	if SaveFlag {
		for i, result := range results {
			nodeOutputDir := filepath.Join(OutputDir, fmt.Sprintf("node_%d", i))
			analyzeResultsSnap(result, logger, nodeOutputDir)
		}
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
		result := m.handleAccountRangePacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle account range packet: %v", result.Error)
		}
		return nil

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
		result := m.handleStorageRangesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle storage ranges packet: %v", result.Error)
		}
		return nil

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
		result := m.handleByteCodesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle bytecodes packet: %v", result.Error)
		}
		return nil

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
		result := m.handleTrieNodesPacket(p, suite)
		if result.Error != "" {
			return fmt.Errorf("failed to handle trie nodes packet: %v", result.Error)
		}
		return nil

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

	msg, err := suite.SnapRequest(snap.GetAccountRangeMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Response: nil,
			Error:    err.Error(),
			Success:  false,
			Valid:    false,
		}
	}
	res, ok := msg.(*snap.AccountRangePacket)
	if !ok {
		return &snapPacketTestResult{
			Response: res,
			Error:    fmt.Sprintf("account range response wrong: %T %v", msg, msg),
			Success:  true,
			Valid:    false,
		}
	}
	// Check that the encoding order is correct
	for i := 1; i < len(res.Accounts); i++ {
		if bytes.Compare(res.Accounts[i-1].Hash[:], res.Accounts[i].Hash[:]) >= 0 {
			return &snapPacketTestResult{
				Response: res,
				Error:    fmt.Sprintf("accounts not monotonically increasing: #%d [%x] vs #%d [%x]", i-1, res.Accounts[i-1].Hash[:], i, res.Accounts[i].Hash[:]),
				Success:  true,
				Valid:    false,
			}
		}
	}
	var (
		hashes   []common.Hash
		accounts [][]byte
		proof    = res.Proof
	)
	hashes, accounts, err = res.Unpack()
	if err != nil {
		return &snapPacketTestResult{
			Response: res,
			Error:    err.Error(),
			Success:  true,
			Valid:    false,
		}
	}
	if len(hashes) == 0 && len(accounts) == 0 && len(proof) == 0 {
		return &snapPacketTestResult{
			Response: res,
			Success:  true,
			Valid:    true,
		}
	}
	// Reconstruct a partial trie from the response and verify it
	keys := make([][]byte, len(hashes))
	for i, key := range hashes {
		keys[i] = common.CopyBytes(key[:])
	}
	nodes := make(trienode.ProofList, len(proof))
	for i, node := range proof {
		nodes[i] = node
	}
	if err != nil {
		return &snapPacketTestResult{
			Response: res,
			Error:    err.Error(),
			Success:  true,
			Valid:    false,
		}
	}

	return &snapPacketTestResult{
		Response: res,
		Success:  true,
		Valid:    true,
	}
}

// 处理 AccountRange 响应
func (m *SnapMaker) handleAccountRangePacket(p *snap.AccountRangePacket, suite *eth.Suite) *snapPacketTestResult {
	_, err := suite.SnapRequest(snap.AccountRangeMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("account range request failed: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	return &snapPacketTestResult{
		Response: nil,
		Success:  true,
		Valid:    true,
	}
}

// 处理 GetStorageRanges 请求
func (m *SnapMaker) handleGetStorageRangesPacket(p *snap.GetStorageRangesPacket, suite *eth.Suite) *snapPacketTestResult {
	msg, err := suite.SnapRequest(snap.GetStorageRangesMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("account range request failed: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	res, ok := msg.(*snap.StorageRangesPacket)
	if !ok {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("account range response wrong: %T %v", msg, msg),
			Success: false,
			Valid:   false,
		}
	}

	// Ensure the ranges are monotonically increasing
	for i, slots := range res.Slots {
		for j := 1; j < len(slots); j++ {
			if bytes.Compare(slots[j-1].Hash[:], slots[j].Hash[:]) >= 0 {
				return &snapPacketTestResult{
					Error:   fmt.Sprintf("storage slots not monotonically increasing for account #%d: #%d [%x] vs #%d [%x]", i, j-1, slots[j-1].Hash[:], j, slots[j].Hash[:]),
					Success: false,
					Valid:   false,
				}
			}
		}
	}
	return &snapPacketTestResult{
		Response: res,
		Success:  true,
		Valid:    true,
	}
}

// 处理 StorageRanges 响应
func (m *SnapMaker) handleStorageRangesPacket(p *snap.StorageRangesPacket, suite *eth.Suite) *snapPacketTestResult {
	_, err := suite.SnapRequest(snap.StorageRangesMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("failed to handle account range packet: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	return &snapPacketTestResult{
		Response: nil,
		Success:  true,
		Valid:    true,
	}
}

// 处理 GetByteCodes 请求
func (m *SnapMaker) handleGetByteCodesPacket(p *snap.GetByteCodesPacket, suite *eth.Suite) *snapPacketTestResult {
	msg, err := suite.SnapRequest(snap.GetByteCodesMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("getBytecodes request failed: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	res, ok := msg.(*snap.ByteCodesPacket)
	if !ok {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("bytecodes response wrong: %T %v", msg, msg),
			Success: false,
			Valid:   false,
		}
	}
	if exp, got := len(p.Hashes), len(res.Codes); exp != got {
		for i, c := range res.Codes {
			fmt.Printf("%d. %#x\n", i, c)
		}
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("expected %d bytecodes, got %d", exp, got),
			Success: false,
			Valid:   false,
		}
	}
	// Cross reference the requested bytecodes with the response to find gaps
	// that the serving node is missing
	var (
		bytecodes = res.Codes
		hasher    = crypto.NewKeccakState()
		hash      = make([]byte, 32)
		codes     = make([][]byte, len(p.Hashes))
	)

	for i, j := 0, 0; i < len(bytecodes); i++ {
		// Find the next hash that we've been served, leaving misses with nils
		hasher.Reset()
		hasher.Write(bytecodes[i])
		hasher.Read(hash)

		for j < len(p.Hashes) && !bytes.Equal(hash, p.Hashes[j][:]) {
			j++
		}
		if j < len(p.Hashes) {
			codes[j] = bytecodes[i]
			j++
			continue
		}
		// We've either ran out of hashes, or got unrequested data
		return &snapPacketTestResult{
			Error:   "unexpected bytecode",
			Success: false,
			Valid:   false,
		}
	}

	return &snapPacketTestResult{
		Response: res,
		Success:  true,
		Valid:    true,
	}
}

// 处理 ByteCodes 响应
func (m *SnapMaker) handleByteCodesPacket(p *snap.ByteCodesPacket, suite *eth.Suite) *snapPacketTestResult {
	_, err := suite.SnapRequest(snap.ByteCodesMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("failed to handle bytecodes packet: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	return &snapPacketTestResult{
		Response: nil,
		Success:  true,
		Valid:    true,
	}
}

// 处理 GetTrieNodes 请求
func (m *SnapMaker) handleGetTrieNodesPacket(p *snap.GetTrieNodesPacket, suite *eth.Suite) *snapPacketTestResult {
	msg, err := suite.SnapRequest(snap.GetTrieNodesMsg, p)
	if err != nil {
		fmt.Printf("Debug - GetTrieNodes - Request failed: %v\n", err)
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("trienodes request failed: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	res, ok := msg.(*snap.TrieNodesPacket)
	if !ok {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("trienodes response wrong: %T %v", msg, msg),
			Success: false,
			Valid:   false,
		}
	}

	// Check the correctness

	// Cross reference the requested trienodes with the response to find gaps
	// that the serving node is missing
	// hasher := crypto.NewKeccakState()
	// hash := make([]byte, 32)
	// trienodes := res.Nodes

	// if got, want := len(trienodes), len(p.Paths); got != want {
	// 	return &snapPacketTestResult{
	// 		Error:   fmt.Sprintf("wrong trienode count, got %d, want %d", got, want),
	// 		Success: false,
	// 		Valid:   false,
	// 	}
	// }
	// for i, trienode := range trienodes {
	// 	hasher.Reset()
	// 	hasher.Write(trienode)
	// 	hasher.Read(hash)
	// 	if got, want := hash, p.Paths[i][0]; !bytes.Equal(got, want) {
	// 		return &snapPacketTestResult{
	// 			Error:   fmt.Sprintf("hash %d wrong, got %#x, want %#x", i, got, want),
	// 			Success: false,
	// 			Valid:   false,
	// 		}
	// 	}
	// }
	return &snapPacketTestResult{
		Response: res,
		Success:  true,
		Valid:    true,
	}
}

// 处理 TrieNodes 响应
func (m *SnapMaker) handleTrieNodesPacket(p *snap.TrieNodesPacket, suite *eth.Suite) *snapPacketTestResult {
	_, err := suite.SnapRequest(snap.TrieNodesMsg, p)
	if err != nil {
		return &snapPacketTestResult{
			Error:   fmt.Sprintf("failed to handle trie nodes packet: %v", err),
			Success: false,
			Valid:   false,
		}
	}
	return &snapPacketTestResult{
		Response: nil,
		Success:  true,
		Valid:    true,
	}
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
func (m *SnapMaker) handlePacketWithResponse(req snap.Packet, suite *eth.Suite) (snap.Packet, string, bool, bool) {

	switch p := req.(type) {
	case *snap.GetAccountRangePacket:
		result := m.handleGetAccountRangePacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.AccountRangePacket:
		result := m.handleAccountRangePacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.GetStorageRangesPacket:
		result := m.handleGetStorageRangesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.StorageRangesPacket:
		result := m.handleStorageRangesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.GetByteCodesPacket:
		result := m.handleGetByteCodesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.ByteCodesPacket:
		result := m.handleByteCodesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.GetTrieNodesPacket:
		result := m.handleGetTrieNodesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	case *snap.TrieNodesPacket:
		result := m.handleTrieNodesPacket(p, suite)
		return result.Response, result.Error, result.Success, result.Valid
	default:
		return nil, "", false, false
	}
}

// analyzeResultsEth 分析测试结果并保存到文件
func analyzeResultsSnap(results []snapPacketTestResult, logger *log.Logger, outputDir string) error {
	// 创建输出目录
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fullPath := filepath.Join(outputDir, "snap")
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create snap directory: %v", err)
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
func cloneAndMutateSnapPacket(mutator *fuzzing.Mutator, seed snap.Packet) snap.Packet {
	switch p := seed.(type) {
	case *snap.GetAccountRangePacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetAccountRangePacket(mutator, &newPacket)

	case *snap.AccountRangePacket:
		// 创建深拷贝
		newPacket := *p
		return mutateAccountRangePacket(mutator, &newPacket)

	case *snap.GetStorageRangesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetStorageRangesPacket(mutator, &newPacket)

	case *snap.StorageRangesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateStorageRangesPacket(mutator, &newPacket)

	case *snap.GetByteCodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetByteCodesPacket(mutator, &newPacket)

	case *snap.ByteCodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateByteCodesPacket(mutator, &newPacket)

	case *snap.GetTrieNodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateGetTrieNodesPacket(mutator, &newPacket)
	case *snap.TrieNodesPacket:
		// 创建深拷贝
		newPacket := *p
		return mutateTrieNodesPacket(mutator, &newPacket)

	default:
		return seed
	}
}

// mutateGetAccountRangePacket 变异 GetAccountRange 请求包
func mutateGetAccountRangePacket(mutator *fuzzing.Mutator, original *snap.GetAccountRangePacket) *snap.GetAccountRangePacket {
	if mutator == nil || original == nil {
		return original
	}

	mutated := *original

	// // 变异 Root 时增加错误处理
	// if rand.Float32() < 0.3 {
	// 	oldRoot := mutated.Root // 保存原始值
	// 	mutator.MutateSnapRoot(&mutated.Root, chain)

	// 	// 如果变异后的 Root 无效，回退到原始值
	// 	if (mutated.Root == common.Hash{}) {
	// 		mutated.Root = oldRoot
	// 	}
	// }

	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapOriginAndLimit(&mutated.Origin, &mutated.Limit)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapBytes(&mutated.Bytes)
	}

	return &mutated
}

func mutateAccountRangePacket(mutator *fuzzing.Mutator, original *snap.AccountRangePacket) *snap.AccountRangePacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}

	// 变异随机账户数据
	if rand.Float32() < 0.3 && len(mutated.Accounts) > 0 {
		idx := rand.Intn(len(mutated.Accounts))
		account := mutated.Accounts[idx]

		if mutator.Bool() {
			account.Hash = mutator.MutateHash()
		}
		if mutator.Bool() {
			account.Body = mutator.MutateRawValue()
		}
		account = mutated.Accounts[idx]

		if mutator.Bool() {
			account.Hash = mutator.MutateHash()
		}
		if mutator.Bool() {
			account.Body = mutator.MutateRawValue()
		}
	}

	// 添加新的账户数据
	if rand.Float32() < 0.3 {
		newAccount := &snap.AccountData{
			Hash: mutator.MutateHash(),
			Body: mutator.MutateRawValue(),
		}
		mutated.Accounts = append(mutated.Accounts, newAccount)
		newAccount = &snap.AccountData{
			Hash: mutator.MutateHash(),
			Body: mutator.MutateRawValue(),
		}
		mutated.Accounts = append(mutated.Accounts, newAccount)
	}

	// 删除随机账户数据
	if rand.Float32() < 0.3 {
		if len(mutated.Accounts) > 1 {
			idx := mutator.RandRange(0, uint64(len(mutated.Accounts)))
			mutated.Accounts = append(
				mutated.Accounts[:idx],
				mutated.Accounts[idx+1:]...,
			)
		}
	}
	// 变异证明数据
	if rand.Float32() < 0.3 {
		mutator.MutateAccountProof(&mutated.Proof)
	}

	return &mutated
}

// mutateGetStorageRangesPacket 变异 GetStorageRanges 请求包
func mutateGetStorageRangesPacket(mutator *fuzzing.Mutator, original *snap.GetStorageRangesPacket) *snap.GetStorageRangesPacket {
	mutated := *original

	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapStorageRangeOriginAndLimit(&mutated.Origin, &mutated.Limit)
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapBytes(&mutated.Bytes)
	}
	if rand.Float32() < 0.3 {
		mutated.Accounts = mutator.MutateSnapAccounts()
	}

	return &mutated
}

func mutateStorageRangesPacket(mutator *fuzzing.Mutator, original *snap.StorageRangesPacket) *snap.StorageRangesPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}

	// 变异随机存储槽
	if rand.Float32() < 0.3 {
		if len(mutated.Slots) > 0 {
			accountIdx := mutator.RandRange(0, uint64(len(mutated.Slots)))
			if len(mutated.Slots[accountIdx]) > 0 {
				slotIdx := mutator.RandRange(0, uint64(len(mutated.Slots[accountIdx])))
				storage := mutated.Slots[accountIdx][slotIdx]

				if mutator.Bool() {
					storage.Hash = mutator.MutateHash()
				}
				if mutator.Bool() {
					mutator.MutateBytes(&storage.Body)
				}
			}
		}
	}

	// 添加新的存储槽
	if rand.Float32() < 0.3 {
		if len(mutated.Slots) > 0 {
			accountIdx := mutator.RandRange(0, uint64(len(mutated.Slots)))
			newSlot := &snap.StorageData{
				Hash: mutator.MutateHash(),
				Body: mutator.MutateRawValue(),
			}
			mutated.Slots[accountIdx] = append(
				mutated.Slots[accountIdx],
				newSlot,
			)
		}
	}

	// 删除随机存储槽
	if rand.Float32() < 0.3 {
		if len(mutated.Slots) > 0 {
			accountIdx := mutator.RandRange(0, uint64(len(mutated.Slots)))
			if len(mutated.Slots[accountIdx]) > 1 {
				slotIdx := mutator.RandRange(0, uint64(len(mutated.Slots[accountIdx])))
				mutated.Slots[accountIdx] = append(
					mutated.Slots[accountIdx][:slotIdx],
					mutated.Slots[accountIdx][slotIdx+1:]...,
				)
			}
		}
	}

	// 变异证明数据
	if rand.Float32() < 0.3 {
		mutator.MutateAccountProof(&mutated.Proof)
	}

	return &mutated
}

// mutateGetByteCodesPacket 变异 GetByteCodes 请求包
func mutateGetByteCodesPacket(mutator *fuzzing.Mutator, original *snap.GetByteCodesPacket) *snap.GetByteCodesPacket {
	mutated := *original

	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}
	if rand.Float32() < 0.3 {
		mutated.Hashes = mutator.MutateSnapHashes()
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapBytes(&mutated.Bytes)
	}

	return &mutated
}

func mutateByteCodesPacket(mutator *fuzzing.Mutator, original *snap.ByteCodesPacket) *snap.ByteCodesPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}

	// 变异随机字节码
	if rand.Float32() < 0.3 {
		mutator.MutateByteCodesResponse(&mutated.Codes)
	}

	// 添加新的字节码
	if rand.Float32() < 0.3 {
		mutator.AddByteCode(&mutated.Codes)
	}

	// 删除随机字节码
	if rand.Float32() < 0.3 {
		mutator.RemoveByteCode(&mutated.Codes)
	}

	return &mutated
}

// mutateGetTrieNodesPacket 变异 GetTrieNodes 请求包
func mutateGetTrieNodesPacket(mutator *fuzzing.Mutator, original *snap.GetTrieNodesPacket) *snap.GetTrieNodesPacket {
	mutated := *original

	if rand.Float32() < 0.3 {
		mutator.MutateSnapRequestId(&mutated.ID)
	}
	if rand.Float32() < 0.3 {
		// 控制路径集合的数量在合理范围内 (1-32)
		pathSetCount := mutator.RandRange(1, 33)
		paths := make([]snap.TrieNodePathSet, pathSetCount)

		for i := uint64(0); i < pathSetCount; i++ {
			// 每个路径集合包含 1-4 个路径
			pathCount := mutator.RandRange(1, 5)
			paths[i] = make([][]byte, pathCount)
			for j := uint64(0); j < pathCount; j++ {
				// 每个路径的长度在 1-64 字节之间
				pathLen := mutator.RandRange(1, 65)
				path := make([]byte, pathLen)
				mutator.FillBytes(&path)
				paths[i][j] = path
			}
		}

		mutated.Paths = paths
	}
	if rand.Float32() < 0.3 {
		mutator.MutateSnapBytes(&mutated.Bytes)
	}

	return &mutated
}

func mutateTrieNodesPacket(mutator *fuzzing.Mutator, original *snap.TrieNodesPacket) *snap.TrieNodesPacket {
	mutated := *original

	// 变异请求ID
	if rand.Float32() < 0.3 {
		mutator.MutateRequestId(&mutated.ID)
	}

	// 变异随机Trie节点
	if rand.Float32() < 0.3 {
		mutator.MutateTrieNodesResponse(&mutated.Nodes)
	}

	// 添加新的Trie节点
	if rand.Float32() < 0.3 {
		mutator.AddTrieNode(&mutated.Nodes)
	}

	// 删除随机Trie节点
	if rand.Float32() < 0.3 {
		mutator.RemoveTrieNode(&mutated.Nodes)
	}

	return &mutated
}
