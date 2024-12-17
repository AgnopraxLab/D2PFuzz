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
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v5options        = []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	v5state          = []string{"ping", "findnode"}
	HandshakeTimeout = 1 * time.Second // Timeout for handshake
)

type V5Maker struct {
	Client     *discv5.UDPv5
	TargetList []*enode.Node

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	PakcetSeed []discv5.Packet // Use store packet seed to mutator

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type v5packetTestResult struct {
	PacketID     int
	RequestType  string
	Check        bool
	CheckResults []bool
	Success      bool
	Request      discv5.Packet
	Response     discv5.Packet
	Error        error
}

type v5result struct {
	result_1 *discv5.Pong
	result_2 *discv5.Nodes
	n        *enode.Node
}

func NewV5Maker(targetDir string) *V5Maker {
	var (
		cli      *discv5.UDPv5
		nodeList []*enode.Node
	)

	cli = generator.InitDiscv5()
	nodeList, _ = getList(targetDir)

	v5maker := &V5Maker{
		Client:     cli,
		TargetList: nodeList,
		testSeq:    generateV5TestSeq(),
		stateSeq:   v5state,
	}
	return v5maker
}

func (m *V5Maker) ToGeneralStateTest(name string) *GeneralStateTest {
	gst := make(GeneralStateTest)
	gst[name] = m.ToSubTest()
	return &gst
}

func (m *V5Maker) ToSubTest() *stJSON {
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

func (m *V5Maker) PacketStart(traceOutput io.Writer, seed discv5.Packet, stats *UDPPacketStats) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []v5packetTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Send initial ping packet to establish connection
	ping := m.Client.GenPacket("ping", m.TargetList[0])
	_, err := m.sendAndReceive(m.TargetList[0], ping, logger)
	if err != nil {
		fmt.Printf("Send initial ping failed: %s", err)
	}

	mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))
	currentSeed := seed

	for i := 0; i < MutateCount; i++ {
		wg.Add(1)

		mutateSeed := cloneAndMutateV5Packet(mutator, currentSeed)

		go func(iteration int, packetSeed discv5.Packet, packetStats *UDPPacketStats) {
			defer wg.Done()

			result, err := m.sendAndReceive(m.TargetList[0], packetSeed, logger)
			if err != nil {
				logger.Printf("failed to send and receive packet: %v", err)
			}
			result.CheckResults = m.checkRequestSemanticsV5(packetSeed)
			result.Check = allTrue(result.CheckResults)
			result.PacketID = i
			result.Request = packetSeed

			if result.Check && !result.Success {
				mu.Lock()
				packetStats.CheckTrueFail = packetStats.CheckTrueFail + 1
				// m.PakcetSeed = append(m.PakcetSeed, mutatedSeed)
				results = append(results, result)
				mu.Unlock()
			} else if !result.Check && result.Success {
				mu.Lock()
				packetStats.CheckFalsePass = packetStats.CheckFalsePass + 1
				// m.PakcetSeed = append(m.PakcetSeed, mutatedSeed)
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

	if SaveFlag {
		analyzeResultsV5(results, logger, OutputDir)
	}
	return nil
}

func (m *V5Maker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *v5result, len(m.TargetList))
		errorCh  = make(chan error, len(m.TargetList))
		logger   *log.Logger
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Iterate over each target object
	for _, target := range m.TargetList {
		wg.Add(1)
		go func(target *enode.Node) {
			defer wg.Done()
			result := &v5result{
				n: target,
			}
			// First round: sending testSeq packets
			for _, packetType := range m.testSeq {
				req := m.Client.GenPacket(packetType, target)
				_, err := m.sendAndReceive(target, req, logger)
				if err != nil {
					fmt.Errorf("failed to send and receive packet")
				}
				logger.Printf("Sent test packet to target: %s, packet: %v", target.String(), req.Kind())
			}

			// Round 2: sending stateSeq packets
			for _, packetType := range m.stateSeq {
				req := m.Client.GenPacket(packetType, target)
				// Set the expected response type based on the packet type
				_, err := m.sendAndReceive(target, req, logger)
				if err != nil {
					fmt.Errorf("failed to send and receive packet")
				}
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
	var allResults []*v5result
	for result := range resultCh {
		allResults = append(allResults, result)
	}
	// fmt.Printf("All results: %v\n", allResults)

	return nil
}

func (m *V5Maker) Close() {
	if m.Client != nil {
		m.Client.Close()
	}
}

func (m *V5Maker) sendAndReceive(target *enode.Node, req discv5.Packet, logger *log.Logger) (v5packetTestResult, error) {
	result := v5packetTestResult{
		RequestType: req.Name(),
	}

	// Determine expected response type based on request type
	var responseType byte
	switch req.Kind() {
	case discv5.PingMsg:
		responseType = discv5.PongMsg
	case discv5.FindnodeMsg:
		responseType = discv5.NodesMsg
	case discv5.TalkRequestMsg:
		responseType = discv5.TalkResponseMsg
	default:
		// Other packet types may not need to wait for response
		responseType = req.Kind()
	}
	// Create call with determined response type
	call := m.Client.CallToNode(target, responseType, req)

	defer m.Client.CallDone(call) // Use defer to ensure cleanup

	respChan := m.Client.GetCallResponseChan(call)
	errChan := m.Client.GetCallErrorChan(call)
	// Wait for response
	select {
	case resp := <-respChan:
		// Process and return value based on request type
		switch req.Kind() {
		case discv5.PingMsg:
			if pong, ok := resp.(*discv5.Pong); ok {
				logger.Printf("Received PONG response")
				result.Response = pong
				result.Success = true
				return result, nil
			}
		case discv5.FindnodeMsg:
			if nodes, ok := resp.(*discv5.Nodes); ok {
				logger.Printf("Received NODES response")
				result.Response = nodes
				result.Success = true
				return result, nil
			}
		case discv5.TalkRequestMsg:
			if talkResp, ok := resp.(*discv5.TalkResponse); ok {
				logger.Printf("Received TALK_RESPONSE")
				result.Response = talkResp
				result.Success = true
				return result, nil
			}
		default:
			logger.Printf("Received unexpected response type: %T", resp)
			result.Success = true
			result.Response = resp
			return result, fmt.Errorf("unexpected response type: %T", resp)
		}

	case err := <-errChan:
		return result, err
	}
	return result, fmt.Errorf("unknown result")
}

func (m *V5Maker) waitForHandshakeResponse(whoareyou *discv5.Whoareyou, target *enode.Node, req discv5.Packet, traceOutput io.Writer, logger *log.Logger) (discv5.Nonce, error) {
	m.Client.SetReadDeadline(time.Now().Add(HandshakeTimeout))

	buf := make([]byte, 1280)

	// Wait and process response
	for {
		n, fromAddr, err := m.Client.ReadFromUDP(buf)
		if err != nil {
			return discv5.Nonce{}, fmt.Errorf("failed to read handshake response: %v", err)
		}

		packet, _, err := m.Client.Decode(buf[:n], fromAddr.String())
		if err != nil {
			return discv5.Nonce{}, fmt.Errorf("failed to decode handshake response: %v", err)
		}

		switch p := packet.(type) {
		case *discv5.Unknown:
			// UNKNOWN packet is normal part of handshake process
			logger.Printf("Received expected Unknown packet during handshake")
			continue

		case *discv5.Pong:
			// Receiving PONG indicates successful handshake completion
			logger.Printf("Handshake completed successfully, received Pong")
			return discv5.Nonce{}, nil

		case *discv5.Whoareyou:
			// If receiving WHOAREYOU here, previous auth packet may have issues
			logger.Printf("Unexpected WHOAREYOU during handshake")
			return discv5.Nonce{}, fmt.Errorf("received unexpected WHOAREYOU")

		default:
			logger.Printf("Unexpected packet type: %T", p)
			continue
		}
	}
}

func (m *V5Maker) logPacketInfo(packet discv5.Packet, traceOutput io.Writer) {
	switch resp := packet.(type) {
	case *discv5.Unknown:
		fmt.Println(traceOutput, "Got Unknown: Nonce=%x\n", resp.Nonce)
	case *discv5.Ping:
		fmt.Println(traceOutput, "Got Ping: ReqID=%x, ENRSeq=%d\n", resp.ReqID, resp.ENRSeq)
	case *discv5.Pong:
		fmt.Println(traceOutput, "Got Pong: ReqID=%x, ENRSeq=%d, ToIP=%v, ToPort=%d\n", resp.ReqID, resp.ENRSeq, resp.ToIP, resp.ToPort)
	case *discv5.Findnode:
		fmt.Println(traceOutput, "Got Findnode: ReqID=%x, Distances=%v, OpID=%d\n", resp.ReqID, resp.Distances, resp.OpID)
	case *discv5.Nodes:
		fmt.Println(traceOutput, "Got Nodes: ReqID=%x, RespCount=%d, Nodes count=%d\n", resp.ReqID, resp.RespCount, len(resp.Nodes))
		for i, node := range resp.Nodes {
			fmt.Println(traceOutput, "  Node %d: %v\n", i, node)
		}
	case *discv5.TalkRequest:
		fmt.Println(traceOutput, "Got TalkRequest: ReqID=%x, Protocol=%s, Message=%x\n", resp.ReqID, resp.Protocol, resp.Message)
	case *discv5.TalkResponse:
		fmt.Println(traceOutput, "Got TalkResponse: ReqID=%x, Message=%x\n", resp.ReqID, resp.Message)
	default:
		fmt.Println(traceOutput, "Unexpected response type: %T\n", resp)
	}
}

func (m *V5Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func generateV5TestSeq() []string {
	seq := make([]string, SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < SequenceLength; i++ {
		seq[i] = v5options[rand.Intn(len(v5options))]
	}

	return seq
}

func (m *V5Maker) checkRequestSemanticsV5(req discv5.Packet) []bool {
	switch p := req.(type) {
	case *discv5.Ping:
		return m.checkPingSemanticsV5(p)
	case *discv5.Findnode:
		return m.checkFindnodeSemanticsV5(p)
	case *discv5.TalkRequest:
		return m.checkTalkRequestSemanticsV5(p)
	case *discv5.Whoareyou:
		return m.checkWhoareyouSemantics(p)
	default:
		// Return an empty []bool or a slice indicating failure
		return []bool{false} // Example: single `false` to indicate unsupported packet type
	}
}

func (m *V5Maker) checkPingSemanticsV5(p *discv5.Ping) []bool {
	var validityResults []bool

	// 1. Check if the ENRSeq is valid
	if p.ENRSeq != m.Client.Self().Seq() {
		validityResults = append(validityResults, false) // Mark expiration check as failed
	} else {
		validityResults = append(validityResults, true) // Mark expiration check as success
	}
	return validityResults
}

func (m *V5Maker) checkFindnodeSemanticsV5(f *discv5.Findnode) []bool {

	return []bool{true}
}

func (m *V5Maker) checkTalkRequestSemanticsV5(t *discv5.TalkRequest) []bool {
	var validityResults []bool

	// 1. Check if the Protocol is valid
	if t.Protocol == "test-protocol" {
		validityResults = append(validityResults, true) // Mark protocol check as success
	} else {
		validityResults = append(validityResults, false) // Mark protocol check as failed
	}

	return validityResults
}

func (m *V5Maker) checkWhoareyouSemantics(w *discv5.Whoareyou) []bool {
	var validityResults []bool

	// 1. Check if RecordSeq matches the client's current sequence
	if w.RecordSeq != m.TargetList[0].Seq() {
		validityResults = append(validityResults, false)
	} else {
		validityResults = append(validityResults, true)
	}

	// 2. Check if the Node matches the client's local node
	if w.Node != m.TargetList[0] {
		validityResults = append(validityResults, false)
	} else {
		fmt.Println("Node is invalid")
		validityResults = append(validityResults, true)
	}

	return validityResults
}

func analyzeResultsV5(results []v5packetTestResult, logger *log.Logger, outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// 需要创建完整的目录路径
	fullPath := filepath.Join(outputDir, "discv5")
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create discv5 directory: %v", err)
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

// Main function for cloning and mutating v5 packets
func cloneAndMutateV5Packet(mutator *fuzzing.Mutator, seed discv5.Packet) discv5.Packet {
	switch p := seed.(type) {
	case *discv5.Ping:
		return mutatePingV5(mutator, p)
	case *discv5.Pong:
		return mutatePongV5(mutator, p)
	case *discv5.Findnode:
		return mutateFindnodeV5(mutator, p)
	case *discv5.Nodes:
		return mutateNodesV5(mutator, p)
	case *discv5.TalkRequest:
		return mutateTalkRequestV5(mutator, p)
	case *discv5.TalkResponse:
		return mutateTalkResponseV5(mutator, p)
	case *discv5.Whoareyou:
		return mutateWhoareyouV5(mutator, p)
	default:
		return seed
	}
}

func mutatePingV5(mutator *fuzzing.Mutator, original *discv5.Ping) *discv5.Ping {
	mutated := *original

	// 使用已有的变异方法
	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateENRSeq(&mutated.ENRSeq)

	return &mutated
}

func mutatePongV5(mutator *fuzzing.Mutator, original *discv5.Pong) *discv5.Pong {
	mutated := *original

	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateENRSeq(&mutated.ENRSeq)
	// Mutate network address
	if mutator.Bool() {
		mutated.ToIP = net.IPv4(
			byte(mutator.Rand(256)),
			byte(mutator.Rand(256)),
			byte(mutator.Rand(256)),
			byte(mutator.Rand(256)),
		)
		mutated.ToPort = uint16(mutator.Rand(65536))
	}

	return &mutated
}

func mutateFindnodeV5(mutator *fuzzing.Mutator, original *discv5.Findnode) *discv5.Findnode {
	mutated := *original

	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateDistances(&mutated.Distances)

	return &mutated
}

func mutateNodesV5(mutator *fuzzing.Mutator, original *discv5.Nodes) *discv5.Nodes {
	mutated := *original

	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateNodes(&mutated.Nodes)

	// Mutate RespCount
	if mutator.Bool() {
		mutated.RespCount = uint8(mutator.Rand(256))
	}

	return &mutated
}

func mutateTalkRequestV5(mutator *fuzzing.Mutator, original *discv5.TalkRequest) *discv5.TalkRequest {
	mutated := *original

	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateBytes(&mutated.Message)

	// Mutate Protocol
	if mutator.Bool() {
		protocols := []string{"test-protocol", "discv5", "eth", "snap"}
		mutated.Protocol = protocols[mutator.Rand(len(protocols))]
	}

	return &mutated
}

func mutateTalkResponseV5(mutator *fuzzing.Mutator, original *discv5.TalkResponse) *discv5.TalkResponse {
	mutated := *original

	mutator.MutateBytes(&mutated.ReqID)
	mutator.MutateBytes(&mutated.Message)

	return &mutated
}

func mutateWhoareyouV5(mutator *fuzzing.Mutator, original *discv5.Whoareyou) *discv5.Whoareyou {
	mutated := *original

	mutator.MutateBytes(&mutated.ChallengeData)
	mutator.FillBytes((*[]byte)(unsafe.Pointer(&mutated.IDNonce)))
	mutator.MutateENRSeq(&mutated.RecordSeq)

	return &mutated
}
