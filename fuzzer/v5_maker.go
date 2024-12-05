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
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v5state          = []string{"ping", "findnode"}
	HandshakeTimeout = 5 * time.Second // 握手专用超时
)

type V5Maker struct {
	client     *discv5.UDPv5
	targetList []*enode.Node

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type v5packetTestResult struct {
	RequestType  string
	CheckResults []bool
	Check        bool
	Success      bool
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
		client:     cli,
		targetList: nodeList,
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

func (m *V5Maker) PacketStart(traceOutput io.Writer) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []v5packetTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	target := m.targetList[0]

	// Send initial ping packet to establish connection
	ping := m.client.GenPacket("ping", target)

	nonce, err := m.sendAndReceive(target, ping, traceOutput, logger)
	if err != nil {
		if logger != nil {
			logger.Printf("Failed to send initial ping: %v", err)
		}
	}
	if logger != nil {
		logger.Printf("Initial ping sent, nonce: %x", nonce)
	}

	req := m.client.GenPacket("ping", target)

	for i := 0; i < 2; i++ {
		wg.Add(1)

		go func(iteration int, currentReq discv5.Packet) {
			defer wg.Done()

			result := v5packetTestResult{
				RequestType: currentReq.Name(),
			}

			_, err := m.sendAndReceive(target, currentReq, traceOutput, logger)
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Success = true
			}
			result.CheckResults = m.checkRequestSemanticsV5(currentReq)
			result.Check = allTrue(result.CheckResults)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, req)

		time.Sleep(50 * time.Millisecond)
	}

	wg.Wait()

	// Analyze results
	analyzeResultsV5(results, logger, SaveFlag, OutputDir)
	return nil
}

func (m *V5Maker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *v5result, len(m.targetList))
		errorCh  = make(chan error, len(m.targetList))
		logger   *log.Logger
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Iterate over each target object
	for _, target := range m.targetList {
		wg.Add(1)
		go func(target *enode.Node) {
			defer wg.Done()
			result := &v5result{
				n: target,
			}
			// First round: sending testSeq packets
			for _, packetType := range m.testSeq {
				req := m.client.GenPacket(packetType, target)
				nonce, err := m.sendAndReceive(target, req, traceOutput, logger)
				if err != nil {
					fmt.Errorf("failed to send and receive packet")
				}
				logger.Printf("Sent test packet to target: %s, packet: %v", target.String(), req.Kind())
				if traceOutput != nil {
					logger.Println(traceOutput, "Sent packet, nonce: %x\n", nonce)
				}
			}

			// Round 2: sending stateSeq packets
			for _, packetType := range m.stateSeq {
				req := m.client.GenPacket(packetType, target)
				// Set the expected response type based on the packet type
				nonce, err := m.sendAndReceive(target, req, traceOutput, logger)
				if err != nil {
					fmt.Errorf("failed to send and receive packet")
				}
				if traceOutput != nil {
					logger.Println(traceOutput, "Sent packet, nonce: %x\n", nonce)
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
	if m.client != nil {
		m.client.Close()
	}
}

func (m *V5Maker) sendAndReceive(target *enode.Node, req discv5.Packet, traceOutput io.Writer, logger *log.Logger) ([]byte, error) {
	// 根据请求类型确定期望的响应类型
	var responseType byte
	switch req.Kind() {
	case discv5.PingMsg:
		responseType = discv5.PongMsg
	case discv5.FindnodeMsg:
		responseType = discv5.NodesMsg
	case discv5.TalkRequestMsg:
		responseType = discv5.TalkResponseMsg
	default:
		// 其他类型的包可能不需要等待响应
		responseType = req.Kind()
	}
	// 创建 call，使用确定的响应类型
	call := m.client.CallToNode(target, responseType, req)

	defer m.client.CallDone(call) // 使用 defer 确保清理

	respChan := m.client.GetCallResponseChan(call)
	errChan := m.client.GetCallErrorChan(call)
	// 等待响应
	select {
	case resp := <-respChan:
		// 根据请求类型处理并返回相应的值
		switch req.Kind() {
		case discv5.PingMsg:
			if pong, ok := resp.(*discv5.Pong); ok {
				logger.Printf("Received PONG response")
				return pong.ReqID, nil
			}
		case discv5.FindnodeMsg:
			if nodes, ok := resp.(*discv5.Nodes); ok {
				logger.Printf("Received NODES response")
				return nodes.ReqID, nil
			}
		case discv5.TalkRequestMsg:
			if talkResp, ok := resp.(*discv5.TalkResponse); ok {
				logger.Printf("Received TALK_RESPONSE")
				return talkResp.ReqID, nil
			}
		}
		return nil, fmt.Errorf("unexpected response type: %T", resp)

	case err := <-errChan:
		return []byte{}, err
	}
}

func (m *V5Maker) waitForHandshakeResponse(whoareyou *discv5.Whoareyou, target *enode.Node, req discv5.Packet, traceOutput io.Writer, logger *log.Logger) (discv5.Nonce, error) {
	m.client.SetReadDeadline(time.Now().Add(HandshakeTimeout))

	buf := make([]byte, 1280)

	// 等待并处理响应
	for {
		n, fromAddr, err := m.client.ReadFromUDP(buf)
		if err != nil {
			return discv5.Nonce{}, fmt.Errorf("failed to read handshake response: %v", err)
		}

		packet, _, err := m.client.Decode(buf[:n], fromAddr.String())
		if err != nil {
			return discv5.Nonce{}, fmt.Errorf("failed to decode handshake response: %v", err)
		}

		switch p := packet.(type) {
		case *discv5.Unknown:
			// UNKNOWN 包是握手过程的正常部分
			logger.Printf("Received expected Unknown packet during handshake")
			continue

		case *discv5.Pong:
			// 收到 PONG 表示握手成功完成
			logger.Printf("Handshake completed successfully, received Pong")
			return discv5.Nonce{}, nil

		case *discv5.Whoareyou:
			// 如果在这里又收到 WHOAREYOU，可能之前的认证包有问题
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
	options := []string{"ping", "pong", "findnode", "nodes", "talkrequest", "talkresponse", "whoareyou"}
	seq := make([]string, SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
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
	if p.ENRSeq != m.client.Self().Seq() {
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
	if w.RecordSeq != m.targetList[0].Seq() {
		validityResults = append(validityResults, false)
	} else {
		validityResults = append(validityResults, true)
	}

	// 2. Check if the Node matches the client's local node
	if w.Node != m.targetList[0] {
		validityResults = append(validityResults, false)
	} else {
		fmt.Println("Node is invalid")
		validityResults = append(validityResults, true)
	}

	return validityResults
}

func analyzeResultsV5(results []v5packetTestResult, logger *log.Logger, saveToFile bool, outputDir string) error {
	// Define slices for three scenarios
	resultWanted := make([]v5packetTestResult, 0)

	// Iterate through results and categorize
	for _, result := range results {
		if result.Check || result.Success {
			resultWanted = append(resultWanted, result)
		}
	}

	if saveToFile {
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}

		// Generate filename (using timestamp)
		filename := filepath.Join(outputDir, "/discv5", fmt.Sprintf("analysis_results_%s.json", time.Now().Format("2006-01-02_15-04-05")))

		// Save to file
		data, err := json.MarshalIndent(resultWanted, "", "    ")
		if err != nil {
			return fmt.Errorf("JSON serialization failed: %v", err)
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}

		logger.Printf("Results saved to file: %s\n", filename)
	} else {
		// Output to log
		logger.Printf("Number of results with: %d\n", len(resultWanted))
	}

	return nil
}
