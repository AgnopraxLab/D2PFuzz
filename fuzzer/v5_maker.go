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

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v5state = []string{"ping", "findnode"}
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
	RequestType string
	Check       bool
	Success     bool
	Response    discv5.Packet
	Error       error
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

	// 发送初始ping包建立连接
	ping := m.client.GenPacket("ping", target)
	nonce, err := m.sendAndReceive(target, ping, traceOutput)
	if err != nil {
		if logger != nil {
			logger.Printf("Failed to send initial ping: %v", err)
		}
	}
	if logger != nil {
		logger.Printf("Initial ping sent, nonce: %x", nonce)
	}

	req := m.client.GenPacket("random", target)

	for i := 0; i < config.MutateCount; i++ {
		wg.Add(1)

		go func(iteration int, currentReq discv5.Packet) {
			defer wg.Done()

			result := v5packetTestResult{
				RequestType: currentReq.Name(),
			}

			_, err := m.sendAndReceive(target, currentReq, traceOutput)
			if err != nil {
				result.Error = err
				result.Success = false
			} else {
				result.Success = true
			}

			result.Check = checkRequestSemanticsV5(currentReq)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, req)

		time.Sleep(50 * time.Millisecond)
	}

	wg.Wait()

	// 分析结果
	analyzeResultsV5(results, logger, config.SaveFlag, config.OutputDir)
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
				nonce, err := m.sendAndReceive(target, req, traceOutput)
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
				nonce, err := m.sendAndReceive(target, req, traceOutput)
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

func (v *V5Maker) Close() {
	if v.client != nil {
		v.client.Close()
	}
}

func (m *V5Maker) sendAndReceive(target *enode.Node, req discv5.Packet, traceOutput io.Writer) (discv5.Nonce, error) {
	const waitTime = 5 * time.Second

	nonce, err := m.client.Send(target, req, nil)
	if err != nil {
		return nonce, fmt.Errorf("failed to send packet: %v", err)
	}

	m.client.SetReadDeadline(time.Now().Add(waitTime))
	buf := make([]byte, 1280)
	n, fromAddr, err := m.client.ReadFromUDP(buf)
	if err != nil {
		return nonce, fmt.Errorf("failed to read response: %v", err)
	}

	packet, _, err := m.client.Decode(buf[:n], fromAddr.String())
	if err != nil {
		return nonce, fmt.Errorf("failed to decode response: %v", err)
	}

	if traceOutput != nil {
		m.logPacketInfo(packet, traceOutput)
	}

	if whoareyou, ok := packet.(*discv5.Whoareyou); ok {
		if whoareyou.Nonce != nonce {
			return nonce, fmt.Errorf("wrong nonce in WHOAREYOU")
		}
		challenge := &discv5.Whoareyou{
			Nonce:     whoareyou.Nonce,
			IDNonce:   whoareyou.IDNonce,
			RecordSeq: whoareyou.RecordSeq,
		}
		nonce, err = m.client.Send(target, req, challenge)
		if err != nil {
			return nonce, fmt.Errorf("failed to send handshake: %v", err)
		}
		return m.sendAndReceive(target, req, traceOutput)
	}

	return nonce, nil
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
	seq := make([]string, config.SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < config.SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}

func checkRequestSemanticsV5(req discv5.Packet) bool {
	switch p := req.(type) {
	case *discv5.Ping:
		return checkPingSemanticsV5(p)
	case *discv5.Findnode:
		return checkFindnodeSemanticsV5(p)
	case *discv5.TalkRequest:
		return checkTalkRequestSemanticsV5(p)
	default:
		return false
	}
}

func checkPingSemanticsV5(p *discv5.Ping) bool {
	if p.ReqID == nil {
		return false
	}
	return true
}

func checkFindnodeSemanticsV5(f *discv5.Findnode) bool {
	if f.ReqID == nil {
		return false
	}
	if len(f.Distances) == 0 {
		return false
	}
	return true
}

func checkTalkRequestSemanticsV5(t *discv5.TalkRequest) bool {
	if t.ReqID == nil {
		return false
	}
	if len(t.Protocol) == 0 {
		return false
	}
	return true
}

func analyzeResultsV5(results []v5packetTestResult, logger *log.Logger, saveToFile bool, outputDir string) error {
	// 分类结果
	checkTrueSuccessTrue := make([]v5packetTestResult, 0)
	checkFalseSuccessTrue := make([]v5packetTestResult, 0)
	checkTrueSuccessFalse := make([]v5packetTestResult, 0)

	for _, result := range results {
		switch {
		case result.Check && result.Success:
			checkTrueSuccessTrue = append(checkTrueSuccessTrue, result)
		case !result.Check && result.Success:
			checkFalseSuccessTrue = append(checkFalseSuccessTrue, result)
		case result.Check && !result.Success:
			checkTrueSuccessFalse = append(checkTrueSuccessFalse, result)
		}
	}

	if saveToFile {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}

		outputResult := struct {
			CheckTrueSuccessTrue  []v5packetTestResult `json:"check_true_success_true"`
			CheckFalseSuccessTrue []v5packetTestResult `json:"check_false_success_true"`
			CheckTrueSuccessFalse []v5packetTestResult `json:"check_true_success_false"`
			Timestamp             string               `json:"timestamp"`
		}{
			CheckTrueSuccessTrue:  checkTrueSuccessTrue,
			CheckFalseSuccessTrue: checkFalseSuccessTrue,
			CheckTrueSuccessFalse: checkTrueSuccessFalse,
			Timestamp:             time.Now().Format("2006-01-02_15-04-05"),
		}

		filename := filepath.Join(outputDir, "/discv5", fmt.Sprintf("analysis_results_%s.json", outputResult.Timestamp))
		data, err := json.MarshalIndent(outputResult, "", "    ")
		if err != nil {
			return fmt.Errorf("JSON serialization failed: %v", err)
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}

		if logger != nil {
			logger.Printf("Results saved to file: %s\n", filename)
		}
	} else {
		if logger != nil {
			logger.Printf("Number of results with Check=true, Success=true: %d\n", len(checkTrueSuccessTrue))
			logger.Printf("Number of results with Check=false, Success=true: %d\n", len(checkFalseSuccessTrue))
			logger.Printf("Number of results with Check=true, Success=false: %d\n", len(checkTrueSuccessFalse))
		}
	}

	return nil
}
