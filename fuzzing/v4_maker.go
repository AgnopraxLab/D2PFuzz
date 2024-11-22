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

package fuzzing

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v4state = []string{"ping", "findnode"}
)

type V4Maker struct {
	client     *discv4.UDPv4
	targetList []*enode.Node
	filler     filler.Filler

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type packetTestResult struct {
	RequestType string
	Success     bool
	Response    discv4.Packet
	Error       error
}

type v4result struct {
	result_1 *discv4.Pong
	result_2 *discv4.Neighbors
	n        *enode.Node
}

func NewV4Maker(f *filler.Filler, targetDir string) *V4Maker {
	var (
		cli      *discv4.UDPv4
		nodeList []*enode.Node
	)

	cli = generator.InitDiscv4()
	nodeList, _ = getList(targetDir)

	v4maker := &V4Maker{
		client:     cli,
		targetList: nodeList,
		testSeq:    generateV4TestSeq(),
		stateSeq:   v4state,
	}

	return v4maker
}

func (m *V4Maker) ToGeneralStateTest(name string) *GeneralStateTest {
	gst := make(GeneralStateTest)
	gst[name] = m.ToSubTest()
	return &gst
}

func (m *V4Maker) ToSubTest() *stJSON {
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

// PacketStart executes fuzzing by sending single packets in multiple goroutines and collecting feedback
func (m *V4Maker) PacketStart(traceOutput io.Writer) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []packetTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	target := m.targetList[0]
	// mutator := NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))

	ping := m.client.GenPacket(&m.filler, "ping", target)
	err := m.client.Send(target, ping)
	if err != nil {
		logger.Printf("Failed to send initial ping: %v", err)
	}

	req := m.client.GenPacket(&m.filler, "random", target)

	// Iterate over each target object
	for i := 0; i < config.MutateCount; i++ {
		wg.Add(1)

		// check req

		go func(iteration int, currentReq discv4.Packet) {
			defer wg.Done()

			if !checkRequestSemantics(currentReq, logger) {
				if logger != nil {
					logger.Printf("Invalid request semantics in iteration %d", iteration)
				}
				return
			}

			// Sending a single packet and waiting for feedback
			result := sendAndWaitResponse(m, target, currentReq, logger)

			// 记录结果
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, req)

		time.Sleep(50 * time.Millisecond)
	}

	wg.Wait()

	// Process results

	// fmt.Printf("All results: %v\n", allResults)

	return nil
}

func (m *V4Maker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *v4result, len(m.targetList))
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
			result := &v4result{
				n: target,
			}
			// First round: sending testSeq packets
			for _, packetType := range m.testSeq {
				req := m.client.GenPacket(&m.filler, packetType, target)
				m.client.Send(target, req)
				logger.Printf("Sent test packet to target: %s, packet: %v", target.String(), req.Kind())
			}

			// Round 2: sending stateSeq packets
			for _, packetType := range m.stateSeq {
				req := m.client.GenPacket(&m.filler, packetType, target)
				// Set the expected response type based on the packet type
				rm := m.client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool) {
					logger.Printf("Received packet of type: %T\n", p)
					if pong, ok := p.(*discv4.Pong); ok {
						logger.Printf("Received Pong response: %+v\n", pong)
						result.result_1 = p.(*discv4.Pong)
						return true, true
					}
					if neighbors, ok := p.(*discv4.Neighbors); ok {
						logger.Printf("Received Neighbors response: %+v\n", neighbors)
						result.result_2 = p.(*discv4.Neighbors)
						return true, true
					}
					return false, false
				})
				if err := m.client.Send(target, req); err != nil {
					if logger != nil {
						logger.Printf("Failed to send packet: %v", err)
					}
				}
				// Record send log info
				if logger != nil {
					logger.Printf("Sent state packet to target: %s, packet: %v", target.String(), req.Kind())
				}
				// Waiting for a response with the new WaitForResponse method
				if err := rm.WaitForResponse(1 * time.Second); err != nil {
					if logger != nil {
						logger.Printf("Timeout waiting for response")
					}
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
	var allResults []*v4result
	for result := range resultCh {
		allResults = append(allResults, result)
	}
	// fmt.Printf("All results: %v\n", allResults)

	return nil
}

func (v *V4Maker) Close() {
	if v.client != nil {
		v.client.Close()
	}
}

func (m *V4Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func processPacket(packet discv4.Packet) byte {
	switch packet.Kind() {
	case discv4.PingPacket:
		fmt.Println("Received ping packet, expecting pong response")
		return discv4.PongPacket
	case discv4.FindnodePacket:
		fmt.Println("Received findnode packet, expecting neighbors response")
		return discv4.NeighborsPacket
	case discv4.ENRRequestPacket:
		fmt.Println("Received ENR request packet, expecting ENR response")
		return discv4.ENRResponsePacket
	case discv4.PongPacket:
		fmt.Println("Received pong packet, no pending required")
		return NoPendingRequired
	case discv4.NeighborsPacket:
		fmt.Println("Received neighbors packet, no pending required")
		return NoPendingRequired
	case discv4.ENRResponsePacket:
		fmt.Println("Received ENR response, no pending required")
		return NoPendingRequired
	default:
		fmt.Printf("Unknown packet type: %v\n", packet.Kind())
		return NoPendingRequired
	}
}

func generateV4TestSeq() []string {
	options := []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
	seq := make([]string, config.SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < config.SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}

func checkRequestSemantics(req discv4.Packet, logger *log.Logger) bool {
	switch p := req.(type) {
	case *discv4.Ping:
		return checkPingSemantics(p, logger)
	case *discv4.Findnode:
		return checkFindnodeSemantics(p, logger)
	case *discv4.ENRRequest:
		return checkENRRequestSemantics(p, logger)
	default:
		if logger != nil {
			logger.Printf("Unknown packet type: %T", req)
		}
		return false
	}
}

func checkPingSemantics(p *discv4.Ping, logger *log.Logger) bool {
	// 检查过期时间是否合理
	// if p.Expiration <= uint64(time.Now().Unix()) {
	// 	if logger != nil {
	// 		logger.Printf("Invalid expiration time in Ping")
	// 	}
	// 	return false
	// }
	// if !isValidEndpoint(p.From) || !isValidEndpoint(p.To) {
	// 	if logger != nil {
	// 		logger.Printf("Invalid endpoint in Ping")
	// 	}
	// 	return false
	// }

	return true
}

// checkFindnodeSemantics 检查Findnode请求的语义正确性
func checkFindnodeSemantics(f *discv4.Findnode, logger *log.Logger) bool {
	return false
}

// checkENRRequestSemantics 检查ENRRequest请求的语义正确性
func checkENRRequestSemantics(e *discv4.ENRRequest, logger *log.Logger) bool {
	// 检查过期时间
	if e.Expiration <= uint64(time.Now().Unix()) {
		if logger != nil {
			logger.Printf("Invalid expiration time in ENRRequest")
		}
		return false
	}

	return true
}

// sendAndWaitResponse 发送请求并等待响应
func sendAndWaitResponse(m *V4Maker, target *enode.Node, req discv4.Packet, logger *log.Logger) packetTestResult {
	result := packetTestResult{
		RequestType: req.Name(),
	}

	// 发送请求
	_ = m.client.Send(target, req)
	if logger != nil {
		logger.Printf("Sent packet to target: %s, type: %s", target.String(), req.Name())
	}

	// 等待响应
	rm := m.client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool) {
		if logger != nil {
			logger.Printf("Received packet of type: %T", p)
		}

		result.Response = p

		switch p.(type) {
		case *discv4.Pong:
			return true, true
		case *discv4.Neighbors:
			return true, true
		case *discv4.ENRResponse:
			return true, true
		}
		return false, false
	})

	if err := rm.WaitForResponse(1 * time.Second); err != nil {
		if logger != nil {
			logger.Printf("Timeout waiting for response")
		}
		result.Error = err
		return result
	}

	result.Success = true
	return result
}

func analyzeResults(results []packetTestResult, logger *log.Logger) {
	if logger == nil {
		return
	}

	var (
		totalTests   = len(results)
		successCount = 0
		failureCount = 0
		timeoutCount = 0
	)

	for _, result := range results {
		if result.Success {
			successCount++
		} else if result.Error != nil {
			if result.Error.Error() == "timeout" {
				timeoutCount++
			} else {
				failureCount++
			}
		}
	}

	// stastic
	logger.Printf("Test Summary:")
	logger.Printf("Total Tests: %d", totalTests)
	logger.Printf("Successful: %d (%.2f%%)", successCount, float64(successCount)/float64(totalTests)*100)
	logger.Printf("Failed: %d (%.2f%%)", failureCount, float64(failureCount)/float64(totalTests)*100)
	logger.Printf("Timeouts: %d (%.2f%%)", timeoutCount, float64(timeoutCount)/float64(totalTests)*100)
}
