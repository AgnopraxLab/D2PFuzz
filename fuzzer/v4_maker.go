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

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v4state = []string{"ping", "findnode"}
)

type V4Maker struct {
	client     *discv4.UDPv4
	targetList []*enode.Node

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type v4packetTestResult struct {
	RequestType  string
	Check        bool
	CheckResults []bool
	Success      bool
	Response     discv4.Packet
	Error        error
}

type v4result struct {
	result_1 *discv4.Pong
	result_2 *discv4.Neighbors
	n        *enode.Node
}

func NewV4Maker(targetDir string) *V4Maker {
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
		results []v4packetTestResult
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	target := m.targetList[0]
	logger.Println("target: ", target.String())
	// mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))

	ping := m.client.GenPacket("ping", target)
	// Add the sendAndWaitResponse call
	result := sendAndWaitResponse(m, target, ping, logger)
	if !result.Success {
		if logger != nil {
			logger.Printf("First ping failed to send")
		}
	}

	req := m.client.GenPacket("random", target)

	//Iterate over each target object
	//MutateCount
	// Iterate over each target object
	for i := 0; i < 2; i++ {
		// Print divider line at the start of each iteration
		logger.Printf("====================== Starting iteration %d ======================", i+1)

		wg.Add(1)

		go func(iteration int, currentReq discv4.Packet) {
			defer wg.Done()

			// Sending a single packet and waiting for feedback
			result := sendAndWaitResponse(m, target, currentReq, logger)
			result.CheckResults = m.checkRequestSemantics(currentReq)
			result.Check = allTrue(result.CheckResults)

			// Record results with mutex lock for thread safety
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(i, req)

		// Sleep between iterations to control packet sending rate
		time.Sleep(PacketSleepTime)

		// Print divider line at the end of each iteration
		logger.Printf("====================== Completed iteration %d ======================", i+1)
	}

	wg.Wait()

	// Process results
	analyzeResults(results, logger, SaveFlag, OutputDir)
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
				req := m.client.GenPacket(packetType, target)
				m.client.Send(target, req)
				logger.Printf("Sent test packet to target: %s, packet: %v", target.String(), req.Kind())
			}

			// Round 2: sending stateSeq packets
			for _, packetType := range m.stateSeq {
				req := m.client.GenPacket(packetType, target)
				// Set the expected response type based on the packet type
				rm := m.client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool, shouldComplete bool) {
					logger.Printf("Received packet of type: %T\n", p)
					if pong, ok := p.(*discv4.Pong); ok {
						logger.Printf("Received Pong response: %+v\n", pong)
						result.result_1 = p.(*discv4.Pong)
						return true, true, true
					}
					if neighbors, ok := p.(*discv4.Neighbors); ok {
						logger.Printf("Received Neighbors response: %+v\n", neighbors)
						result.result_2 = p.(*discv4.Neighbors)
						return true, true, true
					}
					return false, false, false
				})
				_ = m.client.Send(target, req)

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

func (m *V4Maker) Close() {
	if m.client != nil {
		m.client.Close()
	}
}

func (m *V4Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func processPacket(packet discv4.Packet) byte {
	switch packet.Kind() {
	case discv4.PingPacket:
		fmt.Println("Send ping packet, expecting pong response")
		return discv4.PongPacket
	case discv4.FindnodePacket:
		fmt.Println("Send findnode packet, expecting neighbors response")
		return discv4.NeighborsPacket
	case discv4.ENRRequestPacket:
		fmt.Println("Send ENR request packet, expecting ENR response")
		return discv4.ENRResponsePacket
	case discv4.PongPacket:
		fmt.Println("Send pong packet, no pending required")
		return NoPendingRequired
	case discv4.NeighborsPacket:
		fmt.Println("Send neighbors packet, no pending required")
		return NoPendingRequired
	case discv4.ENRResponsePacket:
		fmt.Println("Send ENR response, no pending required")
		return NoPendingRequired
	default:
		fmt.Printf("Unknown packet type: %v\n", packet.Kind())
		return NoPendingRequired
	}
}

func generateV4TestSeq() []string {
	options := []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
	seq := make([]string, SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < SequenceLength; i++ {
		seq[i] = options[rand.Intn(len(options))]
	}

	return seq
}

func (m *V4Maker) checkRequestSemantics(req discv4.Packet) []bool {
	switch p := req.(type) {
	case *discv4.Ping:
		return m.checkPingSemantics(p)
	case *discv4.Findnode:
		return m.checkFindnodeSemantics(p)
	case *discv4.ENRRequest:
		return m.checkENRRequestSemantics(p)
	default:
		// Return an empty []bool or a slice indicating failure
		return []bool{false} // Example: single `false` to indicate unsupported packet type
	}
}

func (m *V4Maker) checkPingSemantics(p *discv4.Ping) []bool {
	var validityResults []bool

	// 1. Check if the version is 4
	if p.Version != 4 {
		validityResults = append(validityResults, false) // Mark version check as failed
	} else {
		validityResults = append(validityResults, true) // Mark version check as success
	}

	// 2. Check if the source IP matches the client's own IP
	if !p.From.IP.Equal(m.client.Self().IP()) {
		validityResults = append(validityResults, false) // Mark source IP check as failed
	} else {
		validityResults = append(validityResults, true) // Mark source IP check as success
	}

	// 3. Check if the target IP matches the first target in the list
	if !p.To.IP.Equal(m.targetList[0].IP()) {
		validityResults = append(validityResults, false) // Mark target IP check as failed
	} else {
		validityResults = append(validityResults, true) // Mark target IP check as success
	}

	// 4. Check if the expiration time is valid
	if p.ENRSeq != m.client.Self().Seq() {
		fmt.Println("Ping ENRSeq does not match the client's ENRSeq")
		validityResults = append(validityResults, false) // Mark expiration check as failed
	} else {
		validityResults = append(validityResults, true) // Mark expiration check as success
	}

	// 5. Check if the ENRSeq matches the client's ENRSeq
	if p.Expiration <= uint64(time.Now().Unix()) {
		validityResults = append(validityResults, false) // Mark ENRSeq check as failed
	} else {
		validityResults = append(validityResults, true) // Mark ENRSeq check as success
	}

	return validityResults
}

// checkFindnodeSemantics checks the semantic correctness of a Findnode request
func (m *V4Maker) checkFindnodeSemantics(f *discv4.Findnode) []bool {
	var validityResults []bool

	// 1. Check if the expiration time is valid
	if f.Expiration <= uint64(time.Now().Unix()) {
		validityResults = append(validityResults, false) // Mark ENRSeq check as failed
	} else {
		validityResults = append(validityResults, true) // Mark ENRSeq check as success
	}

	return validityResults
}

// checkENRRequestSemantics checks the semantic correctness of an ENRRequest
func (m *V4Maker) checkENRRequestSemantics(e *discv4.ENRRequest) []bool {
	var validityResults []bool

	// 1. Check if the expiration time is valid
	if e.Expiration <= uint64(time.Now().Unix()) {
		validityResults = append(validityResults, false) // Mark ENRSeq check as failed
	} else {
		validityResults = append(validityResults, true) // Mark ENRSeq check as success
	}

	return validityResults
}

// sendAndWaitResponse sends a request and waits for response
func sendAndWaitResponse(m *V4Maker, target *enode.Node, req discv4.Packet, logger *log.Logger) v4packetTestResult {
	result := v4packetTestResult{
		RequestType: req.Name(),
	}

	// Set the expected response type based on the packet type
	rm := m.client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool, shouldComplete bool) {
		if pong, ok := p.(*discv4.Pong); ok {
			logger.Printf("Received Pong response: %+v\n", pong)
			result.Response = p.(*discv4.Pong)
			result.Success = true
			return true, true, true
		}
		if neighbors, ok := p.(*discv4.Neighbors); ok {
			logger.Printf("Received Neighbors response: %+v\n", neighbors)
			result.Response = p.(*discv4.Neighbors)
			result.Success = true
			return true, true, true
		}
		if enrResponse, ok := p.(*discv4.ENRResponse); ok {
			logger.Printf("Received ENRResponse response: %+v\n", enrResponse)
			result.Response = p.(*discv4.ENRResponse)
			result.Success = true
			return true, true, true
		}
		return false, false, false
	})

	_ = m.client.Send(target, req)
	// Record send log info
	if logger != nil {
		logger.Printf("Sent packet to target: %s, packet: %v", target.String(), req.Kind())
	}
	// Waiting for a response with the new WaitForResponse method
	if err := rm.WaitForResponse(1 * time.Second); err != nil {
		if err.Error() == "timeout waiting for response" {
			logger.Printf("No response received within timeout")
		} else {
			logger.Printf("Error waiting for response: %v", err)
		}
	} else {
		logger.Printf("Successfully received response")
	}

	return result
}

func analyzeResults(results []v4packetTestResult, logger *log.Logger, saveToFile bool, outputDir string) error {
	// Define slices for three scenarios
	resultWanted := make([]v4packetTestResult, 0)

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

		// 需要创建完整的目录路径
		fullPath := filepath.Join(outputDir, "discv4")
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to create discv4 directory: %v", err)
		}

		filename := filepath.Join(fullPath, fmt.Sprintf("analysis_results_%s.json", time.Now().Format("2006-01-02_15-04-05")))

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
