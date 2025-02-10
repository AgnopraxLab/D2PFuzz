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

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v4options = []string{"ping", "pong", "findnode", "neighbors", "ENRRequest", "ENRResponse"}
	v4state   = []string{"ping", "findnode"}
)

type V4Maker struct {
	Client     *discv4.UDPv4
	TargetList []*enode.Node

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	PakcetSeed []discv4.Packet // Use store packet seed to mutator

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

type v4packetTestResult struct {
	PacketID     int
	RequestType  string
	Check        bool
	CheckResults []bool
	Success      bool
	Request      discv4.Packet
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
		Client:     cli,
		TargetList: nodeList,
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
func (m *V4Maker) PacketStart(traceOutput io.Writer, seed discv4.Packet, stats *UDPPacketStats) error {
	var (
		wg      sync.WaitGroup
		logger  *log.Logger
		mu      sync.Mutex
		results []v4packetTestResult
		// foundNewSeed bool
	)

	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Authentication ping
	ping := m.Client.GenPacket("ping", m.TargetList[0])
	result := sendAndWaitResponse(m, m.TargetList[0], ping, true, logger)
	if result.Error != nil {
		fmt.Printf("%s", result.Error)
	}

	mutator := fuzzing.NewMutator(rand.New(rand.NewSource(time.Now().UnixNano())))
	currentSeed := seed

	for i := 0; i < MutateCount; i++ {
		wg.Add(1)

		mutateSeed := cloneAndMutateV4Packet(mutator, currentSeed)

		go func(iteration int, packetSeed discv4.Packet, packetStats *UDPPacketStats) {
			defer wg.Done()

			result := sendAndWaitResponse(m, m.TargetList[0], packetSeed, false, logger)
			result.CheckResults = m.checkRequestSemantics(packetSeed)
			result.Check = allTrue(result.CheckResults)
			result.PacketID = i
			result.Request = packetSeed

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
		logger.Printf("================================================= Completed iteration %d =================================================", i+1)
		time.Sleep(PacketSleepTime)
	}

	wg.Wait()

	// Only analyze and save results if we found new seeds
	if SaveFlag {
		analyzeResults(results, logger, OutputDir)
	}

	return nil
}

func (m *V4Maker) Start(traceOutput io.Writer) error {
	var (
		wg       sync.WaitGroup
		resultCh = make(chan *v4result, len(m.TargetList))
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
			result := &v4result{
				n: target,
			}
			// First round: sending testSeq packets
			for _, packetType := range m.testSeq {
				req := m.Client.GenPacket(packetType, target)
				m.Client.Send(target, req)
				logger.Printf("Sent test packet to target: %s, packet: %v", target.String(), req.Kind())
			}

			// Round 2: sending stateSeq packets
			for _, packetType := range m.stateSeq {
				req := m.Client.GenPacket(packetType, target)
				// Set the expected response type based on the packet type
				rm := m.Client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool, shouldComplete bool) {
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
				_ = m.Client.Send(target, req)

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
	if m.Client != nil {
		m.Client.Close()
	}
}

func (m *V4Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func processPacket(packet discv4.Packet) byte {
	switch packet.Kind() {
	case discv4.PingPacket:
		// fmt.Println("Send ping packet, expecting pong response")
		return discv4.PongPacket
	case discv4.FindnodePacket:
		// fmt.Println("Send findnode packet, expecting neighbors response")
		return discv4.NeighborsPacket
	case discv4.ENRRequestPacket:
		// fmt.Println("Send ENR request packet, expecting ENR response")
		return discv4.ENRResponsePacket
	case discv4.PongPacket:
		// fmt.Println("Send pong packet, no pending required")
		return NoPendingRequired
	case discv4.NeighborsPacket:
		// fmt.Println("Send neighbors packet, no pending required")
		return NoPendingRequired
	case discv4.ENRResponsePacket:
		// fmt.Println("Send ENR response, no pending required")
		return NoPendingRequired
	default:
		// fmt.Printf("Unknown packet type: %v\n", packet.Kind())
		return NoPendingRequired
	}
}

func generateV4TestSeq() []string {

	seq := make([]string, SequenceLength)

	seq[0] = "ping"

	rand.Seed(time.Now().UnixNano())
	for i := 1; i < SequenceLength; i++ {
		seq[i] = v4options[rand.Intn(len(v4options))]
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
	if !p.From.IP.Equal(m.Client.Self().IP()) {
		validityResults = append(validityResults, false) // Mark source IP check as failed
	} else {
		validityResults = append(validityResults, true) // Mark source IP check as success
	}

	// 3. Check if the target IP matches the first target in the list
	if !p.To.IP.Equal(m.TargetList[0].IP()) {
		validityResults = append(validityResults, false) // Mark target IP check as failed
	} else {
		validityResults = append(validityResults, true) // Mark target IP check as success
	}

	// 4. Check if the ENRSeq matches the client's ENRSeq
	if p.ENRSeq != m.Client.Self().Seq() {
		// fmt.Println("Ping ENRSeq does not match the client's ENRSeq")
		validityResults = append(validityResults, false) // Mark expiration check as failed
	} else {
		validityResults = append(validityResults, true) // Mark expiration check as success
	}

	// 5. Check if the expiration time is valid
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
func sendAndWaitResponse(m *V4Maker, target *enode.Node, req discv4.Packet, handshake bool, logger *log.Logger) v4packetTestResult {
	result := v4packetTestResult{
		RequestType: req.Name(),
	}

	// Set the expected response type based on the packet type
	rm := m.Client.Pending(target.ID(), target.IP(), processPacket(req), func(p discv4.Packet) (matched bool, requestDone bool, shouldComplete bool) {
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

	// Add mutate packet head
	if handshake {
		_ = m.Client.Send(target, req)
	} else {
		_ = m.Client.MutateSend(target, req)
	}

	// Record send log info
	logger.Printf("Send Packet: %s\n", req.Name())
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

func analyzeResults(results []v4packetTestResult, logger *log.Logger, outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fullPath := filepath.Join(outputDir, "discv4")
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create discv4 directory: %v", err)
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

// cloneAndMutateV4Packet clones and mutates the packet
func cloneAndMutateV4Packet(mutator *fuzzing.Mutator, seed discv4.Packet) discv4.Packet {
	switch p := seed.(type) {
	case *discv4.Ping:
		return mutatePing(mutator, p)
	case *discv4.Pong:
		return mutatePong(mutator, p)
	case *discv4.Findnode:
		return mutateFindnode(mutator, p)
	case *discv4.Neighbors:
		return mutateNeighbors(mutator, p)
	case *discv4.ENRRequest:
		return mutateENRRequest(mutator, p)
	case *discv4.ENRResponse:
		return mutateENRResponse(mutator, p)
	default:
		return seed
	}
}

// Mutation functions for different packet types
func mutatePing(mutator *fuzzing.Mutator, original *discv4.Ping) *discv4.Ping {
	mutated := *original // Create a copy

	// Mutate fields
	mutator.MutateExp(&mutated.Expiration)
	mutator.MutateRest(&mutated.Rest)

	// Randomly mutate other fields
	if rand.Float32() < 0.3 { // 30% chance to mutate Version
		mutated.Version = uint(rand.Uint32())
	}
	if rand.Float32() < 0.3 { // 30% chance to mutate ENRSeq
		mutated.ENRSeq = uint64(rand.Uint32())
	}

	return &mutated
}

func mutatePong(mutator *fuzzing.Mutator, original *discv4.Pong) *discv4.Pong {
	mutated := *original

	mutator.MutateExp(&mutated.Expiration)
	mutator.MutateRest(&mutated.Rest)

	if rand.Float32() < 0.3 {
		mutator.MutateBytes(&mutated.ReplyTok)
	}
	if rand.Float32() < 0.3 {
		mutated.ENRSeq = uint64(rand.Uint32())
	}

	return &mutated
}

func mutateFindnode(mutator *fuzzing.Mutator, original *discv4.Findnode) *discv4.Findnode {
	mutated := *original

	mutator.MutateExp(&mutated.Expiration)
	mutator.MutateRest(&mutated.Rest)

	if rand.Float32() < 0.3 {
		var newTarget discv4.Pubkey
		mutator.FillBytes((*[]byte)(unsafe.Pointer(&newTarget)))
		mutated.Target = newTarget
	}

	return &mutated
}

func mutateNeighbors(mutator *fuzzing.Mutator, original *discv4.Neighbors) *discv4.Neighbors {
	mutated := *original

	mutator.MutateExp(&mutated.Expiration)
	mutator.MutateRest(&mutated.Rest)

	// Mutate node list
	if rand.Float32() < 0.3 {
		// Randomly remove nodes
		if len(mutated.Nodes) > 0 {
			index := rand.Intn(len(mutated.Nodes))
			mutated.Nodes = append(mutated.Nodes[:index], mutated.Nodes[index+1:]...)
		}
	}

	// Randomly add or modify nodes
	if rand.Float32() < 0.3 {
		newNode := discv4.Node{
			IP:  net.IPv4(byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))),
			UDP: uint16(rand.Intn(65536)),
			TCP: uint16(rand.Intn(65536)),
		}
		mutator.FillBytes((*[]byte)(unsafe.Pointer(&newNode.ID)))
		mutated.Nodes = append(mutated.Nodes, newNode)
	}

	return &mutated
}

func mutateENRRequest(mutator *fuzzing.Mutator, original *discv4.ENRRequest) *discv4.ENRRequest {
	mutated := *original

	mutator.MutateExp(&mutated.Expiration)
	mutator.MutateRest(&mutated.Rest)

	return &mutated
}

func mutateENRResponse(mutator *fuzzing.Mutator, original *discv4.ENRResponse) *discv4.ENRResponse {
	mutated := *original

	mutator.MutateRest(&mutated.Rest)

	// Mutate ReplyTok
	if rand.Float32() < 0.3 {
		mutator.MutateBytes(&mutated.ReplyTok)
	}

	return &mutated
}
