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
			stPostState{
				Logs:    m.logs,
				Root:    m.root,
				Indexes: stIndex{Gas: 0, Value: 0, Data: 0},
			},
		}
		st.Post = postState
	}
	return st
}

func (m *V4Maker) Start(traceOutput io.Writer) error {
	// init logger
	var logger *log.Logger
	if traceOutput != nil {
		logger = log.New(traceOutput, "TRACE: ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	// Send packet sequence
	for _, packet := range m.packets {
		// 根据数据包类型设置预期的响应类型
		var expectedResponseType byte
		expectedResponseType = processPacket(packet)
		if expectedResponseType != NoPendingRequired {

			// 设置回复匹配器
			rm := m.client.Pending(m.target.ID(), m.target.IP(), expectedResponseType, func(p discv4.Packet) (matched bool, requestDone bool) {
				fmt.Printf("Received packet of type: %T\n", p)
				if pong, ok := p.(*discv4.Pong); ok {
					fmt.Printf("Received Pong response: %+v\n", pong)
					return true, true
				}
				if neighbors, ok := p.(*discv4.Neighbors); ok {
					fmt.Printf("Received Neighbors response: %+v\n", neighbors)
					return true, true
				}
				if ENRresponse, ok := p.(*discv4.ENRResponse); ok {
					fmt.Printf("Received ENR response: %+v\n", ENRresponse)
					return true, true
				}
				return false, false
			})

			if err := m.client.Send(m.target, packet); err != nil {
				if logger != nil {
					logger.Printf("Failed to send packet: %v", err)
				}
			}
			// Record send log info
			if logger != nil {
				logger.Printf("Sent packet to target: %s, packet: %v", m.target.String(), packet.Kind())
			}

			// 使用新的 WaitForResponse 方法等待响应
			if err := rm.WaitForResponse(5 * time.Second); err != nil {
				if logger != nil {
					logger.Printf("Timeout waiting for response")
				}
			}
		} else {
			if err := m.client.Send(m.target, packet); err != nil {
				if logger != nil {
					logger.Printf("Failed to send packet: %v", err)
				}
			}
			// Record send log info
			if logger != nil {
				logger.Printf("Sent packet to target: %s, packet: %v", m.target.String(), packet.Kind())
			}
		}
		time.Sleep(time.Second)
	}

	return nil
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
