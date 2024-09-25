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
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var (
	v5state = []string{"ping", "findnode"}
)

type V5Maker struct {
	client     *discv5.UDPv5
	targetList []*enode.Node
	filler     filler.Filler

	testSeq  []string // testcase sequence
	stateSeq []string // steate sequence

	Series []StateSeries
	forks  []string

	root common.Hash
	logs common.Hash
}

func NewV5Maker(f *filler.Filler, targetDir string) *V5Maker {
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

func (m *V5Maker) Start(traceOutput io.Writer) error {
	for _, packet := range m.packets {
		nonce, err := m.sendAndReceive(packet, traceOutput)
		if err != nil {
			return fmt.Errorf("failed to send and receive packet")
		}

		if traceOutput != nil {
			fmt.Println(traceOutput, "Sent packet, nonce: %x\n", nonce)
		}

		time.Sleep(time.Second) // Sleep between sends as in the original code
	}

	return nil
}

func (m *V5Maker) sendAndReceive(req discv5.Packet, traceOutput io.Writer) (discv5.Nonce, error) {
	const waitTime = 5 * time.Second

	nonce, err := m.client.Send(m.target, req, nil)
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
		nonce, err = m.client.Send(m.target, req, challenge)
		if err != nil {
			return nonce, fmt.Errorf("failed to send handshake: %v", err)
		}
		return m.sendAndReceive(req, traceOutput)
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
