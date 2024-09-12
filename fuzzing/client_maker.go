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
	"io"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"D2PFuzz/d2p/protocol/discv4"
	"D2PFuzz/d2p/protocol/discv5"
	"D2PFuzz/d2p/protocol/eth"
)

const (
	// Encryption/authentication parameters.
	aesKeySize   = 16
	gcmNonceSize = 12
)

// Maker await a decision
type Maker interface {
}

type V4Maker struct {
	client  *discv4.UDPv4
	packets []discv4.Packet
	target  *enode.Node
	Series  []StateSeries
	forks   []string
	root    common.Hash
	logs    common.Hash
}

type V5Maker struct {
	client  *discv5.UDPv5
	packets []discv5.Packet
	target  *enode.Node
	Series  []StateSeries
	forks   []string
	root    common.Hash
	logs    common.Hash
}

type EthMaker struct {
	client  *eth.Suite
	packets []eth.Packet
	target  *enode.Node
	Series  []StateSeries
	forks   []string
	root    common.Hash
	logs    common.Hash
}

type Nonce [gcmNonceSize]byte

type StateSeries struct {
	Type  string
	Nonce Nonce
	State int
}

func NewV4Maker(cli *discv4.UDPv4, n *enode.Node, p []discv4.Packet) *V4Maker {
	v4maker := &V4Maker{
		client:  cli,
		packets: p,
		target:  n,
	}
	return v4maker
}

func NewV5Maker(cli *discv5.UDPv5, n *enode.Node, p []discv5.Packet) *V5Maker {
	v5maker := &V5Maker{
		client:  cli,
		packets: p,
		target:  n,
	}
	return v5maker
}

func NewEthMaker(cli *eth.Suite, n *enode.Node, p []eth.Packet) *EthMaker {
	ethmaker := &EthMaker{
		client:  cli,
		packets: p,
		target:  n,
	}
	return ethmaker
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

	return nil
}

func (m *V4Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
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
		m.client.Send(m.target, packet, nil)
	}

	return nil
}

func (m *V5Maker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}

func (m *EthMaker) ToGeneralStateTest(name string) *GeneralStateTest {
	gst := make(GeneralStateTest)
	gst[name] = m.ToSubTest()
	return &gst
}

func (m *EthMaker) ToSubTest() *stJSON {
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

func (m *EthMaker) Start(traceOutput io.Writer) error {

	return nil
}

func (m *EthMaker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}
