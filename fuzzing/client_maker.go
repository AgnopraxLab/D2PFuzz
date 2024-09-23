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
	"github.com/ethereum/go-ethereum/core/types"
	"io"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
)

const (
	// Encryption/authentication parameters.
	aesKeySize             = 16
	gcmNonceSize           = 12
	NoPendingRequired byte = 0
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
	for _, packet := range m.packets {
		if traceOutput != nil {
			fmt.Println(traceOutput, "Processing packet of type: %T\n", packet)
		}

		switch p := packet.(type) {
		case *eth.StatusPacket:
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

		case *eth.TransactionsPacket:
			// Nudge client out of syncing mode to accept pending txs.
			/*if err := m.client.SendForkchoiceUpdated(); err != nil {
				return fmt.Errorf("failed to send next block: %v", err)
			}*/
			if err := m.handleTransactionPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetBlockHeadersPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetBlockHeadersPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetBlockBodiesPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetBlockBodiesPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.NewBlockHashesPacket, *eth.BlockHeadersPacket, *eth.BlockBodiesPacket, *eth.NewBlockPacket, *eth.PooledTransactionsPacket, *eth.ReceiptsPacket:
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleSendOnlyPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.NewPooledTransactionHashesPacket:
			/*if err := m.client.SendForkchoiceUpdated(); err != nil {
				return fmt.Errorf("failed to send next block: %v", err)
			}*/
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}
			if err := m.handlePooledTransactionHashesPacket(p, traceOutput); err != nil {
				return err
			}

		case *eth.GetPooledTransactionsPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetPooledTransactionsPacket(p, traceOutput); err != nil {
				return err
			}
		case *eth.GetReceiptsPacket:
			// 初始化连接
			if err := m.client.InitializeAndConnect(); err != nil {
				return fmt.Errorf("initialization and connection failed: %v", err)
			}

			if err := m.handleGetReceiptsPacket(p, traceOutput); err != nil {
				return err
			}
		// Add other packet types here as needed
		// case *eth.GetBlockBodiesPacket:
		//     if err := m.handleGetBlockBodiesPacket(p, traceOutput); err != nil {
		//         return err
		//     }
		// case *eth.GetReceiptsPacket:
		//     if err := m.handleGetReceiptsPacket(p, traceOutput); err != nil {
		//         return err
		//     }
		default:
			if traceOutput != nil {
				fmt.Println(traceOutput, "Unsupported packet type: %T\n", packet)
			}
		}

		// Sleep between packet processing to avoid overwhelming the network
		time.Sleep(time.Millisecond * 100)
	}

	return nil
}
func (m *EthMaker) handleSendOnlyPacket(packet interface{}, traceOutput io.Writer) error {
	var msgcode uint64

	switch packet.(type) {
	case *eth.NewBlockHashesPacket:
		msgcode = eth.NewBlockHashesMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending NewBlockHashesPacket")
		}
	case *eth.BlockHeadersPacket:
		msgcode = eth.BlockHeadersMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending BlockHeadersPacket")
		}
	case *eth.BlockBodiesPacket:
		msgcode = eth.BlockBodiesMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending BlockBodiesPacket")
		}
	case *eth.NewBlockPacket:
		msgcode = eth.NewBlockMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending NewBlockPacket")
		}
	case *eth.PooledTransactionsPacket:
		msgcode = eth.PooledTransactionsMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending PooledTransactionsPacket")
		}
	case *eth.ReceiptsPacket:
		msgcode = eth.ReceiptsMsg
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending ReceiptsPacket")
		}
	default:
		return fmt.Errorf("unsupported packet type: %T", packet)
	}

	if err := m.client.SendMsg(eth.EthProto, msgcode, packet); err != nil {
		return fmt.Errorf("could not send %T: %v", packet, err)
	}

	return nil
}

func (m *EthMaker) handleTransactionPacket(p *eth.TransactionsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending transaction")
	}
	for i, tx := range *p {
		if traceOutput != nil {
			fmt.Println(traceOutput, "Sending transaction %d\n", i+1)
		}

		if err := m.client.SendTxs([]*types.Transaction{tx}); err != nil {
			return fmt.Errorf("failed to send transaction: %v", err)
		}

		if traceOutput != nil {
			fmt.Println(traceOutput, "Transaction %d sent successfully\n", i+1)
		}
	}
	return nil
}

func (m *EthMaker) handleGetBlockHeadersPacket(p *eth.GetBlockHeadersPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockHeadersPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetBlockHeadersMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockHeadersMsg: %v", err)
	}

	headers := new(eth.BlockHeadersPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.BlockHeadersMsg, headers); err != nil {
		return fmt.Errorf("error reading BlockHeadersMsg: %v", err)
	}

	if got, want := headers.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id: got %d, want %d", headers.RequestId, p.RequestId)
	}

	expected, err := m.client.GetHeaders(p)
	if err != nil {
		return fmt.Errorf("failed to get headers for given request: %v", err)
	}

	if !eth.HeadersMatch(expected, headers.BlockHeadersRequest) {
		return fmt.Errorf("header mismatch")
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received headers for request %d\n", headers.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetBlockBodiesPacket(p *eth.GetBlockBodiesPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetBlockBodiesPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetBlockBodiesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.BlockBodiesPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.BlockBodiesMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.BlockBodiesResponse
	if len(bodies) != len(p.GetBlockBodiesRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetBlockBodiesRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handlePooledTransactionHashesPacket(p *eth.NewPooledTransactionHashesPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending NewPooledTransactionHashesPacket")
	}

	if err := m.client.SendMsg(eth.EthProto, eth.NewPooledTransactionHashesMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.GetPooledTransactionsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.GetPooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := len(resp.GetPooledTransactionsRequest), len(p.Hashes); got != want {
		return fmt.Errorf("unexpected number of txs requested: got %d, want %d", got, want)
	}
	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetPooledTransactionsPacket(p *eth.GetPooledTransactionsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetPooledTransactionsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.PooledTransactionsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.PooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.PooledTransactionsResponse
	if len(bodies) != len(p.GetPooledTransactionsRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetPooledTransactionsRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) handleGetReceiptsPacket(p *eth.GetReceiptsPacket, traceOutput io.Writer) error {
	if traceOutput != nil {
		fmt.Println(traceOutput, "Sending GetPooledTransactionsPacket with RequestId: %d\n", p.RequestId)
	}

	if err := m.client.SendMsg(eth.EthProto, eth.GetReceiptsMsg, p); err != nil {
		return fmt.Errorf("could not send GetBlockBodiesMsg: %v", err)
	}

	resp := new(eth.ReceiptsPacket)
	if err := m.client.ReadMsg(eth.EthProto, eth.ReceiptsMsg, resp); err != nil {
		return fmt.Errorf("error reading BlockBodiesMsg: %v", err)
	}

	if got, want := resp.RequestId, p.RequestId; got != want {
		return fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	bodies := resp.ReceiptsResponse
	if len(bodies) != len(p.GetReceiptsRequest) {
		return fmt.Errorf("wrong bodies in response: expected %d bodies, got %d", len(p.GetReceiptsRequest), len(bodies))
	}

	if traceOutput != nil {
		fmt.Println(traceOutput, "Received block bodies for request %d\n", resp.RequestId)
	}

	return nil
}

func (m *EthMaker) SetResult(root, logs common.Hash) {
	m.root = root
	m.logs = logs
}
