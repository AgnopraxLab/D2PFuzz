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

// Package generator provides means to generate packet tests for Ethereum node.
package generator

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"golang.org/x/exp/rand"

	"github.com/AgnopraxLab/D2PFuzz/d2p"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
)

func InitDiscv4() *discv4.UDPv4 {
	cfg := d2p.Config{
		PrivateKey: d2p.GenKey(),
		Log:        log.Root(),
		Clock:      mclock.System{},
	}
	ip := getLocalIP()
	if ip == nil {
		fmt.Printf("failed to get local IP address")
	}
	// Select a randomly available port
	addr := &net.UDPAddr{IP: ip, Port: 0}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("failed to create UDP connection")
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	db, _ := enode.OpenDB("")
	nodeKey := d2p.GenKey()
	ln := enode.NewLocalNode(db, nodeKey)
	ln.Set(enr.IP(ip))
	ln.Set(enr.UDP(uint16(port)))
	client, _ := discv4.ListenV4(udpConn, ln, cfg)

	return client
}

func InitDiscv5() *discv5.UDPv5 {
	var (
		DefaultProtocolID = [6]byte{'d', 'i', 's', 'c', 'v', '5'}
	)

	cfg := d2p.Config{
		PrivateKey:   d2p.GenKey(),
		V5ProtocolID: &DefaultProtocolID,
		Log:          log.Root(),
		Clock:        mclock.System{},
	}
	ip := getLocalIP()
	actualIP := discv4.GetActualIP(ip)

	if ip == nil {
		fmt.Printf("failed to get local IP address for thread\n")
	}
	// Select a randomly available port
	addr := &net.UDPAddr{IP: ip, Port: 0}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("failed to create UDP connection for thread\n")
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	db, _ := enode.OpenDB("")
	ln := enode.NewLocalNode(db, cfg.PrivateKey)
	ln.Set(enr.IP(actualIP))
	ln.Set(enr.UDP(uint16(port)))
	client, _ := discv5.ListenV5(udpConn, ln, cfg)

	return client
}

func ReplaceNodeIP(n *enode.Node, newIP net.IP) *enode.Node {
	// Create a new node record while keeping all other information from the original node
	newNode := enode.NewV4(
		n.Pubkey(), // keep original public key
		newIP,      // use new IP
		n.UDP(),    // keep original UDP port
		n.TCP(),    // keep original TCP port
	)
	return newNode
}

func Initeth(dest *enode.Node, dir string) (*eth.Suite, error) {
	jwtPath, secret, err := eth.MakeJWTSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to make jwt secret: %v", err)
	}

	geth, err := eth.RunGeth(dir, jwtPath)
	if err != nil {
		return nil, fmt.Errorf("failed to run geth: %v", err)
	}

	// 创建一个用于清理资源的函数
	cleanup := func() {
		fmt.Println("clear sources")
		geth.Close()
	}

	// pri, err := crypto.GenerateKey()
	// if err != nil {
	// 	cleanup()
	// 	return nil, fmt.Errorf("failed to generate private key: %v", err)
	// }

	// Create Suite
	client, err := eth.NewSuite(dest, dir, geth.HTTPAuthEndpoint(), common.Bytes2Hex(secret[:]))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create suite: %v", err)
	}

	return client, nil
}

func RunGenerate(protocol, targetDir, chainDir, ptype string) error {
	// Parse the target into an enode
	nodeList, _ := getList(targetDir)
	node := nodeList[0]
	bytes := make([]byte, 1000)
	crand.Read(bytes)

	switch protocol {
	case "discv4":
		client := InitDiscv4()
		packet := client.GenPacket(ptype, node)
		jsonData, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("error encoding JSON")
		}
		fmt.Println(string(jsonData))
	case "discv5":
		client := InitDiscv5()
		packet := client.GenPacket(ptype, node)
		jsonData, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("error encoding JSON")
		}
		fmt.Println(string(jsonData))
	case "eth":
		client, err := Initeth(node, chainDir)
		if err != nil {
			return fmt.Errorf("error init eth client")
		}
		packetTypeInt := getEthPacketType(ptype)
		packet, err := client.GenPacket(packetTypeInt)
		if err != nil {
			return fmt.Errorf("error gen eth packet")
		}
		jsonData, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("error encoding JSON")
		}
		fmt.Println(string(jsonData))
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
	return nil
}

func getEthPacketType(packetType string) int {
	options := []int{
		eth.StatusMsg, eth.NewBlockHashesMsg, eth.TransactionsMsg, eth.GetBlockHeadersMsg,
		eth.BlockHeadersMsg, eth.GetBlockBodiesMsg, eth.BlockBodiesMsg, eth.NewBlockMsg,
		eth.NewPooledTransactionHashesMsg, eth.GetPooledTransactionsMsg, eth.PooledTransactionsMsg,
		eth.GetReceiptsMsg, eth.ReceiptsMsg,
	}
	switch packetType {
	case "Status":
		return eth.StatusMsg // 0x00-F
	case "NewBlockHashes":
		return eth.NewBlockHashesMsg // 0x01
	case "Transactions":
		return eth.TransactionsMsg // 0x02
	case "GetBlockHeaders":
		return eth.GetBlockHeadersMsg // 0x03-T
	case "BlockHeaders":
		return eth.BlockHeadersMsg // 0x04
	case "GetBlockBodies":
		return eth.GetBlockBodiesMsg // 0x05-T
	case "BlockBodies":
		return eth.BlockBodiesMsg // 0x06
	case "NewBlock":
		return eth.NewBlockMsg // 0x07
	case "NewPooledTransactionHashes":
		return eth.NewPooledTransactionHashesMsg // 0x08
	case "GetPooledTransactions":
		return eth.GetPooledTransactionsMsg // 0x09
	case "PooledTransactions":
		return eth.PooledTransactionsMsg // 0x0a
	case "GetReceipts":
		return eth.GetReceiptsMsg // 0x0f-T
	case "Receipts":
		return eth.ReceiptsMsg // 0x10
	case "random":
		return rand.Intn(len(options))
	default:
		return -1
	}
}
