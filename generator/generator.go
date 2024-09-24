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
	"errors"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"

	"github.com/AgnopraxLab/D2PFuzz/d2p"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv4"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/discv5"
	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
)

func GenerateV4Packet(f *filler.Filler, target string) *fuzzing.V4Maker {
	var (
		node    *enode.Node
		cli     *discv4.UDPv4
		packets []discv4.Packet
		series  []string
	)

	node, _ = getNode(target)
	cli = initDiscv4()

	// TODO: init oracle and series

	// Generate a sequence of Packets
	for _, i := range series {
		packet := cli.GenPacket(f, i, node)
		packets = append(packets, packet)
	}

	v4maker := fuzzing.NewV4Maker(cli, node, packets)
	return v4maker
}

func GenerateV5Packet(f *filler.Filler, target string) *fuzzing.V5Maker {
	var (
		node    *enode.Node
		cli     *discv5.UDPv5
		packets []discv5.Packet
		series  []string
	)

	node, _ = getNode(target)
	cli = initDiscv5()

	// TODO: init oracle and series

	// Generate a sequence of Packets
	for _, i := range series {
		packet := cli.GenPacket(f, i, node)
		packets = append(packets, packet)
	}

	v5maker := fuzzing.NewV5Maker(cli, node, packets)
	return v5maker
}

func GenerateEthPacket(f *filler.Filler, target, chain string) *fuzzing.EthMaker {
	var (
		node    *enode.Node
		cli     *eth.Suite
		packets []eth.Packet
		series  []int
	)

	node, _ = getNode(target)
	cli, err := initeth(node, chain)
	if err != nil {
		fmt.Printf("failed to initialize eth clients: %v", err)
	}

	// TODO: init oracle and series
	state := eth.InitOracleState(cli)

	// Generate a sequence of Packets
	spec := &eth.PacketSpecification{
		BlockNumbers: []int{10, 20, 30},
		BlockHashes:  make([]common.Hash, 3),
	}
	for i := 0; i < 3; i++ {
		hash := crypto.Keccak256([]byte(fmt.Sprintf("hash%d", i)))
		spec.BlockHashes[i] = common.BytesToHash(hash[:])
	}
	for _, packetType := range series {
		packet, err := cli.GenPacket(f, packetType, spec)
		if err != nil {
			fmt.Println("GenPacket fail")
		}
		// Checking and Correcting Packets with Oracle
		checkedPacket, err := eth.OracleCheck(packet, state, cli)
		if err != nil {
			fmt.Println("oracle check fail")
		}
		state.PacketHistory = append(state.PacketHistory, checkedPacket)
		packets = append(packets, packet)
	}

	ethmaker := fuzzing.NewEthMaker(cli, node, packets)
	return ethmaker
}

func initDiscv4() *discv4.UDPv4 {
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

func initDiscv5() *discv5.UDPv5 {
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
	ln.Set(enr.IP(ip))
	ln.Set(enr.UDP(uint16(port)))
	client, _ := discv5.ListenV5(udpConn, ln, cfg)

	return client
}

func initeth(dest *enode.Node, dir string) (*eth.Suite, error) {

	pri, _ := crypto.GenerateKey()
	client, err := eth.NewSuite(dest, dir, pri, "", "")
	if err != nil {
		return nil, errors.New("new Suite fail")
	}

	// return client, nil
	return client, nil
}
