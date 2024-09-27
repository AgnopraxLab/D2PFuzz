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
	"crypto/rand"
	"encoding/json"
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

func Initeth(dest *enode.Node, dir string) (*eth.Suite, error) {
	jwtPath, secret, err := eth.MakeJWTSecret()
	if err != nil {
		fmt.Printf("could not make jwt secret: %v", err)
	}
	geth, err := eth.RunGeth("./testdata", jwtPath)
	if err != nil {
		fmt.Printf("could not run geth: %v", err)
	}
	defer geth.Close()

	pri, _ := crypto.GenerateKey()
	client, err := eth.NewSuite(dest, dir, pri, geth.HTTPAuthEndpoint(), common.Bytes2Hex(secret[:]))
	if err != nil {
		return nil, fmt.Errorf("new suite fail")
	}

	return client, nil
}

func RunGenerate(protocol, target, ptype string) error {
	// Parse the target into an enode
	node, err := enode.ParseV4(target)
	if err != nil {
		return fmt.Errorf("failed to parse target node: %v", err)
	}
	bytes := make([]byte, 1000)
	rand.Read(bytes)
	f := filler.NewFiller(bytes)

	switch protocol {
	case "discv4":
		client := InitDiscv4()
		packet := client.GenPacket(f, ptype, node)
		jsonData, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("error encoding JSON")
		}
		fmt.Println(string(jsonData))
	case "discv5":
		client := InitDiscv5()
		packet := client.GenPacket(f, ptype, node)
		jsonData, err := json.Marshal(packet)
		if err != nil {
			return fmt.Errorf("error encoding JSON")
		}
		fmt.Println(string(jsonData))
	case "eth":
		return nil
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
	return nil
}
