// Copyright 2024 Fudong
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

package generator

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("failed to get local IP address: %v", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}
	return nil
}

func getList(fName string) ([]*enode.Node, error) {
	file, err := os.Open(fName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var nodeList []*enode.Node

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("\nParsing enode URL: %s\n", line)

		node := enode.MustParse(line)
		// 打印解析后的节点信息
		fmt.Printf("Node ID immediately after parsing: %x\n", node.ID().Bytes())
		// 将节点添加到列表前再次检查 ID
		fmt.Printf("Node ID before adding to list: %x\n", node.ID().Bytes())
		nodeList = append(nodeList, node)
	}

	// 检查第一个节点的 ID
	if len(nodeList) > 0 {
		fmt.Printf("First node ID in final list: %x\n", nodeList[0].ID().Bytes())
	}

	return nodeList, nil
}
