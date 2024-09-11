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
	"fmt"
	"net"
	"strings"

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

func getNode(target string) (*enode.Node, error) {
	// Remove possible BOM and whitespace characters
	cleanContent := strings.TrimSpace(target)
	cleanContent = strings.TrimPrefix(cleanContent, "\uFEFF")

	if !strings.HasPrefix(cleanContent, "enr:") {
		return nil, fmt.Errorf("invalid ENR: missing 'enr:' prefix")
	}

	node, err := enode.Parse(enode.ValidSchemes, cleanContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enode: %v", err)
	}

	return node, nil
}
