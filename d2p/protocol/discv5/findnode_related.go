package discv5

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"

	"net"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	totalNodesResponseLimit = 5 // applies in waitForNodes
)

var (
	errLowPort = errors.New("low port")
)

// RequestENR requests n's record.
func (t *UDPv5) RequestENR(n *enode.Node) (*enode.Node, error) {
	nodes, err := t.sendfindnode(n, []uint{0})
	if err != nil {
		return nil, err
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("%d nodes in response for distance zero", len(nodes))
	}
	return nodes[0], nil
}

func (t *UDPv5) makeFindnode(distances []uint) *Findnode {
	return &Findnode{
		Distances: distances,
	}
}

// findnode calls FINDNODE on a node and waits for responses.
func (t *UDPv5) sendfindnode(n *enode.Node, distances []uint) ([]*enode.Node, error) {
	req := t.makeFindnode(distances)
	resp := t.callToNode(n, NodesMsg, req)
	return t.waitForNodes(resp, distances)
}

// waitForNodes waits for NODES responses to the given call.
func (t *UDPv5) waitForNodes(c *callV5, distances []uint) ([]*enode.Node, error) {
	defer t.callDone(c)

	var (
		nodes           []*enode.Node
		seen            = make(map[enode.ID]struct{})
		received, total = 0, -1
	)
	for {
		select {
		case responseP := <-c.ch:
			response := responseP.(*Nodes)
			for _, record := range response.Nodes {
				node, err := t.verifyResponseNode(c, record, distances, seen)
				if err != nil {
					t.log.Debug("Invalid record in "+response.Name(), "id", c.node.ID(), "err", err)
					continue
				}
				nodes = append(nodes, node)
			}
			if total == -1 {
				total = min(int(response.RespCount), totalNodesResponseLimit)
			}
			if received++; received == total {
				return nodes, nil
			}
		case err := <-c.err:
			return nodes, err
		}
	}
}

// verifyResponseNode checks validity of a record in a NODES response.
func (t *UDPv5) verifyResponseNode(c *callV5, r *enr.Record, distances []uint, seen map[enode.ID]struct{}) (*enode.Node, error) {
	node, err := enode.New(t.validSchemes, r)
	if err != nil {
		return nil, err
	}
	if err := netutil.CheckRelayIP(c.addr.IP, node.IP()); err != nil {
		return nil, err
	}
	if node.UDP() <= 1024 {
		return nil, errLowPort
	}
	if distances != nil {
		nd := enode.LogDist(c.id, node.ID())
		found := false
		for _, d := range distances {
			if d == uint(nd) {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("does not match any requested distance")
		}
	}
	if _, ok := seen[node.ID()]; ok {
		return nil, errors.New("duplicate record")
	}
	seen[node.ID()] = struct{}{}
	return node, nil
}

// handleFindnode returns nodes to the requester.
func (t *UDPv5) handleFindnode(p *Findnode, fromID enode.ID, fromAddr *net.UDPAddr) {
	nodes := t.collectTableNodes(fromAddr.IP, p.Distances, findnodeResultLimit)
	for _, resp := range packNodes(p.ReqID, nodes) {
		t.sendResponse(fromID, fromAddr, resp)
	}
}

// collectTableNodes creates a FINDNODE result set for the given distances.
func (t *UDPv5) collectTableNodes(rip net.IP, distances []uint, limit int) []*enode.Node {
	var nodes []*enode.Node
	var processed = make(map[uint]struct{})
	for _, dist := range distances {
		// Reject duplicate / invalid distances.
		_, seen := processed[dist]
		if seen || dist > 256 {
			continue
		}
		processed[dist] = struct{}{}

		// 为每个距离生成节点，直到达到限制
		for len(nodes) < limit {
			node := generateRandomNode(dist)
			// 检查中继 IP
			if netutil.CheckRelayIP(rip, node.IP()) == nil {
				nodes = append(nodes, node)
			}
		}

		// 如果已经达到限制，返回结果
		if len(nodes) >= limit {
			return nodes
		}
	}
	return nodes
}

func generateRandomNode(dist uint) *enode.Node {
	// 生成随机私钥
	privateKey, _ := ecdsa.GenerateKey(crypto.S256(), rand.Reader)

	// 生成随机 IP
	ip := make(net.IP, 4)
	rand.Read(ip)

	// 生成随机端口
	maxBig := big.NewInt(65535 - 1024)
	portBig, _ := rand.Int(rand.Reader, maxBig)
	port := uint16(portBig.Int64() + 1024)

	// 创建节点
	return enode.NewV4(&privateKey.PublicKey, ip, int(port), int(port))
}

// packNodes creates NODES response packets for the given node list.
func packNodes(reqid []byte, nodes []*enode.Node) []*Nodes {
	if len(nodes) == 0 {
		return []*Nodes{{ReqID: reqid, RespCount: 1}}
	}

	// This limit represents the available space for nodes in output packets. Maximum
	// packet size is 1280, and out of this ~80 bytes will be taken up by the packet
	// frame. So limiting to 1000 bytes here leaves 200 bytes for other fields of the
	// NODES message, which is a lot.
	const sizeLimit = 1000

	var resp []*Nodes
	for len(nodes) > 0 {
		p := &Nodes{ReqID: reqid}
		size := uint64(0)
		for len(nodes) > 0 {
			r := nodes[0].Record()
			if size += r.Size(); size > sizeLimit {
				break
			}
			p.Nodes = append(p.Nodes, r)
			nodes = nodes[1:]
		}
		resp = append(resp, p)
	}
	for _, msg := range resp {
		msg.RespCount = uint8(len(resp))
	}
	return resp
}
