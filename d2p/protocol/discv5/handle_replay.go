package discv5

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/d2p"
)

// Errors
var (
	errTimeout = errors.New("RPC timeout")
	errClosed  = errors.New("socket closed")
)

func (t *UDPv5) handlePacket(rawpacket []byte, fromAddr *net.UDPAddr) error {
	fmt.Printf("\nStep 1: Starting handlePacket for addr: %s\n", fromAddr.String())

	addr := fromAddr.String()
	fromID, _, packet, err := t.codec.Decode(rawpacket, addr)
	if err != nil {

		fmt.Printf("Step 2: Decode failed with error: %v\n", err)
		if t.unhandled != nil && v5wire.IsInvalidHeader(err) {

			fmt.Printf("Step 2.1: Forwarding unhandled packet\n")
			up := d2p.ReadPacket{Data: make([]byte, len(rawpacket)), Addr: fromAddr}
			copy(up.Data, rawpacket)
			t.unhandled <- up
			return nil
		}
		t.log.Debug("Bad discv5 packet", "id", fromID, "addr", addr, "err", err)
		return err
	}

	fmt.Printf("Step 2: Successfully decoded packet type: %s\n", packet.Name())

	if packet.Kind() != v5wire.WhoareyouPacket {

		fmt.Printf("Step 3: Processing non-WHOAREYOU packet\n")
		t.logcontext = append(t.logcontext[:0], "id", fromID, "addr", addr)
		t.logcontext = packet.AppendLogInfo(t.logcontext)
		t.log.Trace("<< "+packet.Name(), t.logcontext...)
	} else {

		fmt.Printf("Step 3: Processing WHOAREYOU packet\n")
	}

	fmt.Printf("Step 4: Calling handle() for packet type: %s\n", packet.Name())
	t.handle(packet, fromID, fromAddr)
	return nil
}

func (t *UDPv5) handle(p Packet, fromID enode.ID, fromAddr *net.UDPAddr) {
	fmt.Printf("\nStep 5: handle() started for packet type: %s\n", p.Name())
	fmt.Printf("From ID: %v\n", fromID)
	fmt.Printf("From Address: %v\n", fromAddr)

	switch p := p.(type) {
	case *Unknown:
		fmt.Printf("Step 6: Handling Unknown packet\n")
		t.handleUnknown(p, fromID, fromAddr)
	case *Whoareyou:
		fmt.Printf("Step 6: Handling Whoareyou packet\n")
		t.handleWhoareyou(p, fromID, fromAddr)
	case *Ping:
		fmt.Printf("Step 6: Handling Ping packet\n")
		t.handlePing(p, fromID, fromAddr)
	case *Pong:
		fmt.Printf("Step 6: Handling Pong packet\n")
		t.handleCallResponse(fromID, fromAddr, p)
	case *Findnode:
		fmt.Printf("Step 6: Handling Findnode packet\n")
		t.handleFindnode(p, fromID, fromAddr)
	case *Nodes:
		fmt.Printf("Step 6: Handling Nodes packet\n")
		t.handleCallResponse(fromID, fromAddr, p)
	case *TalkRequest:
		fmt.Printf("Step 6: Handling TalkRequest packet\n")
		t.talk.handleRequest(fromID, fromAddr, p)
	case *TalkResponse:
		fmt.Printf("Step 6: Handling TalkResponse packet\n")
		t.handleCallResponse(fromID, fromAddr, p)
	}
}

// callToNode sends the given call and sets up a handler for response packets (of message
// type responseType). Responses are dispatched to the call's response channel.
func (t *UDPv5) CallToNode(n *enode.Node, responseType byte, req Packet) *callV5 {
	// 首先打印输入参数的信息，确认我们收到的数据是否正确
	fmt.Printf("Creating call to node:\n")
	fmt.Printf("  Node ID (raw bytes): %x\n", n.ID().Bytes()) // 使用 %x 打印原始字节
	fmt.Printf("  Complete node record: %s\n", n.String())    // 打印完整的节点信息供参考
	fmt.Printf("  ID length: %d bytes\n", len(n.ID()))        // 验证 ID 长度是否正确（应该是32字节）

	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}

	c := &callV5{id: n.ID(), addr: addr, node: n}

	// 初始化调用
	t.initCall(c, responseType, req)

	return c
}

// callToID is like callToNode, but for cases where the node record is not available.
func (t *UDPv5) callToID(id enode.ID, addr *net.UDPAddr, responseType byte, req Packet) *callV5 {
	c := &callV5{id: id, addr: addr}
	t.initCall(c, responseType, req)
	return c
}

func (t *UDPv5) initCall(c *callV5, responseType byte, packet Packet) {
	c.packet = packet
	c.responseType = responseType
	c.reqid = make([]byte, 8)
	c.ch = make(chan Packet, 1)
	c.err = make(chan error, 1)
	// Assign request ID.
	crand.Read(c.reqid)
	packet.SetRequestID(c.reqid)
	// Send call to dispatch.
	select {
	case t.callCh <- c:
	case <-t.closeCtx.Done():
		c.err <- errClosed
	}
}

// callDone tells dispatch that the active call is done.
func (t *UDPv5) CallDone(c *callV5) {
	// This needs a loop because further responses may be incoming until the
	// scent to callDoneCh has completed. Such responses need to be discarded
	// in order to avoid blocking the dispatch loop.
	for {
		select {
		case <-c.ch:
			// late response, discard.
		case <-c.err:
			// late error, discard.
		case t.callDoneCh <- c:
			return
		case <-t.closeCtx.Done():
			return
		}
	}
}

// send a packet to the given node.
func (t *UDPv5) send(toID enode.ID, toAddr *net.UDPAddr, packet Packet, c *Whoareyou) (Nonce, error) {
	// 记录发送前的信息
	fmt.Printf("\nPreparing to send %s packet:\n", packet.Name())
	// 添加调试信息来验证 ID 的格式
	fmt.Printf("Raw node ID bytes: %x\n", toID[:])
	fmt.Printf("Target Address: %s\n", toAddr.String())
	// 如果是认证包，打印认证信息
	if c != nil {
		fmt.Printf("Authentication info:\n")
		fmt.Printf("  Challenge Nonce: %x\n", c.Nonce)
		fmt.Printf("  ID Nonce: %x\n", c.IDNonce)
		fmt.Printf("  Record Seq: %d\n", c.RecordSeq)
		if c.Node != nil {
			fmt.Printf("  Node Record: %s\n", c.Node.String())
		}
	} else {
		fmt.Printf("No authentication challenge (initial packet)\n")
	}

	addr := toAddr.String()
	t.logcontext = append(t.logcontext[:0], "id", toID, "addr", addr)
	t.logcontext = packet.AppendLogInfo(t.logcontext)

	enc, nonce, err := t.codec.Encode(toID, addr, packet, c)
	if err != nil {
		fmt.Printf("Encoding failed: %v\n", err)
		t.logcontext = append(t.logcontext, "err", err)
		t.log.Warn(">> "+packet.Name(), t.logcontext...)
		return nonce, err
	}

	fmt.Printf("Encoding successful:\n")
	fmt.Printf("  Packet length: %d bytes\n", len(enc))
	fmt.Printf("  Generated nonce: %x\n", nonce)

	_, err = t.conn.WriteToUDP(enc, toAddr)

	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
	} else {
		fmt.Printf("Packet sent successfully\n")
	}

	t.log.Trace(">> "+packet.Name(), t.logcontext...)
	return nonce, err
}

// sendResponse sends a response packet to the given node.
// This doesn't trigger a handshake even if no keys are available.
func (t *UDPv5) sendResponse(toID enode.ID, toAddr *net.UDPAddr, packet Packet) error {
	_, err := t.send(toID, toAddr, packet, nil)
	return err
}

// startResponseTimeout sets the response timer for a call.
func (t *UDPv5) startResponseTimeout(c *callV5) {
	if c.timeout != nil {
		c.timeout.Stop()
	}
	var (
		timer mclock.Timer
		done  = make(chan struct{})
	)
	timer = t.clock.AfterFunc(respTimeoutV5, func() {
		<-done
		select {
		case t.respTimeoutCh <- &callTimeout{c, timer}:
		case <-t.closeCtx.Done():
		}
	})
	c.timeout = timer
	close(done)
}

// sendCall encodes and sends a request packet to the call's recipient node.
// This performs a handshake if needed.
func (t *UDPv5) sendCall(c *callV5) {
	// 删除旧的 nonce 映射
	if c.nonce != (Nonce{}) {
		delete(t.activeCallByAuth, c.nonce)
	}

	// 添加调试信息，但要先检查 challenge 是否存在
	fmt.Printf("Preparing authenticated call:\n")
	fmt.Printf("Node record: %+v\n", c.node)
	if c.challenge != nil {
		fmt.Printf("Challenge IDNonce: %x\n", c.challenge.IDNonce)
	} else {
		fmt.Printf("No challenge present (initial call)\n")
	}

	// 发送包并处理响应
	newNonce, _ := t.send(c.id, c.addr, c.packet, c.challenge)
	c.nonce = newNonce
	t.activeCallByAuth[newNonce] = c
	t.startResponseTimeout(c)

	// 添加发送后的调试信息
	fmt.Printf("Sent authenticated call with nonce: %x\n", newNonce)
}

// sendNextCall sends the next call in the call queue if there is no active call.
func (t *UDPv5) sendNextCall(id enode.ID) {
	queue := t.callQueue[id]
	if len(queue) == 0 || t.activeCallByNode[id] != nil {
		return
	}
	t.activeCallByNode[id] = queue[0]
	t.sendCall(t.activeCallByNode[id])
	if len(queue) == 1 {
		delete(t.callQueue, id)
	} else {
		copy(queue, queue[1:])
		t.callQueue[id] = queue[:len(queue)-1]
	}
}

// handleCallResponse dispatches a response packet to the call waiting for it.
func (t *UDPv5) handleCallResponse(fromID enode.ID, fromAddr *net.UDPAddr, p Packet) bool {
	ac := t.activeCallByNode[fromID]
	if ac == nil || !bytes.Equal(p.RequestID(), ac.reqid) {
		t.log.Debug(fmt.Sprintf("Unsolicited/late %s response", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if !fromAddr.IP.Equal(ac.addr.IP) || fromAddr.Port != ac.addr.Port {
		t.log.Debug(fmt.Sprintf("%s from wrong endpoint", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if p.Kind() != ac.responseType {
		t.log.Debug(fmt.Sprintf("Wrong discv5 response type %s", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	t.startResponseTimeout(ac)
	ac.ch <- p
	return true
}
