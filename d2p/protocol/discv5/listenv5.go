package discv5

import (
	"D2PFuzz/d2p"
	"context"
	crand "crypto/rand"
	"errors"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"io"
	"net"
)

// ListenV5 listens on the given connection.
func ListenV5(conn d2p.UDPConn, ln *enode.LocalNode, cfg d2p.Config) (*UDPv5, error) {
	t, err := newUDPv5(conn, ln, cfg)
	if err != nil {
		return nil, err
	}
	t.wg.Add(2)
	go t.readLoop()
	go t.dispatch()
	return t, nil
}

// newUDPv5 creates a UDPv5 transport, but doesn't start any goroutines.
func newUDPv5(conn d2p.UDPConn, ln *enode.LocalNode, cfg d2p.Config) (*UDPv5, error) {
	closeCtx, cancelCloseCtx := context.WithCancel(context.Background())
	cfg = cfg.withDefaults()
	t := &UDPv5{
		// static fields
		conn:         newMeteredConn(conn),
		localNode:    ln,
		priv:         cfg.PrivateKey,
		log:          cfg.Log,
		validSchemes: cfg.ValidSchemes,
		clock:        cfg.Clock,
		// channels into dispatch
		packetInCh:    make(chan ReadPacket, 1),
		readNextCh:    make(chan struct{}, 1),
		callCh:        make(chan *callV5),
		callDoneCh:    make(chan *callV5),
		sendCh:        make(chan sendRequest),
		respTimeoutCh: make(chan *callTimeout),
		unhandled:     cfg.Unhandled,
		// state of dispatch
		codec:            v5wire.NewCodec(ln, cfg.PrivateKey, cfg.Clock, cfg.V5ProtocolID),
		activeCallByNode: make(map[enode.ID]*callV5),
		activeCallByAuth: make(map[v5wire.Nonce]*callV5),
		callQueue:        make(map[enode.ID][]*callV5),
		// shutdown
		closeCtx:       closeCtx,
		cancelCloseCtx: cancelCloseCtx,
	}
	t.talk = newTalkSystem(t)
	tab, err := newMeteredTable(t, t.db, cfg)
	if err != nil {
		return nil, err
	}
	t.tab = tab
	return t, nil
}


// Close shuts down packet processing.
func (t *UDPv5) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.talk.wait()
		t.wg.Wait()
		t.tab.close()
	})
}

// readLoop runs in its own goroutine and reads packets from the network.
func (t *UDPv5) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, maxPacketSize)
	for range t.readNextCh {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			t.log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permanent errors.
			if !errors.Is(err, io.EOF) {
				t.log.Debug("UDP read error", "err", err)
			}
			return
		}
		t.dispatchReadPacket(from, buf[:nbytes])
	}
}

// dispatch runs in its own goroutine, handles incoming packets and deals with calls.
//
// For any destination node there is at most one 'active call', stored in the t.activeCall*
// maps. A call is made active when it is sent. The active call can be answered by a
// matching response, in which case c.ch receives the response; or by timing out, in which case
// c.err receives the error. When the function that created the call signals the active
// call is done through callDone, the next call from the call queue is started.
//
// Calls may also be answered by a WHOAREYOU packet referencing the call packet's authTag.
// When that happens the call is simply re-sent to complete the handshake. We allow one
// handshake attempt per call.
func (t *UDPv5) dispatch() {
	defer t.wg.Done()

	// Arm first read.
	t.readNextCh <- struct{}{}

	for {
		select {
		case c := <-t.callCh:
			t.callQueue[c.id] = append(t.callQueue[c.id], c)
			t.sendNextCall(c.id)

		case ct := <-t.respTimeoutCh:
			active := t.activeCallByNode[ct.c.id]
			if ct.c == active && ct.timer == active.timeout {
				ct.c.err <- errTimeout
			}

		case c := <-t.callDoneCh:
			active := t.activeCallByNode[c.id]
			if active != c {
				panic("BUG: callDone for inactive call")
			}
			c.timeout.Stop()
			delete(t.activeCallByAuth, c.nonce)
			delete(t.activeCallByNode, c.id)
			t.sendNextCall(c.id)

		case r := <-t.sendCh:
			t.send(r.destID, r.destAddr, r.msg, nil)

		case p := <-t.packetInCh:
			t.handlePacket(p.Data, p.Addr)
			// Arm next read.
			t.readNextCh <- struct{}{}

		case <-t.closeCtx.Done():
			close(t.readNextCh)
			for id, queue := range t.callQueue {
				for _, c := range queue {
					c.err <- errClosed
				}
				delete(t.callQueue, id)
			}
			for id, c := range t.activeCallByNode {
				c.err <- errClosed
				delete(t.activeCallByNode, id)
				delete(t.activeCallByAuth, c.nonce)
			}
			return
		}
	}
}

// RegisterTalkHandler adds a handler for 'talk requests'. The handler function is called
// whenever a request for the given protocol is received and should return the response
// data or nil.
func (t *UDPv5) RegisterTalkHandler(protocol string, handler TalkRequestHandler) {
	t.talk.register(protocol, handler)
}

// TalkRequest sends a talk request to a node and waits for a response.
func (t *UDPv5) TalkRequest(n *enode.Node, protocol string, request []byte) ([]byte, error) {
	req := &v5wire.TalkRequest{Protocol: protocol, Message: request}
	resp := t.callToNode(n, v5wire.TalkResponseMsg, req)
	defer t.callDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*v5wire.TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// TalkRequestToID sends a talk request to a node and waits for a response.
func (t *UDPv5) TalkRequestToID(id enode.ID, addr *net.UDPAddr, protocol string, request []byte) ([]byte, error) {
	req := &v5wire.TalkRequest{Protocol: protocol, Message: request}
	resp := t.callToID(id, addr, v5wire.TalkResponseMsg, req)
	defer t.callDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*v5wire.TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// callToNode sends the given call and sets up a handler for response packets (of message
// type responseType). Responses are dispatched to the call's response channel.
func (t *UDPv5) callToNode(n *enode.Node, responseType byte, req Packet) *callV5 {
	addr := &net.UDPAddr{IP: n.IP(), Port: n.UDP()}
	c := &callV5{id: n.ID(), addr: addr, node: n}
	t.initCall(c, responseType, req)
	return c
}

func (t *UDPv5) initCall(c *callV5, responseType byte, packet Packet) {
	c.packet = packet
	c.responseType = responseType
	c.reqid = make([]byte, 8)
	c.ch = make(chan v5wire.Packet, 1)
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