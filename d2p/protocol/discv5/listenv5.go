package discv5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"

	"github.com/AgnopraxLab/D2PFuzz/d2p"
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
	cfg = cfg.WithDefaults()
	t := &UDPv5{
		// static fields
		conn:         newMeteredConn(conn),
		localNode:    ln,
		priv:         cfg.PrivateKey,
		log:          cfg.Log,
		validSchemes: cfg.ValidSchemes,
		clock:        cfg.Clock,
		// channels into dispatch
		packetInCh:    make(chan d2p.ReadPacket, 1),
		readNextCh:    make(chan struct{}, 1),
		callCh:        make(chan *callV5),
		callDoneCh:    make(chan *callV5),
		sendCh:        make(chan sendRequest),
		respTimeoutCh: make(chan *callTimeout),
		unhandled:     cfg.Unhandled,
		// state of dispatch
		codec:            NewCodec(ln, cfg.PrivateKey, cfg.Clock, cfg.V5ProtocolID),
		activeCallByNode: make(map[enode.ID]*callV5),
		activeCallByAuth: make(map[Nonce]*callV5),
		callQueue:        make(map[enode.ID][]*callV5),
		// shutdown
		closeCtx:       closeCtx,
		cancelCloseCtx: cancelCloseCtx,
	}
	t.talk = newTalkSystem(t)
	return t, nil
}

// Close shuts down packet processing.
func (t *UDPv5) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.talk.wait()
		t.wg.Wait()
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

// dispatchReadPacket sends a packet into the dispatch loop.
func (t *UDPv5) dispatchReadPacket(from *net.UDPAddr, content []byte) bool {
	select {
	case t.packetInCh <- d2p.ReadPacket{Data: content, Addr: from}:
		return true
	case <-t.closeCtx.Done():
		return false
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

	t.readNextCh <- struct{}{}

	for {
		select {
		case c := <-t.callCh:
			fmt.Printf("\nDispatch: Received new call, ID: %v\n", c.id)
			t.callQueue[c.id] = append(t.callQueue[c.id], c)
			t.sendNextCall(c.id)

		case ct := <-t.respTimeoutCh:
			fmt.Printf("\nDispatch: Call timeout triggered\n")
			active := t.activeCallByNode[ct.c.id]
			if ct.c == active && ct.timer == active.timeout {
				ct.c.err <- errTimeout
			}

		case c := <-t.callDoneCh:
			fmt.Printf("\nDispatch: Call completed, ID: %v\n", c.id)
			active := t.activeCallByNode[c.id]
			if active != c {
				panic(any("BUG: callDone for inactive call"))
			}
			c.timeout.Stop()
			delete(t.activeCallByAuth, c.nonce)
			delete(t.activeCallByNode, c.id)
			t.sendNextCall(c.id)

		case r := <-t.sendCh:
			fmt.Printf("\nDispatch: Sending message to ID: %v\n", r.destID)
			t.send(r.destID, r.destAddr, r.msg, nil)

		case p := <-t.packetInCh:
			fmt.Printf("Dispatch: Received incoming packet\n")
			t.handlePacket(p.Data, p.Addr)
			t.readNextCh <- struct{}{}

		case <-t.closeCtx.Done():
			fmt.Println("\nDispatch: Closing down")
			close(t.readNextCh)
			// ... rest of closing code ...
			return
		}
	}
}

// meteredUdpConn is a wrapper around a net.UDPConn that meters both the
// inbound and outbound network traffic.
type meteredUdpConn struct {
	d2p.UDPConn
}

func newMeteredConn(conn d2p.UDPConn) d2p.UDPConn {
	// Short circuit if metrics are disabled
	if !metrics.Enabled {
		return conn
	}
	return &meteredUdpConn{UDPConn: conn}
}
