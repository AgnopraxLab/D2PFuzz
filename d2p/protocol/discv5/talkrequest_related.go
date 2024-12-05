package discv5

import (
	"net"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// RegisterTalkHandler adds a handler for 'talk requests'. The handler function is called
// whenever a request for the given protocol is received and should return the response
// data or nil.
func (t *UDPv5) RegisterTalkHandler(protocol string, handler TalkRequestHandler) {
	t.talk.register(protocol, handler)
}

// makeTalkRequest creates a TalkRequest packet.
func (t *UDPv5) makeTalkRequest(protocol string, message []byte) *TalkRequest {
	return &TalkRequest{
		Protocol: protocol,
		Message:  message,
	}
}

// sendTalkRequest sends a talk request to a node and waits for a response.
func (t *UDPv5) sendTalkRequest(n *enode.Node, protocol string, message []byte) ([]byte, error) {
	req := t.makeTalkRequest(protocol, message)
	resp := t.CallToNode(n, TalkResponseMsg, req)
	defer t.CallDone(resp)

	select {
	case respMsg := <-resp.ch:
		return respMsg.(*TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// TalkRequestToID sends a talk request to a node and waits for a response.
func (t *UDPv5) TalkRequestToID(id enode.ID, addr *net.UDPAddr, protocol string, request []byte) ([]byte, error) {
	req := t.makeTalkRequest(protocol, request)
	resp := t.callToID(id, addr, TalkResponseMsg, req)
	defer t.CallDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// handleRequest handles a talk request.
func (t *talkSystem) handleRequest(id enode.ID, addr *net.UDPAddr, req *TalkRequest) {
	t.mutex.Lock()
	handler, ok := t.handlers[req.Protocol]
	t.mutex.Unlock()

	if !ok {
		resp := &TalkResponse{ReqID: req.ReqID}
		t.transport.sendResponse(id, addr, resp)
		return
	}

	// Wait for a slot to become available, then run the handler.
	timeout := time.NewTimer(talkHandlerLaunchTimeout)
	defer timeout.Stop()
	select {
	case <-t.slots:
		go func() {
			defer func() { t.slots <- struct{}{} }()
			respMessage := handler(id, addr, req.Message)
			resp := &TalkResponse{ReqID: req.ReqID, Message: respMessage}
			t.transport.sendFromAnotherThread(id, addr, resp)
		}()
	case <-timeout.C:
		// Couldn't get it in time, drop the request.
		if time.Since(t.lastLog) > 5*time.Second {
			log.Warn("Dropping TALKREQ due to overload", "ndrop", t.dropCount)
			t.lastLog = time.Now()
			t.dropCount++
		}
	case <-t.transport.closeCtx.Done():
		// Transport closed, drop the request.
	}
}

func (t *UDPv5) sendFromAnotherThread(toID enode.ID, toAddr *net.UDPAddr, packet Packet) {
	select {
	case t.sendCh <- sendRequest{toID, toAddr, packet}:
	case <-t.closeCtx.Done():
	}
}
