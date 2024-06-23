package discv5

import (
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
	"sync"
	"time"
)

// This is a limit for the number of concurrent talk requests.
const maxActiveTalkRequests = 1024

// This is the timeout for acquiring a handler execution slot for a talk request.
// The timeout should be short enough to fit within the request timeout.
const talkHandlerLaunchTimeout = 400 * time.Millisecond

// TalkRequestHandler callback processes a talk request and returns a response.
//
// Note that talk handlers are expected to come up with a response very quickly, within at
// most 200ms or so. If the handler takes longer than that, the remote end may time out
// and won't receive the response.
type TalkRequestHandler func(enode.ID, *net.UDPAddr, []byte) []byte

type talkSystem struct {
	transport *UDPv5

	mutex     sync.Mutex
	handlers  map[string]TalkRequestHandler
	slots     chan struct{}
	lastLog   time.Time
	dropCount int
}

func newTalkSystem(transport *UDPv5) *talkSystem {
	t := &talkSystem{
		transport: transport,
		handlers:  make(map[string]TalkRequestHandler),
		slots:     make(chan struct{}, maxActiveTalkRequests),
	}
	for i := 0; i < cap(t.slots); i++ {
		t.slots <- struct{}{}
	}
	return t
}

// register adds a protocol handler.
func (t *talkSystem) register(protocol string, handler TalkRequestHandler) {
	t.mutex.Lock()
	t.handlers[protocol] = handler
	t.mutex.Unlock()
}

// handleRequest handles a talk request.
func (t *talkSystem) handleRequest(id enode.ID, addr *net.UDPAddr, req *v5wire.TalkRequest) {
	t.mutex.Lock()
	handler, ok := t.handlers[req.Protocol]
	t.mutex.Unlock()

	if !ok {
		resp := &v5wire.TalkResponse{ReqID: req.ReqID}
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
			resp := &v5wire.TalkResponse{ReqID: req.ReqID, Message: respMessage}
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

// wait blocks until all active requests have finished, and prevents new request
// handlers from being launched.
func (t *talkSystem) wait() {
	for i := 0; i < cap(t.slots); i++ {
		<-t.slots
	}
}
