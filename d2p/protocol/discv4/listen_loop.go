package discv4

import (
	"D2PFuzz/d2p"
	"container/list"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"io"
	"net"
	"slices"
	"time"
)

// Errors
var (
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
	errLowPort          = errors.New("low port")
)

const (
	respTimeout    = 500 * time.Millisecond
	expiration     = 20 * time.Second
	bondExpiration = 24 * time.Hour

	maxFindnodeFailures = 5                // nodes exceeding this limit are dropped
	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user

	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	maxPacketSize = 1280
	ntpPool       = "pool.ntp.org" // ntpPool is the NTP server to query for the current time
	ntpChecks     = 3              // Number of measurements to do against the NTP server
)

// Config holds settings for the discovery listener.
type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	// All remaining settings are optional.

	// Packet handling configuration:
	Unhandled chan<- ReadPacket // unhandled packets are sent on this channel

	// The options below are useful in very specific cases, like in unit tests.
	V5ProtocolID *[6]byte
	Log          log.Logger         // if set, log messages go here
	ValidSchemes enr.IdentityScheme // allowed identity schemes
	Clock        mclock.Clock
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

func (cfg Config) withDefaults() Config {

	// Debug/test settings:
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

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

func ListenV4(c d2p.UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	cfg = cfg.withDefaults()
	closeCtx, cancel := context.WithCancel(context.Background())
	t := &UDPv4{
		conn:            newMeteredConn(c),
		priv:            cfg.PrivateKey,
		localNode:       ln,
		gotreply:        make(chan reply),
		addReplyMatcher: make(chan *replyMatcher),
		closeCtx:        closeCtx,
		cancelCloseCtx:  cancel,
		log:             cfg.Log,
	}

	t.wg.Add(2)
	go t.loop()
	go t.readLoop(cfg.Unhandled)
	return t, nil
}

// Close shuts down the socket and aborts any running queries.
func (t *UDPv4) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.wg.Wait()
	})
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *UDPv4) loop() {
	defer t.wg.Done()

	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *replyMatcher // head of plist when timeout was last reset
		contTimeouts = 0           // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*replyMatcher)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closeCtx.Done():
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*replyMatcher).errc <- errClosed
			}
			return

		case p := <-t.addReplyMatcher:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool // whether any replyMatcher considered the reply acceptable.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if p.from == r.from && p.ptype == r.data.Kind() && p.ip.Equal(r.ip) {
					ok, requestDone := p.callback(r.data)
					matched = matched || ok
					p.reply = r.data
					// Remove the matcher if callback indicates that all replies have been received.
					if requestDone {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *UDPv4) readLoop(unhandled chan<- ReadPacket) {
	defer t.wg.Done()
	if unhandled != nil {
		defer close(unhandled)
	}

	buf := make([]byte, maxPacketSize)
	for {
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
		if t.handlePacket(from, buf[:nbytes]) != nil && unhandled != nil {
			select {
			case unhandled <- ReadPacket{buf[:nbytes], from}:
			default:
			}
		}
	}
}

// checkClockDrift queries an NTP server for clock drifts and warns the user if
// one large enough is detected.
func checkClockDrift() {
	drift, err := sntpDrift(ntpChecks)
	if err != nil {
		return
	}
	if drift < -driftThreshold || drift > driftThreshold {
		log.Warn(fmt.Sprintf("System clock seems off by %v, which can prevent network connectivity", drift))
		log.Warn("Please enable network time synchronisation in system settings.")
	} else {
		log.Debug("NTP sanity check done", "drift", drift)
	}
}

func sntpDrift(measurements int) (time.Duration, error) {
	// Resolve the address of the NTP server
	addr, err := net.ResolveUDPAddr("udp", ntpPool+":123")
	if err != nil {
		return 0, err
	}
	// Construct the time request (empty package with only 2 fields set):
	//   Bits 3-5: Protocol version, 3
	//   Bits 6-8: Mode of operation, client, 3
	request := make([]byte, 48)
	request[0] = 3<<3 | 3

	// Execute each of the measurements
	var drifts []time.Duration
	for i := 0; i < measurements+2; i++ {
		// Dial the NTP server and send the time retrieval request
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return 0, err
		}

		sent := time.Now()
		if _, err = conn.Write(request); err != nil {
			conn.Close()
			return 0, err
		}
		// Retrieve the reply and calculate the elapsed time
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		reply := make([]byte, 48)
		if _, err = conn.Read(reply); err != nil {
			conn.Close()
			return 0, err
		}
		elapsed := time.Since(sent)

		// Reconstruct the time from the reply data
		sec := uint64(reply[43]) | uint64(reply[42])<<8 | uint64(reply[41])<<16 | uint64(reply[40])<<24
		frac := uint64(reply[47]) | uint64(reply[46])<<8 | uint64(reply[45])<<16 | uint64(reply[44])<<24

		nanosec := sec*1e9 + (frac*1e9)>>32

		t := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nanosec)).Local()

		// Calculate the drift based on an assumed answer time of RRT/2
		drifts = append(drifts, sent.Sub(t)+elapsed/2)

		conn.Close()
	}
	// Calculate average drift (drop two extremities to avoid outliers)
	slices.Sort(drifts)

	drift := time.Duration(0)
	for i := 1; i < len(drifts)-1; i++ {
		drift += drifts[i]
	}
	return drift / time.Duration(measurements), nil
}

func (t *UDPv4) handlePacket(from *net.UDPAddr, buf []byte) error {
	rawpacket, fromKey, hash, err := Decode(buf)
	if err != nil {
		t.log.Debug("Bad discv4 packet", "addr", from, "err", err)
		return err
	}
	packet := t.wrapPacket(rawpacket)
	fromID := fromKey.ID()
	if packet.preverify != nil {
		err = packet.preverify(packet, from, fromID, fromKey)
	}
	t.log.Trace("<< "+packet.Name(), "id", fromID, "addr", from, "err", err)
	if err == nil && packet.handle != nil {
		packet.handle(packet, from, fromID, hash)
	}
	return err
}

// wrapPacket returns the handler functions applicable to a packet.
func (t *UDPv4) wrapPacket(p Packet) *packetHandlerV4 {
	var h packetHandlerV4
	h.Packet = p
	switch p.(type) {
	case *Ping:
		h.preverify = t.verifyPing
		h.handle = t.handlePing
	case *Pong:
		h.preverify = t.verifyPong
	case *Findnode:
		h.preverify = t.verifyFindnode
		h.handle = t.handleFindnode
	case *Neighbors:
		h.preverify = t.verifyNeighbors
	case *ENRRequest:
		h.preverify = t.verifyENRRequest
		h.handle = t.handleENRRequest
	case *ENRResponse:
		h.preverify = t.verifyENRResponse
	}
	return &h
}
