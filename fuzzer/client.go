package fuzzer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
)

// FuzzClient represents a P2P client for fuzzing Ethereum nodes
type FuzzClient struct {
	privateKey *ecdsa.PrivateKey
	localNode  *enode.LocalNode
	peers      map[enode.ID]*Peer
	peersMu    sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	logger     Logger
}

// Peer represents a connected peer
type Peer struct {
	Node     *enode.Node
	Conn     *rlpx.Conn
	RW       p2p.MsgReadWriter
	Protocols map[string]Protocol
	Connected time.Time
	mu       sync.RWMutex
}

// Protocol represents a supported protocol
type Protocol struct {
	Name    string
	Version uint
	Length  uint64
	Run     func(*Peer) error
}

// Logger interface for logging
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewFuzzClient creates a new P2P fuzzing client
func NewFuzzClient(logger Logger) (*FuzzClient, error) {
	// Generate a private key for this client
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create local node
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, fmt.Errorf("failed to open node database: %w", err)
	}

	localNode := enode.NewLocalNode(db, privateKey)
	localNode.Set(enr.IP(net.IPv4(127, 0, 0, 1)))
	localNode.Set(enr.TCP(0)) // Will be set when we start listening

	ctx, cancel := context.WithCancel(context.Background())

	return &FuzzClient{
		privateKey: privateKey,
		localNode:  localNode,
		peers:      make(map[enode.ID]*Peer),
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger,
	}, nil
}

// ConnectToPeer establishes a connection to a remote peer
func (c *FuzzClient) ConnectToPeer(nodeURL string) (*Peer, error) {
	// Parse the node URL
	node, err := enode.Parse(enode.ValidSchemes, nodeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse node URL: %w", err)
	}

	c.logger.Info("Connecting to peer: %s", node.String())

	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node.IP(), node.TCP()), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer: %w", err)
	}

	// Perform RLPx handshake
	pubkey := node.Pubkey()
	rlpxConn := rlpx.NewConn(conn, pubkey)
	if _, err := rlpxConn.Handshake(c.privateKey); err != nil {
		conn.Close()
		return nil, fmt.Errorf("RLPx handshake failed: %w", err)
	}

	c.logger.Info("RLPx handshake completed with peer: %s", node.ID())

	// Create peer object
	peer := &Peer{
		Node:      node,
		Conn:      rlpxConn,
		RW:        &rlpxReadWriter{conn: rlpxConn},
		Protocols: make(map[string]Protocol),
		Connected: time.Now(),
	}

	// Store peer
	c.peersMu.Lock()
	c.peers[node.ID()] = peer
	c.peersMu.Unlock()

	// Perform protocol handshake
	if err := c.performProtocolHandshake(peer); err != nil {
		c.logger.Error("Protocol handshake failed: %v", err)
		// Don't return error, as we might still want to fuzz the connection
	}

	c.logger.Info("Successfully connected to peer: %s", node.ID())
	return peer, nil
}

// performProtocolHandshake performs the devp2p protocol handshake
func (c *FuzzClient) performProtocolHandshake(peer *Peer) error {
	// Send Hello message
	helloMsg := &HelloMsg{
		Version:    5, // devp2p version
		Name:       "D2PFuzz/1.0.0",
		Caps:       []Cap{{"eth", 68}, {"snap", 1}},
		ListenPort: 0,
		ID:         c.localNode.ID().Bytes(),
	}

	if err := p2p.Send(peer.RW, 0x00, helloMsg); err != nil {
		return fmt.Errorf("failed to send hello message: %w", err)
	}

	c.logger.Debug("Sent Hello message to peer: %s", peer.Node.ID())

	// Receive Hello response
	msg, err := peer.RW.ReadMsg()
	if err != nil {
		return fmt.Errorf("failed to read hello response: %w", err)
	}
	defer msg.Discard()

	if msg.Code != 0x00 {
		return fmt.Errorf("expected hello message, got code: %x", msg.Code)
	}

	var remoteHello HelloMsg
	if err := msg.Decode(&remoteHello); err != nil {
		return fmt.Errorf("failed to decode hello message: %w", err)
	}

	c.logger.Info("Received Hello from %s: %s, caps: %v", peer.Node.ID(), remoteHello.Name, remoteHello.Caps)

	// Store supported protocols
	for _, cap := range remoteHello.Caps {
		peer.Protocols[cap.Name] = Protocol{
			Name:    cap.Name,
			Version: cap.Version,
		}
	}

	return nil
}

// SendEthMessage sends an Ethereum protocol message
func (c *FuzzClient) SendEthMessage(peerID enode.ID, msgCode uint64, data interface{}) error {
	c.peersMu.RLock()
	peer, exists := c.peers[peerID]
	c.peersMu.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found: %s", peerID)
	}

	// Check if peer supports eth protocol
	if _, hasEth := peer.Protocols["eth"]; !hasEth {
		return fmt.Errorf("peer does not support eth protocol")
	}

	// Send the message (assuming eth protocol starts at offset 0x10)
	ethMsgCode := 0x10 + msgCode
	if err := p2p.Send(peer.RW, ethMsgCode, data); err != nil {
		return fmt.Errorf("failed to send eth message: %w", err)
	}

	c.logger.Debug("Sent eth message %x to peer %s", msgCode, peerID)
	return nil
}

// SendSnapMessage sends a Snap protocol message
func (c *FuzzClient) SendSnapMessage(peerID enode.ID, msgCode uint64, data interface{}) error {
	c.peersMu.RLock()
	peer, exists := c.peers[peerID]
	c.peersMu.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found: %s", peerID)
	}

	// Check if peer supports snap protocol
	if _, hasSnap := peer.Protocols["snap"]; !hasSnap {
		return fmt.Errorf("peer does not support snap protocol")
	}

	// Send the message (assuming snap protocol starts after eth)
	snapMsgCode := 0x20 + msgCode // This offset needs to be calculated based on eth protocol length
	if err := p2p.Send(peer.RW, snapMsgCode, data); err != nil {
		return fmt.Errorf("failed to send snap message: %w", err)
	}

	c.logger.Debug("Sent snap message %x to peer %s", msgCode, peerID)
	return nil
}

// ReceiveMessage receives a message from any connected peer
func (c *FuzzClient) ReceiveMessage(peerID enode.ID) (*p2p.Msg, error) {
	c.peersMu.RLock()
	peer, exists := c.peers[peerID]
	c.peersMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("peer not found: %s", peerID)
	}

	msg, err := peer.RW.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	c.logger.Debug("Received message %x from peer %s", msg.Code, peerID)
	return &msg, nil
}

// GetConnectedPeers returns a list of connected peer IDs
func (c *FuzzClient) GetConnectedPeers() []enode.ID {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	peerIDs := make([]enode.ID, 0, len(c.peers))
	for id := range c.peers {
		peerIDs = append(peerIDs, id)
	}
	return peerIDs
}

// DisconnectPeer disconnects from a specific peer
func (c *FuzzClient) DisconnectPeer(peerID enode.ID) error {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()

	peer, exists := c.peers[peerID]
	if !exists {
		return fmt.Errorf("peer not found: %s", peerID)
	}

	// Send disconnect message
	p2p.Send(peer.RW, 0x01, []interface{}{0x08}) // Disconnect reason: client quitting

	// Close connection
	peer.Conn.Close()

	// Remove from peers map
	delete(c.peers, peerID)

	c.logger.Info("Disconnected from peer: %s", peerID)
	return nil
}

// Close closes all connections and shuts down the client
func (c *FuzzClient) Close() error {
	c.cancel()

	c.peersMu.Lock()
	defer c.peersMu.Unlock()

	// Disconnect all peers
	for id, peer := range c.peers {
		peer.Conn.Close()
		c.logger.Info("Closed connection to peer: %s", id)
	}

	c.peers = make(map[enode.ID]*Peer)
	c.logger.Info("FuzzClient closed")
	return nil
}

// HelloMsg represents the devp2p Hello message
type HelloMsg struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ListenPort uint64
	ID         []byte
}

// Cap represents a protocol capability
type Cap struct {
	Name    string
	Version uint
}

// rlpxReadWriter wraps rlpx.Conn to implement p2p.MsgReadWriter
type rlpxReadWriter struct {
	conn *rlpx.Conn
}

func (rw *rlpxReadWriter) ReadMsg() (p2p.Msg, error) {
	// Use the underlying connection's read method
	code, data, _, err := rw.conn.Read()
	if err != nil {
		return p2p.Msg{}, err
	}
	return p2p.Msg{
		Code:       code,
		Size:       uint32(len(data)),
		Payload:    bytes.NewReader(data),
		ReceivedAt: time.Now(),
	}, nil
}

func (rw *rlpxReadWriter) WriteMsg(msg p2p.Msg) error {
	// Read the payload data
	data, err := io.ReadAll(msg.Payload)
	if err != nil {
		return err
	}
	// Use the underlying connection's write method
	_, err = rw.conn.Write(msg.Code, data)
	return err
}