package ethclient

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
)

// Client encapsulates Ethereum client connection information
type Client struct {
	suite    *ethtest.Suite
	node     *enode.Node
	nodeName string
	nodeIP   string
	config   *config.Config
}

// NewClient creates a new Ethereum client from configuration
// This is the SINGLE entry point for creating clients, eliminating dial repetition
func NewClient(cfg *config.Config, nodeIndex int) (*Client, error) {
	// Validate node index
	if nodeIndex < 0 || nodeIndex >= len(cfg.P2P.BootstrapNodes) {
		return nil, fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, len(cfg.P2P.BootstrapNodes)-1)
	}

	// Get node name from config (no more hardcoded elNames!)
	nodeName := cfg.GetNodeName(nodeIndex)
	if nodeName == "" {
		nodeName = fmt.Sprintf("node-%d", nodeIndex)
	}

	// Parse enode
	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enode for %s: %w", nodeName, err)
	}

	nodeIP := node.IP().String()

	// Parse JWT secret
	jwtSecret, err := parseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT secret: %w", err)
	}

	// Create suite (unified creation logic)
	suite, err := ethtest.NewSuite(node, nodeIP+":8551", common.Bytes2Hex(jwtSecret[:]), nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to create suite for %s: %w", nodeName, err)
	}

	return &Client{
		suite:    suite,
		node:     node,
		nodeName: nodeName,
		nodeIP:   nodeIP,
		config:   cfg,
	}, nil
}

// NewClientWithPrivateKey creates a client with a custom private key
func NewClientWithPrivateKey(cfg *config.Config, nodeIndex int, privateKey *ecdsa.PrivateKey) (*Client, error) {
	client, err := NewClient(cfg, nodeIndex)
	if err != nil {
		return nil, err
	}
	// Additional setup with private key if needed
	return client, nil
}

// GetSuite returns the underlying eth test suite
func (c *Client) GetSuite() *ethtest.Suite {
	return c.suite
}

// GetNode returns the enode information
func (c *Client) GetNode() *enode.Node {
	return c.node
}

// GetNodeName returns the node name
func (c *Client) GetNodeName() string {
	return c.nodeName
}

// GetNodeIP returns the node IP address
func (c *Client) GetNodeIP() string {
	return c.nodeIP
}

// Dial establishes a connection to the node
// This is the unified dial method, replacing all the scattered dial code
func (c *Client) Dial() (*ethtest.Conn, error) {
	conn, err := c.suite.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", c.nodeName, err)
	}
	return conn, nil
}

// DialAndPeer establishes a connection and performs peering
// Pass nil for default peering
func (c *Client) DialAndPeer() (*ethtest.Conn, error) {
	return c.suite.DialAndPeer(nil)
}

// String returns a string representation of the client
func (c *Client) String() string {
	return fmt.Sprintf("Client[%s @ %s]", c.nodeName, c.nodeIP)
}

// parseJWTSecretFromHexString parses hexadecimal string to JWT secret
func parseJWTSecretFromHexString(hexString string) ([]byte, error) {
	// Remove possible 0x prefix and whitespace
	hexString = strings.TrimSpace(hexString)
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	// Convert to byte array
	jwtSecret, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Validate length
	if len(jwtSecret) != 32 {
		return nil, fmt.Errorf("invalid JWT secret length: expected 32 bytes, got %d", len(jwtSecret))
	}

	return jwtSecret, nil
}

// GeneratePrivateKey generates a new private key
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// PrivateKeyFromHex converts a hex string to private key
func PrivateKeyFromHex(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(hexKey)
}

// ClientFromSuite creates a Client from an existing Suite (for legacy code compatibility)
func ClientFromSuite(suite *ethtest.Suite, cfg *config.Config, nodeIndex int) *Client {
	return &Client{
		suite:    suite,
		nodeName: cfg.GetNodeName(nodeIndex),
		config:   cfg,
	}
}
