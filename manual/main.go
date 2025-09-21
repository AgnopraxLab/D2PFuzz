package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
	"gopkg.in/yaml.v2"

	ethtest "D2PFuzz/devp2p/protocol/eth"
)

// Account account structure
type Account struct {
	Address    string // Public key address
	PrivateKey string // Private key (without 0x prefix)
}

// AccountManager account manager for polling different accounts
type AccountManager struct {
	accounts    []Account
	currentFrom int // Current sender account index
	currentTo   int // Current receiver account index
}

// NodeAccountManager manages independent accounts and nonce for each node
type NodeAccountManager struct {
	nodeAccounts map[int]*NodeAccount // Node index -> Node account information
	totalNodes   int
}

// NodeAccount single node account information
type NodeAccount struct {
	FromAccount Account
	ToAccount   Account
	Nonce       uint64
}

// NewNodeAccountManager create node account manager
func NewNodeAccountManager(accounts []Account, nodeCount int) *NodeAccountManager {
	if len(accounts) < nodeCount*2 {
		panic(fmt.Sprintf("Need at least %d accounts to support %d nodes, but only have %d accounts", nodeCount*2, nodeCount, len(accounts)))
	}

	nodeAccounts := make(map[int]*NodeAccount)
	for i := 0; i < nodeCount; i++ {
		// Assign two fixed accounts for each node: one sender, one receiver
		fromIndex := i * 2
		toIndex := i*2 + 1

		nodeAccounts[i] = &NodeAccount{
			FromAccount: accounts[fromIndex],
			ToAccount:   accounts[toIndex],
			Nonce:       0, // Each node starts from nonce 0
		}
	}

	return &NodeAccountManager{
		nodeAccounts: nodeAccounts,
		totalNodes:   nodeCount,
	}
}

// NewNodeAccountManagerWithNonces create node account manager with custom initial nonce values
func NewNodeAccountManagerWithNonces(accounts []Account, nodeCount int, initialNonces []uint64) *NodeAccountManager {
	if len(accounts) < nodeCount+5 {
		panic(fmt.Sprintf("Need at least %d accounts to support %d nodes, but only have %d accounts", nodeCount+5, nodeCount, len(accounts)))
	}

	nodeAccounts := make(map[int]*NodeAccount)
	for i := 0; i < nodeCount; i++ {
		// Modified account allocation strategy: account i transfers to account (i+5)
		// Node 0: account 0 → account 5
		// Node 1: account 1 → account 6
		// Node 2: account 2 → account 7
		// And so on...
		fromIndex := i
		toIndex := i + 5

		// Get the initial nonce value for this node, default to 0 if not specified
		initialNonce := uint64(0)
		if i < len(initialNonces) {
			initialNonce = initialNonces[i]
		}

		nodeAccounts[i] = &NodeAccount{
			FromAccount: accounts[fromIndex],
			ToAccount:   accounts[toIndex],
			Nonce:       initialNonce, // Use specified initial nonce value
		}
	}

	return &NodeAccountManager{
		nodeAccounts: nodeAccounts,
		totalNodes:   nodeCount,
	}
}

// GetNodeAccount get account information for specified node
func (nam *NodeAccountManager) GetNodeAccount(nodeIndex int) *NodeAccount {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		return nodeAccount
	}
	return nil
}

// IncrementNonce increment nonce value for specified node
func (nam *NodeAccountManager) IncrementNonce(nodeIndex int) {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		nodeAccount.Nonce++
	}
}

// GetCurrentNonce get current nonce value for specified node
func (nam *NodeAccountManager) GetCurrentNonce(nodeIndex int) uint64 {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		return nodeAccount.Nonce
	}
	return 0
}

// NewAccountManager create new account manager
func NewAccountManager(accounts []Account) *AccountManager {
	return &AccountManager{
		accounts:    accounts,
		currentFrom: 0,
		currentTo:   1,
	}
}

// GetNextAccountPair get next account pair (sender and receiver)
func (am *AccountManager) GetNextAccountPair() (from Account, to Account) {
	from = am.accounts[am.currentFrom]
	to = am.accounts[am.currentTo]

	// Update indices to ensure different accounts are used next time
	am.currentFrom = (am.currentFrom + 1) % len(am.accounts)
	am.currentTo = (am.currentTo + 1) % len(am.accounts)

	// Ensure sender and receiver are not the same account
	if am.currentFrom == am.currentTo {
		am.currentTo = (am.currentTo + 1) % len(am.accounts)
	}

	return from, to
}

// GetAccountByIndex get account by index
func (am *AccountManager) GetAccountByIndex(index int) Account {
	if index < 0 || index >= len(am.accounts) {
		return am.accounts[0] // Default to return first account
	}
	return am.accounts[index]
}

// GetTotalAccounts get total number of accounts
func (am *AccountManager) GetTotalAccounts() int {
	return len(am.accounts)
}

// writeHashesToFile writes transaction hashes to the specified file
// The first hash overwrites the file, subsequent hashes are appended to the end of the file
// appendToFile appends content to file
func appendToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

func writeHashesToFile(hashes []common.Hash, filename string) error {
	if len(hashes) == 0 {
		return nil
	}

	// First hash overwrites the file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}

	// Write the first hash
	_, err = file.WriteString(hashes[0].Hex() + "\n")
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to write first hash: %v", err)
	}
	file.Close()

	// If there are more hashes, write them in append mode
	if len(hashes) > 1 {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file for append: %v", err)
		}
		defer file.Close()

		for i := 1; i < len(hashes); i++ {
			_, err = file.WriteString(hashes[i].Hex() + "\n")
			if err != nil {
				return fmt.Errorf("failed to write hash %d: %v", i, err)
			}
		}
	}

	// fmt.Printf("Successfully wrote %d transaction hashes to %s\n", len(hashes), filename)
	return nil
}

// If you use ethereum-package to create a local test environment, there will be the following predefined accounts
var PredefinedAccounts = []Account{
	{Address: "0x8943545177806ED17B9F23F0a21ee5948eCaa776", PrivateKey: "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31"},
	{Address: "0xE25583099BA105D9ec0A67f5Ae86D90e50036425", PrivateKey: "39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d"},
	{Address: "0x614561D2d143621E126e87831AEF287678B442b8", PrivateKey: "53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710"},
	{Address: "0xf93Ee4Cf8c6c40b329b0c0626F28333c132CF241", PrivateKey: "ab63b23eb7941c1251757e24b3d2350d2bc05c3c388d06f8fe6feafefb1e8c70"},
	{Address: "0x802dCbE1B1A97554B4F50DB5119E37E8e7336417", PrivateKey: "5d2344259f42259f82d2c140aa66102ba89b57b4883ee441a8b312622bd42491"},
	{Address: "0xAe95d8DA9244C37CaC0a3e16BA966a8e852Bb6D6", PrivateKey: "27515f805127bebad2fb9b183508bdacb8c763da16f54e0678b16e8f28ef3fff"},
	{Address: "0x2c57d1CFC6d5f8E4182a56b4cf75421472eBAEa4", PrivateKey: "7ff1a4c1d57e5e784d327c4c7651e952350bc271f156afb3d00d20f5ef924856"},
	{Address: "0x741bFE4802cE1C4b5b00F9Df2F5f179A1C89171A", PrivateKey: "3a91003acaf4c21b3953d94fa4a6db694fa69e5242b2e37be05dd82761058899"},
	{Address: "0xc3913d4D8bAb4914328651C2EAE817C8b78E1f4c", PrivateKey: "bb1d0f125b4fb2bb173c318cdead45468474ca71474e2247776b2b4c0fa2d3f5"},
	{Address: "0x65D08a056c17Ae13370565B04cF77D2AfA1cB9FA", PrivateKey: "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c"},
	{Address: "0x3e95dFbBaF6B348396E6674C7871546dCC568e56", PrivateKey: "94eb3102993b41ec55c241060f47daa0f6372e2e3ad7e91612ae36c364042e44"},
	{Address: "0x5918b2e647464d4743601a865753e64C8059Dc4F", PrivateKey: "daf15504c22a352648a71ef2926334fe040ac1d5005019e09f6c979808024dc7"},
	{Address: "0x589A698b7b7dA0Bec545177D3963A2741105C7C9", PrivateKey: "eaba42282ad33c8ef2524f07277c03a776d98ae19f581990ce75becb7cfa1c23"},
	{Address: "0x4d1CB4eB7969f8806E2CaAc0cbbB71f88C8ec413", PrivateKey: "3fd98b5187bf6526734efaa644ffbb4e3670d66f5d0268ce0323ec09124bff61"},
	{Address: "0xF5504cE2BcC52614F121aff9b93b2001d92715CA", PrivateKey: "5288e2f440c7f0cb61a9be8afdeb4295f786383f96f5e35eb0c94ef103996b64"},
	{Address: "0xF61E98E7D47aB884C244E39E031978E33162ff4b", PrivateKey: "f296c7802555da2a5a662be70e078cbd38b44f96f8615ae529da41122ce8db05"},
	{Address: "0xf1424826861ffbbD25405F5145B5E50d0F1bFc90", PrivateKey: "bf3beef3bd999ba9f2451e06936f0423cd62b815c9233dd3bc90f7e02a1e8673"},
	{Address: "0xfDCe42116f541fc8f7b0776e2B30832bD5621C85", PrivateKey: "6ecadc396415970e91293726c3f5775225440ea0844ae5616135fd10d66b5954"},
	{Address: "0xD9211042f35968820A3407ac3d80C725f8F75c14", PrivateKey: "a492823c3e193d6c595f37a18e3c06650cf4c74558cc818b16130b293716106f"},
	{Address: "0xD8F3183DEF51A987222D845be228e0Bbb932C222", PrivateKey: "c5114526e042343c6d1899cad05e1c00ba588314de9b96929914ee0df18d46b2"},
	{Address: "0xafF0CA253b97e54440965855cec0A8a2E2399896", PrivateKey: "04b9f63ecf84210c5366c66d68fa1f5da1fa4f634fad6dfc86178e4d79ff9e59"},
}

// Config configuration structure
type Config struct {
	P2P struct {
		MaxPeers       int      `yaml:"max_peers"`
		ListenPort     int      `yaml:"listen_port"`
		BootstrapNodes []string `yaml:"bootstrap_nodes"`
		JWTSecret      string   `yaml:"jwt_secret"`
	} `yaml:"p2p"`
	testMode struct {
		TestMode string `yaml:"testMode"`
	}
}

type protocolHandshake struct {
	Version    uint64
	Name       string
	Caps       []p2p.Cap
	ListenPort uint64
	ID         []byte // secp256k1 public key

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// loadConfig reads configuration file
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createRLPxConnection creates RLPx connection
func createRLPxConnection(node *enode.Node, privateKey *ecdsa.PrivateKey) (*rlpx.Conn, error) {

	// Connect to node
	addr := fmt.Sprintf("%s:%d", node.IP(), node.TCP())
	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	// Perform RLPx handshake
	conn := rlpx.NewConn(tcpConn, node.Pubkey())
	fmt.Printf("conn: %v\n", conn)

	_, err = conn.Handshake(privateKey)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to perform RLPx handshake: %w", err)
	}
	// fmt.Println("publickKey: ", publicKey)
	fmt.Println("RLPx handshake completed successfully")

	return conn, nil
}

// // testGetBlockHeaders test GetBlockHeaders request
// func testGetBlockHeaders(conn *rlpx.Conn) error {
// 	// First perform ETH protocol handshake
// 	err := performETHHandshake(conn)
// 	if err != nil {
// 		return fmt.Errorf("failed to perform ETH handshake: %w", err)
// 	}

// 	request := &eth.GetBlockHeadersPacket{
// 		RequestId: 1,
// 		GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
// 			Origin: eth.HashOrNumber{
// 				Number: 1,
// 			}, // Request starting from block 1
// 			Amount:  10, // Request 10 block headers
// 			Skip:    0,
// 			Reverse: false,
// 		},
// 	}

// 	// Use RLP encoding to send message
// 	data, err := rlp.EncodeToBytes(request)
// 	if err != nil {
// 		return fmt.Errorf("failed to encode GetBlockHeaders request: %w", err)
// 	}

// 	_, err = conn.Write(0x03, data) // GetBlockHeadersMsg = 0x03
// 	if err != nil {
// 		return fmt.Errorf("failed to send GetBlockHeaders request: %w", err)
// 	}
// 	fmt.Println("GetBlockHeaders request sent successfully")

// 	// Receive response
// 	code, responseData, _, err := conn.Read()
// 	if err != nil {
// 		return fmt.Errorf("failed to read response: %w", err)
// 	}
// 	fmt.Printf("Received message with code: %d, size: %d\n", code, len(responseData))

// 	if code == 0x04 { // BlockHeadersMsg = 0x04
// 		type BlockHeadersPacket struct {
// 			RequestId uint64
// 			Headers   []*types.Header
// 		}
// 		var response BlockHeadersPacket
// 		err = rlp.DecodeBytes(responseData, &response)
// 		if err != nil {
// 			return fmt.Errorf("failed to decode block headers: %w", err)
// 		}
// 		fmt.Printf("Received %d block headers:\n", len(response.Headers))

// 		for i, header := range response.Headers {
// 			fmt.Printf("  Header %d: Block #%d, Hash: %s\n", i+1, header.Number.Uint64(), header.Hash().Hex())
// 		}
// 	} else {
// 		fmt.Printf("Unexpected message code: %d\n", code)
// 	}

// 	return nil
// }

// // performETHHandshake perform ETH protocol handshake
// func performETHHandshake(conn *rlpx.Conn) error {
// 	// Use default mainnet configuration to create status packet
// 	genesisHash := common.HexToHash("0x307b844cd0697aeebd02d2ee2443f0fa7e990258ec48e980d97c81669d00affd")
// 	latestHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
// 	td := big.NewInt(0)

// 	// Create a virtual genesis block for forkid calculation
// 	genesisHeader := &types.Header{
// 		Number:     big.NewInt(0),
// 		Time:       0,
// 		Difficulty: big.NewInt(1),
// 	}

// 	// Create a virtual block for forkid calculation
// 	body := &types.Body{}
// 	genesisBlock := types.NewBlock(genesisHeader, body, nil, nil)
// 	fmt.Println("genesisBlock: ", genesisBlock)
// 	status := &eth.StatusPacket68{
// 		ProtocolVersion: 68, // ETH68
// 		NetworkID:       1,  // Mainnet
// 		TD:              td,
// 		Head:            latestHash,
// 		Genesis:         genesisHash,
// 		ForkID:          forkid.NewID(params.MainnetChainConfig, genesisBlock, 0, 0),
// 	}

// 	// Send status packet
// 	statusData, err := rlp.EncodeToBytes(status)
// 	if err != nil {
// 		return fmt.Errorf("failed to encode status packet: %w", err)
// 	} else {
// 		fmt.Println("statusData: ", statusData)
// 	}
// 	code1, err := conn.Write(0x00, statusData) // StatusMsg = 0x00
// 	if err != nil {
// 		return fmt.Errorf("failed to send status packet: %w", err)
// 	} else {
// 		fmt.Println("code1: ", code1)
// 	}

// 	fmt.Println("ETH status packet sent")

// 	// Receive peer's status packet
// 	code, data, _, err := conn.Read()
// 	if err != nil {
// 		return fmt.Errorf("failed to read status response: %w", err)
// 	}

// 	fmt.Printf("Received message - Code: %d, Data length: %d\n", code, len(data))
// 	fmt.Printf("Raw data (hex): %x\n", data)

// 	// Parse raw data to readable format
// 	handshake := parseRawData(data)
// 	fmt.Printf("Parsed data: %v\n", handshake)

// 	// Specifically parse P2P handshake data
// 	parseP2PHandshakeData(data)

// 	if code == 0x00 {
// 		fmt.Println("\nThis appears to be a P2P handshake message, not an ETH status message.")
// 		fmt.Println("The peer is responding with its protocol capabilities.")
// 	} else {
// 		fmt.Printf("Received message with code %d\n", code)
// 	}

// 	return nil
// }

// parseRawData parse raw data to readable format
func parseRawData(data []byte) *protocolHandshake {
	if len(data) == 0 {
		fmt.Println("empty data")
		return nil
	}

	// Try to parse as RLP structure
	var result interface{}
	err := rlp.DecodeBytes(data, &result)
	if err != nil {
		fmt.Println("rlp decode error")
		return nil
	}
	fmt.Println("Data before parsing:", data)
	// Try to parse as P2P handshake message
	var handshake protocolHandshake
	err = rlp.DecodeBytes(data, &handshake)
	if err == nil {
		fmt.Println("decode bytes error")
		return nil
	}

	return &protocolHandshake{
		Version:    handshake.Version,
		Name:       handshake.Name,
		Caps:       handshake.Caps,
		ListenPort: handshake.ListenPort,
	}
}

// parseP2PHandshakeData specifically parses P2P handshake data
func parseP2PHandshakeData(data []byte) {
	var handshake protocolHandshake
	err := rlp.DecodeBytes(data, &handshake)
	if err != nil {
		fmt.Printf("Failed to decode P2P handshake: %v\n", err)
		return
	}

	fmt.Printf("=== P2P Handshake Details ===\n")
	fmt.Printf("Version: %d\n", handshake.Version)
	fmt.Printf("Name: %s\n", handshake.Name)
	fmt.Printf("Listen Port: %d\n", handshake.ListenPort)
	fmt.Printf("Node ID: %x\n", handshake.ID)
	fmt.Printf("Capabilities:\n")
	for i, cap := range handshake.Caps {
		fmt.Printf("  %d. %s/%d\n", i+1, cap.Name, cap.Version)
	}
	fmt.Printf("==============================\n")
}

// Parse hexadecimal string directly
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

// runSingleNodeTestingWithUI handle user interaction logic for single node testing
func runSingleNodeTestingWithUI(elNames []string, config *Config) {
	fmt.Println("\nAvailable nodes:")
	for i, name := range elNames {
		fmt.Printf("  %d. %s\n", i, name)
	}

	fmt.Print("Please select node index (0-4): ")
	var nodeIndex int
	fmt.Scanln(&nodeIndex)

	if nodeIndex < 0 || nodeIndex >= len(elNames) {
		fmt.Printf("Invalid node index: %d. Valid range: 0-%d\n", nodeIndex, len(elNames)-1)
		return
	}

	fmt.Print("Enter custom starting nonce (press Enter for default 0): ")
	var nonceInput string
	fmt.Scanln(&nonceInput)

	var customNonce *uint64
	if nonceInput != "" && nonceInput != "0" {
		if nonce, err := strconv.ParseUint(nonceInput, 10, 64); err == nil {
			customNonce = &nonce
		} else {
			fmt.Printf("Invalid nonce value, using default 0\n")
		}
	}

	fmt.Print("Enter number of transactions to send (default 3): ")
	var batchSizeInput string
	fmt.Scanln(&batchSizeInput)

	batchSize := 3 // Default value
	if batchSizeInput != "" {
		if size, err := strconv.Atoi(batchSizeInput); err == nil && size > 0 {
			batchSize = size
		}
	}

	fmt.Printf("\n🎯 Starting single node testing for %s (Node %d)...\n", elNames[nodeIndex], nodeIndex)
	singleNodeTesting(elNames, config, nodeIndex, customNonce, batchSize)
}

func main() {
	// ========== Test Configuration Variables ==========
	// Modify these variables to control test behavior without console input
	// 1. Read configuration from config.yaml file in current directory
	config, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}
	// Test mode: "multi" = multi-node testing, "single" = single node testing,
	// "interactive" = interactive selection,
	// "oneTransaction" = single transaction testing,
	// "largeTransactions" = large batch transaction testing
	testMode := config.testMode.TestMode

	// Multi-node testing configuration (only effective when testMode = "multi")
	multiNodeNonceInitialValues := []uint64{
		0, // Node 0 (geth) initial nonce
		0, // Node 1 (nethermind) initial nonce
		0, // Node 2 (reth) initial nonce
		0, // Node 3 (erigon) initial nonce
		0, // Node 4 (besu) initial nonce
	}
	multiNodeBatchSize := 2 // Number of transactions to send per node

	// Single node testing configuration (only effective when testMode = "single")
	singleNodeIndex := 2          // Node index to test (0=geth, 1=nethermind, 2=reth, 3=erigon, 4=besu)
	singleNodeNonce := uint64(13) // Starting nonce value
	singleNodeBatchSize := 1      // Number of transactions to send

	// ========================================

	// 2. Get enode values, parse to extract IP and port
	if len(config.P2P.BootstrapNodes) == 0 {
		fmt.Println("No bootstrap nodes found in config")
		return
	}

	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}

	// Execute corresponding tests based on configuration variables
	switch testMode {
	case "multi":
		// Multi-node testing
		fmt.Println("=== D2PFuzz Multi-Node Testing Tool ===")
		fmt.Println("🚀 Starting multi-node testing...")
		multiNodesTesting(elNames, config, multiNodeNonceInitialValues, multiNodeBatchSize)

	case "single":
		// Single node testing
		fmt.Println("=== D2PFuzz Single-Node Testing Tool ===")
		if singleNodeIndex < 0 || singleNodeIndex >= len(elNames) {
			fmt.Printf("Invalid node index: %d. Valid range: 0-%d\n", singleNodeIndex, len(elNames)-1)
			return
		}
		fmt.Printf("🎯 Starting single node testing for %s (Node %d)...\n", elNames[singleNodeIndex], singleNodeIndex)
		singleNodeTesting(elNames, config, singleNodeIndex, &singleNodeNonce, singleNodeBatchSize)
	case "oneTransaction":
		// Single node testing, send only one transaction
		fmt.Println("=== D2PFuzz Single-Transaction Testing Tool ===")

		sendTransaction(config)
	case "largeTransactions":
		// Single node testing, send only one transaction
		fmt.Println("=== D2PFuzz Large-Transaction Testing Tool ===")
		sendLargeTransactions(config)
	case "interactive":
		// Interactive selection mode
		fmt.Println("=== D2PFuzz Multi-Node Testing Tool ===")
		fmt.Println("Available test modes:")
		fmt.Println("1. Multi-node testing (all nodes)")
		fmt.Println("2. Single node testing (specific node)")
		fmt.Print("Please select test mode (1 or 2): ")

		var choice int
		fmt.Scanln(&choice)

		switch choice {
		case 1:
			fmt.Println("\n🚀 Starting multi-node testing...")
			multiNodesTesting(elNames, config, multiNodeNonceInitialValues, multiNodeBatchSize)
		case 2:
			runSingleNodeTestingWithUI(elNames, config)
		default:
			fmt.Println("Invalid choice. Please select 1 or 2.")
		}

	default:
		fmt.Printf("Invalid test mode: %s. Valid modes: multi, single, interactive\n", testMode)
	}
}

func singleNodeTesting(elNames []string, config *Config, elIndex int, customNonce *uint64, batchSize int) {
	if elIndex < 0 || elIndex >= len(elNames) {
		fmt.Printf("❌ Invalid node index: %d. Valid range: 0-%d\n", elIndex, len(elNames)-1)
		return
	}

	fmt.Printf("\n=== Single Node Testing ===\n")
	fmt.Printf("●Execution Client: %v (Node %d)\n", elNames[elIndex], elIndex)

	// Set nonce initial value
	nodeNonceInitialValues := []uint64{0, 0, 0, 0, 0}
	if customNonce != nil {
		if elIndex < len(nodeNonceInitialValues) {
			nodeNonceInitialValues[elIndex] = *customNonce
		}
	}

	// Create node account manager, allocate accounts only for current node
	nodeAccountManager := NewNodeAccountManagerWithNonces(PredefinedAccounts, len(elNames), nodeNonceInitialValues)

	// parse node info
	enodeStr := config.P2P.BootstrapNodes[elIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		fmt.Printf("❌ Failed to parse enode: %v\n", err)
		return
	}

	fmt.Printf("🔗 Connecting to %s node:\n", elNames[elIndex])
	fmt.Printf("📍 IP: %s, Port: %d\n", node.IP(), node.TCP())

	// Read JWTSecret
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		fmt.Printf("❌ Failed to parse JWT secret: %v\n", err)
		return
	}

	// Create suite
	suite, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[elIndex])
	if err != nil {
		fmt.Printf("❌ Failed to create suite: %v\n", err)
		return
	}

	// Get fixed account information for current node
	nodeAccount := nodeAccountManager.GetNodeAccount(elIndex)
	if nodeAccount == nil {
		fmt.Printf("❌ Failed to get account for node %d\n", elIndex)
		return
	}

	fmt.Printf("💳Using accounts:\n")
	fmt.Printf("   From: %s (Initial Nonce: %d)\n", nodeAccount.FromAccount.Address, nodeAccount.Nonce)
	fmt.Printf("   To: %s\n", nodeAccount.ToAccount.Address)

	// Initialize transaction hash record file - single node testing directly uses txhashes.txt
	hashFilePath := "/home/kkk/workspaces/D2PFuzz/test/txhashes.txt"
	// Clear file content and add node name comment
	nodeHeader := fmt.Sprintf("# %s\n", elNames[elIndex])
	if err := os.WriteFile(hashFilePath, []byte(nodeHeader), 0644); err != nil {
		fmt.Printf("❌ Failed to initialize hash file: %v\n", err)
		return
	}

	// Batch transaction sending test
	fmt.Printf("📤 Sending %d transactions...\n", batchSize)

	successCount := 0
	for j := 0; j < batchSize; j++ {
		currentNonce := nodeAccountManager.GetCurrentNonce(elIndex)
		fmt.Printf("   Transaction %d/%d (Nonce: %d)...", j+1, batchSize, currentNonce)

		txHash, err := sendTransactionWithAccountsAndNonce(suite, nodeAccount.FromAccount, nodeAccount.ToAccount, currentNonce)
		if err != nil {
			fmt.Printf(" ❌ Failed: %v\n", err)
			break
		}

		// Write transaction hash to file
		hashLine := fmt.Sprintf("%s\n", txHash.Hex())
		if err := appendToFile(hashFilePath, hashLine); err != nil {
			fmt.Printf(" ⚠️ Failed to write hash to file: %v", err)
		}

		// Increment nonce for this node after successful transaction
		nodeAccountManager.IncrementNonce(elIndex)
		fmt.Printf(" ✅ Finished! (New Nonce: %d, Hash: %s)\n", nodeAccountManager.GetCurrentNonce(elIndex), txHash.Hex())
		successCount++

		// Add small delay between transactions to avoid nonce conflicts
		time.Sleep(100 * time.Millisecond)
	}

	// Print test summary
	// fmt.Printf("\n=== Single Node Testing Summary ===\n")
	// fmt.Printf("Node: %s (Index: %d)\n", elNames[elIndex], elIndex)
	// fmt.Printf("Transactions sent: %d/%d\n", successCount, batchSize)
	fmt.Printf("=== Single Node Testing Completed ===\n")
	// fmt.Printf("📄 Transaction hashes saved to: %s\n", hashFilePath)
}

func multiNodesTesting(elNames []string, config *Config, nodeNonceInitialValues []uint64, batchSize int) {
	// Ensure nonce initial values list has sufficient length
	for len(nodeNonceInitialValues) < len(elNames) {
		nodeNonceInitialValues = append(nodeNonceInitialValues, 0)
	}

	fmt.Printf("\n=== Node Nonce Initial Values ===\n")
	for i := 0; i < len(elNames); i++ {
		fmt.Printf("Node %d (%s): Initial Nonce = %d\n", i, elNames[i], nodeNonceInitialValues[i])
	}
	fmt.Println()

	// Create node account manager, allocate fixed accounts and independent nonce management for each node
	nodeAccountManager := NewNodeAccountManagerWithNonces(PredefinedAccounts, len(elNames), nodeNonceInitialValues)

	fmt.Printf("\n=== Multi-Node Testing Started ===\n")
	// fmt.Printf("Total nodes to test: %d\n", len(elNames))
	// fmt.Printf("Account allocation strategy: Fixed accounts per node\n")
	// fmt.Printf("Nonce management: Independent per node\n\n")

	// Statistics for test results
	// successCount := 0
	failureCount := 0

	// Initialize transaction hash record file
	hashFilePath := "/home/kkk/workspaces/D2PFuzz/test/txhashes.txt"
	// Clear file content
	if err := os.WriteFile(hashFilePath, []byte(""), 0644); err != nil {
		fmt.Printf("❌ Failed to initialize hash file: %v\n", err)
		return
	}

	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		fmt.Printf("❌ Failed to parse JWT secret: %v\n", err)
		failureCount++
		return
	}

	// Loop test all nodes
	for i := 0; i < len(elNames); i++ {
		fmt.Printf("●Execution Client: %v (Node %d/%d)\n", elNames[i], i+1, len(elNames))

		// parse node info
		enodeStr := config.P2P.BootstrapNodes[i]
		node, err := enode.Parse(enode.ValidSchemes, enodeStr)
		if err != nil {
			fmt.Printf("❌ Failed to parse enode: %v\n", err)
			failureCount++
			continue
		}

		fmt.Printf("🔗 Connecting to %s node:\n", elNames[i])
		fmt.Printf("📍 IP: %s, Port: %d\n", node.IP(), node.TCP())

		// Create suite
		suite, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[i])
		if err != nil {
			fmt.Printf("❌ Failed to create suite: %v\n", err)
			failureCount++
			continue
		}

		// Get fixed account information for current node
		nodeAccount := nodeAccountManager.GetNodeAccount(i)
		if nodeAccount == nil {
			fmt.Printf("❌ Failed to get account for node %d\n", i)
			failureCount++
			continue
		}

		fmt.Printf("💳 Node %d - Using fixed accounts:\n", i+1)
		fmt.Printf("   From: %s (Nonce: %d)\n", nodeAccount.FromAccount.Address, nodeAccount.Nonce)
		fmt.Printf("   To: %s\n", nodeAccount.ToAccount.Address)

		// Write node name to hash file
		nodeHeader := fmt.Sprintf("# %s\n", elNames[i])
		if err := appendToFile(hashFilePath, nodeHeader); err != nil {
			fmt.Printf("❌ Failed to write node header to hash file: %v\n", err)
		}

		// Batch transaction sending test (can adjust transaction count as needed)
		fmt.Printf("📤 Sending %d transactions for Node %d...\n", batchSize, i+1)

		// nodeSuccess := true
		for j := 0; j < batchSize; j++ {
			currentNonce := nodeAccountManager.GetCurrentNonce(i)
			fmt.Printf("   Transaction %d/%d (Nonce: %d)...", j+1, batchSize, currentNonce)

			txHash, err := sendTransactionWithAccountsAndNonce(suite, nodeAccount.FromAccount, nodeAccount.ToAccount, currentNonce)
			if err != nil {
				fmt.Printf(" ❌ Failed: %v\n", err)
				// nodeSuccess = false
				break
			}

			// Write transaction hash to file
			hashLine := fmt.Sprintf("%s\n", txHash.Hex())
			if err := appendToFile(hashFilePath, hashLine); err != nil {
				fmt.Printf(" ⚠️ Failed to write hash to file: %v", err)
			}

			// Increment nonce for this node after successful transaction
			nodeAccountManager.IncrementNonce(i)
			fmt.Printf(" Finished. (New Nonce: %d, Hash: %s)\n", nodeAccountManager.GetCurrentNonce(i), txHash.Hex())

			// Add small delay between transactions to avoid nonce conflicts
			time.Sleep(100 * time.Millisecond)
		}

		// if nodeSuccess {
		// 	fmt.Printf("✅ Node %d (%s) - All transactions sent successfully!\n", i, elNames[i])
		// 	successCount++
		// } else {
		// 	fmt.Printf("❌ Node %d (%s) - Some transactions failed!\n", i, elNames[i])
		// 	failureCount++
		// }

		fmt.Println(strings.Repeat("-", 60))
	}

	// Print test summary
	// fmt.Printf("\n=== Multi-Node Testing Summary ===\n")
	fmt.Printf("Total nodes tested: %d\n", len(elNames))
	// fmt.Printf("Successful nodes: %d\n", successCount)
	// fmt.Printf("Failed nodes: %d\n", failureCount)
	// fmt.Printf("Success rate: %.1f%%\n", float64(successCount)/float64(len(elNames))*100)

	// Print final nonce status
	fmt.Println("\n=== Final Nonce Status ===")
	for i := 0; i < len(elNames); i++ {
		nodeAccount := nodeAccountManager.GetNodeAccount(i)
		if nodeAccount != nil {
			fmt.Printf("Node %d (%-10s): From=%s, (Nonce should be %d)\n",
				i+1, elNames[i], nodeAccount.FromAccount.Address, nodeAccount.Nonce)
		}
	}

	fmt.Printf("\n=== Multi-Node Testing Completed ===\n")
	fmt.Printf("📄 Transaction hashes saved to: %s\n", hashFilePath)
}

func printTransaction(tx *types.Transaction) {
	fmt.Printf("Transaction Details:\n")
	fmt.Printf("  Hash: %s\n", tx.Hash().Hex())
	fmt.Printf("  Nonce: %d\n", tx.Nonce())
	fmt.Printf("  Gas Price: %d\n", tx.GasPrice())
	fmt.Printf("  Gas: %d\n", tx.Gas())
	fmt.Printf("  To: %s\n", tx.To().Hex())
	fmt.Printf("  Value: %s\n", tx.Value())
	fmt.Printf("  Data: %x\n", tx.Data())
	// Signature information
	v, r, s := tx.RawSignatureValues()
	fmt.Printf("Signature V: %d\n", v.Uint64())
	fmt.Printf("Signature R: %s\n", r.String())
	fmt.Printf("Signature S: %s\n", s.String())
}

// queryTransactionByHash queries whether a transaction is on the chain by transaction hash
func queryTransactionByHash(s *ethtest.Suite, txHash common.Hash) (tx *types.Transaction, err error) {
	// Establish connection
	conn, err := s.Dial()
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return nil, fmt.Errorf("peering failed: %v", err)
	}

	// Create transaction query request (using GetPooledTransactions as query mechanism)
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    999,
		GetPooledTransactionsRequest: []common.Hash{txHash},
	}

	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		return nil, fmt.Errorf("failed to write transaction query: %v", err)
	}
	fmt.Println("req: ", req)
	// Wait for response
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}
	resp := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, resp); err != nil {
		return nil, fmt.Errorf("failed to read transaction response: %v", err)
	}
	fmt.Println("resp: ", resp)

	// Verify response
	if got, want := resp.RequestId, req.RequestId; got != want {
		return nil, fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	// Check if transaction was found
	if len(resp.PooledTransactionsResponse) == 0 {
		return nil, fmt.Errorf("transaction not found: %s", txHash.Hex())
	}

	// Verify if returned transaction hash matches
	foundTx := resp.PooledTransactionsResponse[0]
	if foundTx.Hash() != txHash {
		return nil, fmt.Errorf("transaction hash mismatch: expected %s, got %s",
			txHash.Hex(), foundTx.Hash().Hex())
	}

	fmt.Printf("Successfully found transaction on chain: %s", txHash.Hex())
	return foundTx, nil
}

func sendLargeTransactions(config *Config) (eth.PooledTransactionsResponse, []common.Hash) {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return eth.PooledTransactionsResponse{}, nil
	}
	enodeStr := config.P2P.BootstrapNodes[1]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), "nethermind")
	fmt.Printf("🎯 Starting large transactions testing for %s ...\n", s.GetElName())
	// This test first sends count transactions to the node, then requests these transactions using GetPooledTransactions on another peer connection.
	var (
		nonce  = uint64(31)
		from   = PredefinedAccounts[1].PrivateKey
		count  = 20000
		txs    []*types.Transaction
		hashes []common.Hash
		set    = make(map[common.Hash]struct{})
	)
	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		fmt.Println("failed to generate private key")
		return nil, nil
	}
	var to common.Address = common.HexToAddress(PredefinedAccounts[6].Address)
	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID: big.NewInt(3151908),
			// Nonce:     nonce + uint64(i),
			Nonce:     nonce,
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(20000000000),
			Gas:       21000,
			To:        &to,
			Value:     common.Big1,
		}
		tx := types.NewTx(inner)
		tx, err = types.SignTx(tx, types.NewLondonSigner(big.NewInt(3151908)), prik)
		if err != nil {
			fmt.Println("failed to sign tx: err")
		}
		txs = append(txs, tx)
		set[tx.Hash()] = struct{}{}
		hashes = append(hashes, tx.Hash())
	}
	// Send txs.
	// Record sending time
	sendStart := time.Now()
	s.SendTxs(txs)
	elapsed := time.Since(sendStart)
	if len(txs) == 1 {
		fmt.Println("The hash value of this transaction is:\n", hashes[0])
	}
	fmt.Printf("Transaction sending time consumed: %v", elapsed)

	// Write transaction hashes to file
	hashFilePath := "/home/kkk/workspaces/D2PFuzz/test/txhashes.txt"
	if err := writeHashesToFile(hashes, hashFilePath); err != nil {
		fmt.Printf("Failed to write hashes to file: %v\n", err)
	}

	// Set up receive connection to ensure node is peered with the receiving
	// connection before tx request is sent.
	conn, err := s.Dial()
	if err != nil {
		fmt.Printf("dial failed: %v", err)
	}
	defer conn.Close()
	if err = conn.Peer(nil); err != nil {
		fmt.Printf("peering failed: %v", err)
	}
	// Create and send pooled tx request.
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    1234,
		GetPooledTransactionsRequest: hashes,
	}
	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		fmt.Printf("could not write to conn: %v", err)
	}
	// Check that all received transactions match those that were sent to node.
	msg := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, &msg); err != nil {
		fmt.Printf("error reading from connection: %v", err)
	}
	if got, want := msg.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in response: got %d, want %d", got, want)
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			fmt.Printf("unexpected tx received: %v", got.Hash())
		}
	}
	fmt.Printf("\n%v transactions have been sent.\n", len(txs))

	return msg.PooledTransactionsResponse, hashes
}

func printPooledTransactions(resp eth.PooledTransactionsResponse) {
	if len(resp) == 0 {
		fmt.Println("No pooled transaction data")
		return
	}

	fmt.Printf("=== Pooled Transactions Response ===\n")
	fmt.Printf("Total transactions: %d\n\n", len(resp))

	for i, tx := range resp {
		fmt.Printf("--- Transaction %d ---\n", i+1)

		// Basic transaction information
		fmt.Printf("Transaction hash: %s\n", tx.Hash().Hex())
		// fmt.Printf("Transaction type: %d\n", tx.Type())
		fmt.Printf("Nonce: %d\n", tx.Nonce())

		// Address information
		if tx.To() != nil {
			fmt.Printf("To address: %s\n", tx.To().Hex())
		} else {
			fmt.Printf("To address: Contract creation transaction\n")
		}

		// Amount and Gas information
		fmt.Printf("Transfer amount: %s Wei\n", tx.Value().String())
		// fmt.Printf("Gas limit: %d\n", tx.Gas())

		// // Gas price information (display different fields based on transaction type)
		// switch tx.Type() {
		// case types.LegacyTxType:
		// 	fmt.Printf("Gas price: %s Wei\n", tx.GasPrice().String())
		// case types.AccessListTxType:
		// 	fmt.Printf("Gas price: %s Wei\n", tx.GasPrice().String())
		// case types.DynamicFeeTxType:
		// 	fmt.Printf("Max fee: %s Wei\n", tx.GasFeeCap().String())
		// 	fmt.Printf("Priority fee: %s Wei\n", tx.GasTipCap().String())
		// case types.BlobTxType:
		// 	fmt.Printf("Max fee: %s Wei\n", tx.GasFeeCap().String())
		// 	fmt.Printf("Priority fee: %s Wei\n", tx.GasTipCap().String())
		// 	if tx.BlobGasFeeCap() != nil {
		// 		fmt.Printf("Blob gas fee cap: %s Wei\n", tx.BlobGasFeeCap().String())
		// 	}
		// 	if tx.BlobHashes() != nil {
		// 		fmt.Printf("Blob hash count: %d\n", len(tx.BlobHashes()))
		// 		for j, blobHash := range tx.BlobHashes() {
		// 			fmt.Printf("  Blob hash %d: %s\n", j+1, blobHash.Hex())
		// 		}
		// 	}
		// default:
		// 	fmt.Printf("Gas price: %s Wei\n", tx.GasPrice().String())
		// }

		// // Chain ID
		// if tx.ChainId() != nil {
		// 	fmt.Printf("Chain ID: %d\n", tx.ChainId().Uint64())
		// }

		// // Transaction data
		// data := tx.Data()
		// if len(data) > 0 {
		// 	fmt.Printf("Data length: %d bytes\n", len(data))
		// 	if len(data) <= 64 {
		// 		fmt.Printf("Data content: %x\n", data)
		// 	} else {
		// 		fmt.Printf("Data content (first 32 bytes): %x...\n", data[:32])
		// 	}
		// } else {
		// 	fmt.Printf("Data: None\n")
		// }

		// // Transaction size
		// fmt.Printf("Transaction size: %d bytes\n", tx.Size())

		// // Signature information
		// v, r, s := tx.RawSignatureValues()
		// fmt.Printf("Signature V: %d\n", v.Uint64())
		// fmt.Printf("Signature R: %s\n", r.String())
		// fmt.Printf("Signature S: %s\n", s.String())

		// Calculate sender address (if possible)
		if signer := types.LatestSignerForChainID(tx.ChainId()); signer != nil {
			if sender, err := types.Sender(signer, tx); err == nil {
				fmt.Printf("Sender address: %s\n", sender.Hex())
			} else {
				fmt.Printf("Sender address: Unable to calculate (%v)\n", err)
			}
		}

		fmt.Println("=================================")
	}
}

func printMsg(msg any) {
	fmt.Printf("Msg: %v\n", msg)
}

func sendTransaction(config *Config) error {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return err
	}
	enodeStr := config.P2P.BootstrapNodes[0]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), "besu")
	if err != nil {
		return err
	}
	fmt.Printf("🎯 Starting single transaction testing for %s ...\n", s.GetElName())
	nonce := uint64(0)
	// nonce := uint64(9999999)
	var to common.Address = common.HexToAddress(PredefinedAccounts[0].Address)
	txdata := &types.DynamicFeeTx{
		ChainID:   big.NewInt(3151908),
		Nonce:     nonce,
		GasTipCap: big.NewInt(100000000),
		GasFeeCap: big.NewInt(2000000000),
		Gas:       21000,
		To:        &to,
		Value: func() *big.Int {
			val, ok := new(big.Int).SetString("999999999999000000000000000", 10)
			if !ok {
				panic("failed to parse big integer string")
			}
			return val
		}(),
	}
	innertx := types.NewTx(txdata)
	prik, err := crypto.HexToECDSA(PredefinedAccounts[13].PrivateKey)
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}
	tx, err := types.SignTx(innertx, types.NewLondonSigner(big.NewInt(3151908)), prik)
	var hashes []common.Hash
	var set = make(map[common.Hash]struct{})
	set[tx.Hash()] = struct{}{}
	hashes = append(hashes, tx.Hash())
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}

	// Record sending time
	sendStart := time.Now()
	// if err = s.SendTxs([]*types.Transaction{tx}); err != nil {
	// elapsed := time.Since(sendStart)
	// fmt.Printf("Transaction sending failed, time consumed: %v\n", elapsed)
	// return err
	// }
	s.SendTxs([]*types.Transaction{tx})
	elapsed := time.Since(sendStart)
	fmt.Printf("Transaction sending time consumed: %v\n", elapsed)

	// Write transaction hashes to file
	// hashFilePath := "/home/kkk/workspaces/D2PFuzz/test/txhashes.txt"
	// if err := writeHashesToFile(hashes, hashFilePath); err != nil {
	// 	fmt.Printf("Failed to write hashes to file: %v\n", err)
	// }

	// Reference sendLargeTransactions validation method, establish connection to verify if transactions are received by node
	conn, err := s.Dial()
	if err != nil {
		fmt.Printf("dial failed: %v", err)
	}
	defer conn.Close()
	if err = conn.Peer(nil); err != nil {
		fmt.Printf("peering failed: %v", err)
	}

	// Create and send pooled transaction request to verify transactions
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    1234,
		GetPooledTransactionsRequest: hashes,
	}
	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		fmt.Printf("could not write to conn: %v", err)
	}
	// Check if sent transactions were received
	msg := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, &msg); err != nil {
		fmt.Printf("error reading from connection: %v", err)
	}
	if got, want := msg.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in response: got %d, want %d", got, want)
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			fmt.Printf("unexpected tx received: %v", got.Hash())
		}
	}
	fmt.Println("The hash value of this transaction is:\n", hashes[0])
	printPooledTransactions(msg.PooledTransactionsResponse)

	return nil
}

func sendTransactionWithAccounts(s *ethtest.Suite, fromAccount Account, toAccount Account, nonce uint64) error {
	var to common.Address = common.HexToAddress(toAccount.Address)
	txdata := &types.DynamicFeeTx{
		ChainID:   big.NewInt(3151908),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(10000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1),
	}
	innertx := types.NewTx(txdata)
	prik, err := crypto.HexToECDSA(fromAccount.PrivateKey)
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}
	tx, err := types.SignTx(innertx, types.NewLondonSigner(big.NewInt(3151908)), prik)
	var hashes []common.Hash
	var set = make(map[common.Hash]struct{})
	set[tx.Hash()] = struct{}{}
	hashes = append(hashes, tx.Hash())
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return err
	}

	fmt.Printf("Sending transaction from %s to %s (nonce: %d)\n", fromAccount.Address, toAccount.Address, nonce)

	// Record sending time
	sendStart := time.Now()
	s.SendTxs([]*types.Transaction{tx})
	elapsed := time.Since(sendStart)
	fmt.Printf("Transaction sending time consumed: %v\n", elapsed)

	// Refer to sendLargeTransactions verification method, establish connection to verify if transaction is received by node
	conn, err := s.Dial()
	if err != nil {
		fmt.Printf("dial failed: %v", err)
	}
	defer conn.Close()
	if err = conn.Peer(nil); err != nil {
		fmt.Printf("peering failed: %v", err)
	}

	// Create and send pooled transaction request to verify transaction
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    1234,
		GetPooledTransactionsRequest: hashes,
	}
	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		fmt.Printf("could not write to conn: %v", err)
	}
	// Check if the sent transaction was received
	msg := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, &msg); err != nil {
		fmt.Printf("error reading from connection: %v", err)
	}
	if got, want := msg.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in response: got %d, want %d", got, want)
	}
	for _, got := range msg.PooledTransactionsResponse {
		if _, exists := set[got.Hash()]; !exists {
			fmt.Printf("unexpected tx received: %v", got.Hash())
		}
	}

	// printPooledTransactions(msg.PooledTransactionsResponse)

	return nil
}

// sendTransactionWithAccountsAndNonce sends transaction using specified account and nonce, returns transaction hash
func sendTransactionWithAccountsAndNonce(s *ethtest.Suite, fromAccount Account, toAccount Account, nonce uint64) (common.Hash, error) {
	var to common.Address = common.HexToAddress(toAccount.Address)
	txdata := &types.DynamicFeeTx{
		ChainID:   big.NewInt(3151908),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1),
		// Value: func() *big.Int {
		// 	val, ok := new(big.Int).SetString("999999999998000000000000000", 10)
		// 	if !ok {
		// 		panic("failed to parse big integer string")
		// 	}
		// 	return val
		// }(),
	}
	innertx := types.NewTx(txdata)
	prik, err := crypto.HexToECDSA(fromAccount.PrivateKey)
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return common.Hash{}, err
	}
	tx, err := types.SignTx(innertx, types.NewLondonSigner(big.NewInt(3151908)), prik)
	if err != nil {
		fmt.Printf("failed to sign tx: %v", err)
		return common.Hash{}, err
	}

	txHash := tx.Hash()

	// Record sending time
	sendStart := time.Now()
	if s.GetElName() == "reth" {
		// reth must handle recv content
		err = s.SendTxs([]*types.Transaction{tx})
	} else {
		// Other clients can skip recv content handling
		err = s.SendTxsWithoutRecv([]*types.Transaction{tx})
	}
	if err != nil {
		fmt.Printf("failed to send tx: %v", err)
		return common.Hash{}, err
	}
	elapsed := time.Since(sendStart)
	fmt.Printf("Transaction sending time consumed: %v\n", elapsed)

	return txHash, nil
}

// Keep original function for backward compatibility
func sendTransactionWithNonce(s *ethtest.Suite, nonce uint64) error {
	return sendTransactionWithAccounts(s, PredefinedAccounts[0], PredefinedAccounts[1], nonce)
}

func printReceipts(receipts []*eth.ReceiptList68) {
	if len(receipts) == 0 {
		fmt.Println("No receipt data")
		return
	}

	for i, receiptList := range receipts {
		fmt.Printf("=== Receipt list for block %d ===\n", i+1)

		// ReceiptList68 should be a list containing multiple Receipts
		// According to go-ethereum implementation, this should be []*types.Receipt
		if receiptList == nil {
			fmt.Println("Receipt list is empty")
			continue
		}

		// Since the specific structure of ReceiptList68 is unclear, we need to access its fields through reflection
		reflectValue := reflect.ValueOf(receiptList).Elem()
		reflectType := reflectValue.Type()

		fmt.Printf("Receipt list type: %s\n", reflectType.Name())
		fmt.Printf("Field count: %d\n", reflectValue.NumField())

		// Iterate through all fields
		for j := 0; j < reflectValue.NumField(); j++ {
			field := reflectType.Field(j)
			fieldValue := reflectValue.Field(j)

			fmt.Printf("  Field %s (%s): ", field.Name, field.Type)

			// If the field can be accessed
			if fieldValue.CanInterface() {
				switch fieldValue.Kind() {
				case reflect.Slice:
					fmt.Printf("Slice length %d\n", fieldValue.Len())
					// If it's a Receipt slice, print detailed information for each Receipt
					if field.Type.String() == "[]*types.Receipt" {
						for k := 0; k < fieldValue.Len(); k++ {
							receipt := fieldValue.Index(k).Interface().(*types.Receipt)
							printSingleReceipt(receipt, k+1)
						}
					}
				case reflect.Ptr:
					if !fieldValue.IsNil() {
						fmt.Printf("%v\n", fieldValue.Interface())
					} else {
						fmt.Println("nil")
					}
				default:
					fmt.Printf("%v\n", fieldValue.Interface())
				}
			} else {
				fmt.Println("Cannot access")
			}
		}
		fmt.Println()
	}
}

func printSingleReceipt(receipt *types.Receipt, index int) {
	fmt.Printf("    --- Receipt %d ---\n", index)

	// Basic information
	fmt.Printf("    Transaction Type: %d\n", receipt.Type)
	fmt.Printf("    Transaction Hash: %s\n", receipt.TxHash.Hex())
	fmt.Printf("    Status: %d\n", receipt.Status)

	// Gas related information
	fmt.Printf("    Cumulative Gas Used: %d\n", receipt.CumulativeGasUsed)
	fmt.Printf("    Gas Used: %d\n", receipt.GasUsed)
	if receipt.EffectiveGasPrice != nil {
		fmt.Printf("    Effective Gas Price: %s Wei\n", receipt.EffectiveGasPrice.String())
	}

	// Contract address (if it's a contract creation transaction)
	if receipt.ContractAddress != (common.Address{}) {
		fmt.Printf("    Contract Address: %s\n", receipt.ContractAddress.Hex())
	} else {
		fmt.Printf("    Contract Address: None (not a contract creation transaction)\n")
	}

	// Block information
	if receipt.BlockHash != (common.Hash{}) {
		fmt.Printf("    Block Hash: %s\n", receipt.BlockHash.Hex())
	}
	if receipt.BlockNumber != nil {
		fmt.Printf("    Block Number: %d\n", receipt.BlockNumber.Uint64())
	}
	fmt.Printf("    Transaction Index: %d\n", receipt.TransactionIndex)

	// Bloom filter
	fmt.Printf("    Bloom Filter: %x\n", receipt.Bloom)

	// Blob related information (if exists)
	if receipt.BlobGasUsed > 0 {
		fmt.Printf("    Blob Gas Used: %d\n", receipt.BlobGasUsed)
	}
	if receipt.BlobGasPrice != nil {
		fmt.Printf("    Blob Gas Price: %s Wei\n", receipt.BlobGasPrice.String())
	}

	// Log information
	if len(receipt.Logs) > 0 {
		fmt.Printf("    Log Count: %d\n", len(receipt.Logs))
		for j, log := range receipt.Logs {
			fmt.Printf("      Log %d:\n", j+1)
			fmt.Printf("        Address: %s\n", log.Address.Hex())
			fmt.Printf("        Topic Count: %d\n", len(log.Topics))
			for k, topic := range log.Topics {
				fmt.Printf("        Topic %d: %s\n", k+1, topic.Hex())
			}
			fmt.Printf("        Data Length: %d bytes\n", len(log.Data))
			if len(log.Data) > 0 && len(log.Data) <= 64 {
				fmt.Printf("        Data: %x\n", log.Data)
			}
		}
	} else {
		fmt.Printf("    Logs: None\n")
	}

	fmt.Println()
}

func getReceipts(s *ethtest.Suite) (list []*eth.ReceiptList68, err error) {
	conn, err := s.DialAndPeer(nil)
	if err != nil {
		fmt.Printf("peering failed: %v", err)
	}
	defer conn.Close()

	// Find some blocks containing receipts.
	var hashes = make([]common.Hash, 0, 3)
	for i := range s.GetChain().Len() {
		block := s.GetChain().GetBlock(i)
		if len(block.Transactions()) > 0 {
			hashes = append(hashes, block.Hash())
		}
		if len(hashes) == cap(hashes) {
			break
		}
	}

	// Create block bodies request.
	req := &eth.GetReceiptsPacket{
		RequestId:          66,
		GetReceiptsRequest: (eth.GetReceiptsRequest)(hashes),
	}
	if err := conn.Write(1, eth.GetReceiptsMsg, req); err != nil {
		fmt.Printf("could not write to connection: %v", err)
	}
	fmt.Println("req: ", req)
	// Wait for response.
	resp := new(eth.ReceiptsPacket[*eth.ReceiptList68])
	if err := conn.ReadMsg(1, eth.ReceiptsMsg, &resp); err != nil {
		fmt.Printf("error reading block bodies msg: %v", err)
	}
	if got, want := resp.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id in respond: got %d, want %d", got, want)
	}
	if len(resp.List) != len(req.GetReceiptsRequest) {
		fmt.Printf("wrong bodies in response: expected %d bodies, got %d", len(req.GetReceiptsRequest), len(resp.List))
	}
	return resp.List, err
}

func printHeaders(headers *eth.BlockHeadersPacket) {
	for i, header := range headers.BlockHeadersRequest {
		fmt.Printf("=== Header %d ===\n", i+1)
		fmt.Printf("Block Number: %d\n", header.Number.Uint64())
		fmt.Printf("Block Hash: %s\n", header.Hash().Hex())
		fmt.Printf("Parent Block Hash: %s\n", header.ParentHash.Hex())
		fmt.Printf("Timestamp: %d\n", header.Time)
		fmt.Printf("Gas Limit: %d\n", header.GasLimit)
		fmt.Printf("Gas Used: %d\n", header.GasUsed)
		fmt.Printf("Difficulty: %s\n", header.Difficulty.String())
		fmt.Printf("Miner Address: %s\n", header.Coinbase.Hex())
		fmt.Printf("State Root: %s\n", header.Root.Hex())
		fmt.Printf("Transaction Root: %s\n", header.TxHash.Hex())
		fmt.Printf("Receipt Root: %s\n", header.ReceiptHash.Hex())
		fmt.Println()
	}
}

func GetBlockHeaders(suite *ethtest.Suite) (*eth.BlockHeadersPacket, error) {
	// chain, err := ethtest.NewChain("./testdata")
	// if err != nil {
	// 	return nil, err
	// }
	conn, err := suite.DialAndPeer(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := &eth.GetBlockHeadersPacket{
		RequestId: 33,
		GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
			Origin:  eth.HashOrNumber{Number: uint64(0)},
			Amount:  uint64(512),
			Skip:    5,
			Reverse: false,
		},
	}
	// Read headers response.
	if err = conn.Write(1, eth.GetBlockHeadersMsg, req); err != nil {
		fmt.Printf("could not write to connection: %v", err)
	}
	headers := new(eth.BlockHeadersPacket)
	if err = conn.ReadMsg(1, eth.BlockHeadersMsg, &headers); err != nil {
		fmt.Printf("error reading msg: %v", err)
	}
	if got, want := headers.RequestId, req.RequestId; got != want {
		fmt.Printf("unexpected request id")
	}
	// Check for correct headers.
	// expected, err := suite.GetChain().GetHeaders(req)
	// if err != nil {
	// 	fmt.Printf("failed to get headers for given request: %v", err)
	// }
	// if !headersMatch(expected, headers.BlockHeadersRequest) {
	// 	fmt.Printf("header mismatch: \nexpected %v \ngot %v", expected, headers)
	// }
	return headers, nil
}

// headersMatch returns whether the received headers match the given request
func headersMatch(expected []*types.Header, headers []*types.Header) bool {
	return reflect.DeepEqual(expected, headers)
}
