package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"math"
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

	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
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

func main() {
	// ========== Test Configuration Variables ==========
	// Modify these variables to control test behavior without console input
	// 1. Read configuration from config.yaml file in current directory
	config, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}
	// Test mode:
	// "multi" = multi-node testing,
	// "single" = single node testing,
	// "oneTransaction" = single transaction testing,
	// "largeTransactions" = large batch transaction testing
	// "GetPooledTxs" = test GetPooledTransactions
	// "test-soft-limit" = test NewPooledTransactionHashes soft limit
	// "test-soft-limit-single" = test NewPooledTransactionHashes soft limit for single client
	// "test-soft-limit-report" = generate concise test report for all clients
	testMode := "test-soft-limit-report"

	getPooledTxsNodeIndex := 1 //0:"geth", 1:"nethermind", 2:"reth", 3:"erigon", 4:"besu"

	// Multi-node testing configuration (only effective when testMode = "multi")
	multiNodeNonceInitialValues := []uint64{
		0, // Node 0 (geth) initial nonce
		0, // Node 1 (nethermind) initial nonce
		0, // Node 2 (reth) initial nonce
		0, // Node 3 (erigon) initial nonce
		0, // Node 4 (besu) initial nonce
	}
	multiNodeBatchSize := 20 // Number of transactions to send per node

	// Single node testing configuration (only effective when testMode = "single")
	singleNodeIndex := 1          // Node index to test (0=geth, 1=nethermind, 2=reth, 3=erigon, 4=besu)
	singleNodeNonce := uint64(53) // Starting nonce value
	singleNodeBatchSize := 4      // Number of transactions to send

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
	case "GetPooledTxs":
		fmt.Println("=== D2PFuzz GetPooledTxs Testing Tool ===")
		getPooledTxs(config, getPooledTxsNodeIndex)
		// Test soft limit
	case "test-soft-limit":
		fmt.Println("=== D2PFuzz Test All Clients Soft Limit ===")
		TestAllClientsSoftLimit(config)

	// Or test single client
	case "test-soft-limit-single":
		nodeIndex := 1             // 0: geth, 1: nethermind, 2: reth, 3: erigon, 4: besu
		hashCount := 4096          // Test 4096 hashes (at soft limit)
		startNonce := uint64(9999) // Start from real nonce value

		elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
		fmt.Printf("\n========================================\n")
		fmt.Printf("Testing: %s\n", strings.ToUpper(elNames[nodeIndex]))
		fmt.Printf("Scenario: %d items\n", hashCount)
		fmt.Printf("Starting nonce: %d\n", startNonce)
		fmt.Printf("========================================\n\n")

		requested, status, err := TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(config, nodeIndex, hashCount, startNonce)
		if err != nil {
			fmt.Printf("❌ Test error: %v\n", err)
		} else {
			percentage := float64(requested) * 100.0 / float64(hashCount)
			symbol := "✓"
			if requested < hashCount && hashCount > 4096 {
				symbol = "⚠"
			}
			if status != "SUCCESS" {
				symbol = "❌"
			}

			fmt.Printf("\n========================================\n")
			fmt.Printf("Result: %s %d/%d (%.1f%%) [%s]\n", symbol, requested, hashCount, percentage, status)

			// Analyze result
			if status == "SUCCESS" {
				if requested == hashCount {
					if hashCount <= 4096 {
						fmt.Printf("Status: ✅ PASS - All announcements accepted (within limit)\n")
					} else {
						fmt.Printf("Status: ❌ FAIL - No soft limit enforced\n")
					}
				} else if requested == 4096 && hashCount > 4096 {
					fmt.Printf("Status: ✅ PASS - Soft limit (4096) correctly enforced\n")
				} else if requested < 4096 {
					fmt.Printf("Status: ⚠ PARTIAL - Custom limit at %d items\n", requested)
				} else {
					fmt.Printf("Status: ⚠ MIXED - Inconsistent behavior\n")
				}
			} else {
				fmt.Printf("Status: %s\n", status)
			}
			fmt.Printf("========================================\n")
		}

	// Test report mode - for generating concise test reports
	case "test-soft-limit-report":
		fmt.Println("=== D2PFuzz Soft Limit Test Report ===")
		TestSoftLimitForReport(config)

	case "oneTransaction":
		// Single node testing, send only one transaction
		fmt.Println("=== D2PFuzz Single-Transaction Testing Tool ===")

		sendTransaction(config)
	case "largeTransactions":
		// Single node testing, send only one transaction
		fmt.Println("=== D2PFuzz Large-Transaction Testing Tool ===")
		sendLargeTransactions(config)

	default:
		fmt.Printf("Invalid test mode: %s. Valid modes: multi, single\n", testMode)
	}
}

// NewNodeAccountManager creates node account manager
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

// NewNodeAccountManagerWithNonces creates node account manager with custom initial nonce values
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

// GetNodeAccount gets account information for specified node
func (nam *NodeAccountManager) GetNodeAccount(nodeIndex int) *NodeAccount {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		return nodeAccount
	}
	return nil
}

// IncrementNonce increments nonce value for specified node
func (nam *NodeAccountManager) IncrementNonce(nodeIndex int) {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		nodeAccount.Nonce++
	}
}

// DecrementNonce decrements nonce value for specified node
func (nam *NodeAccountManager) DecrementNonce(nodeIndex int) {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		nodeAccount.Nonce--
	}
}

// GetCurrentNonce gets current nonce value for specified node
func (nam *NodeAccountManager) GetCurrentNonce(nodeIndex int) uint64 {
	if nodeAccount, exists := nam.nodeAccounts[nodeIndex]; exists {
		return nodeAccount.Nonce
	}
	return 0
}

// NewAccountManager creates new account manager
func NewAccountManager(accounts []Account) *AccountManager {
	return &AccountManager{
		accounts:    accounts,
		currentFrom: 0,
		currentTo:   1,
	}
}

// GetNextAccountPair gets next account pair (sender and receiver)
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

// GetAccountByIndex gets account by index
func (am *AccountManager) GetAccountByIndex(index int) Account {
	if index < 0 || index >= len(am.accounts) {
		return am.accounts[0] // Default to return first account
	}
	return am.accounts[index]
}

// GetTotalAccounts gets total number of accounts
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

// parseJWTSecretFromHexString parses hexadecimal string directly
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

// runSingleNodeTestingWithUI handles user interaction logic for single node testing
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

	// Parse node info
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
	hashFilePath := "/home/kkk/workspaces/github.com/AgnopraxLab/D2PFuzz/manual/txhashes.txt"
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
		// nodeAccountManager.DecrementNonce(elIndex)
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
	hashFilePath := "/home/kkk/workspaces/github.com/AgnopraxLab/D2PFuzz/manual/txhashes.txt"
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

		// Parse node info
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
func queryTransactionByHash(s *ethtest.Suite, txHashs []common.Hash) ([]*types.Transaction, error) {
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
		GetPooledTransactionsRequest: txHashs,
	}

	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		return nil, fmt.Errorf("failed to write transaction query: %v", err)
	}
	fmt.Println("req: ", req)
	// Wait for response
	err = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
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

	// Check response and count successful transactions
	successCount := len(resp.PooledTransactionsResponse)
	fmt.Printf("Successfully found %d out of %d transactions\n", successCount, len(txHashs))

	if successCount == 0 {
		fmt.Printf("No transactions found for the requested %d hashes\n", len(txHashs))
		return nil, fmt.Errorf("no transactions found")
	}

	// Print details of found transactions
	for i, foundTx := range resp.PooledTransactionsResponse {
		fmt.Printf("Transaction %d: %s\n", i+1, foundTx.Hash().Hex())

		// Try to match with requested hashes
		for _, requestedHash := range txHashs {
			if foundTx.Hash() == requestedHash {
				fmt.Printf("  ✓ Matches requested hash: %s\n", requestedHash.Hex())
				break
			}
		}
	}

	// Return all found transactions
	return resp.PooledTransactionsResponse, nil
}

func sendLargeTransactions(config *Config) (eth.PooledTransactionsResponse, []common.Hash) {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return eth.PooledTransactionsResponse{}, nil
	}

	nodeIndex := 0 //0:"geth", 1:"nethermind", 2:"reth", 3:"erigon", 4:"besu"
	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
	enodeStr := config.P2P.BootstrapNodes[nodeIndex]
	node, _ := enode.Parse(enode.ValidSchemes, enodeStr)
	s, _ := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[nodeIndex])
	fmt.Printf("🎯 Starting large transactions testing for %s ...\n", s.GetElName())
	// This test first sends count transactions to the node, then requests these transactions using GetPooledTransactions on another peer connection.
	var (
		nonce  = uint64(math.MaxUint64)
		from   = PredefinedAccounts[0].PrivateKey
		count  = 1000
		txs    []*types.Transaction
		hashes []common.Hash
		set    = make(map[common.Hash]struct{})
	)
	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		fmt.Println("failed to generate private key")
		return nil, nil
	}
	var to common.Address = common.HexToAddress(PredefinedAccounts[5].Address)
	for i := 0; i < count; i++ {
		inner := &types.DynamicFeeTx{
			ChainID: big.NewInt(3151908),
			// Nonce:     nonce + uint64(i),
			Nonce:     nonce - uint64(i),
			GasTipCap: big.NewInt(3000000000),
			GasFeeCap: big.NewInt(30000000000),
			Gas:       21000,
			To:        &to,
			Value:     big.NewInt(1),
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
	fmt.Println("txHash: ", hashes[0])
	if err := writeHashesToFile([]common.Hash{hashes[0]}, "./txhash.txt"); err != nil {
		fmt.Printf("Failed to write hashes to file: %v\n", err)
	}
	// Send txs.
	// Record sending time
	sendStart := time.Now()
	s.SendTxsWithoutRecv(txs)
	elapsed := time.Since(sendStart)
	if len(txs) == 1 {
		fmt.Println("The hash value of this transaction is:\n", hashes[0])
	}
	fmt.Printf("Transaction sending time consumed: %v", elapsed)

	// Write transaction hashes to file
	hashFilePath := "/home/kkk/workspaces/github.com/AgnopraxLab/D2PFuzz/manual/txhashes.txt"
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

// TestNewPooledTransactionHashesSoftLimit tests client implementation of NewPooledTransactionHashes message soft limit
// The recommended soft limit is 4096 items (~150 KiB)
// quiet: if true, reduces output verbosity for report generation
func TestNewPooledTransactionHashesSoftLimit(config *Config, nodeIndex int, hashCount int, quiet bool) error {
	// Use large nonce to avoid conflicts with real transactions
	startNonce := uint64(math.MaxUint64) - uint64(hashCount)
	return TestNewPooledTransactionHashesSoftLimitWithNonce(config, nodeIndex, hashCount, startNonce, quiet)
}

// TestNewPooledTransactionHashesSoftLimitWithNonceDetailed tests with custom starting nonce and returns detailed results
func TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(config *Config, nodeIndex int, hashCount int, startNonce uint64) (int, string, error) {
	fmt.Print("  Preparing test... ")

	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
	enodeStr := config.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[nodeIndex])
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to create suite: %v", err)
	}

	// Generate transactions
	var (
		from    = PredefinedAccounts[0].PrivateKey
		nonce   = startNonce
		hashes  = make([]common.Hash, hashCount)
		txTypes = make([]byte, hashCount)
		sizes   = make([]uint32, hashCount)
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to generate private key: %v", err)
	}

	fmt.Print("Done\n  Generating transactions... ")
	for i := 0; i < hashCount; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   big.NewInt(3151908),
			Nonce:     nonce + uint64(i),
			GasTipCap: big.NewInt(3000000000),
			GasFeeCap: big.NewInt(30000000000),
			Gas:       21000,
		}
		tx := types.NewTx(inner)
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(3151908)), prik)
		if err != nil {
			return 0, "ERROR", fmt.Errorf("failed to sign tx: %v", err)
		}
		hashes[i] = signedTx.Hash()
		txTypes[i] = signedTx.Type()
		sizes[i] = uint32(signedTx.Size())
	}
	fmt.Print("Done\n  Connecting to peer... ")

	// Connect to node
	conn, err := s.Dial()
	if err != nil {
		return 0, "ERROR", fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return 0, "ERROR", fmt.Errorf("peering failed: %v", err)
	}
	fmt.Print("Done\n  Sending announcement... ")

	// Send announcement
	ann := eth.NewPooledTransactionHashesPacket{
		Types:  txTypes,
		Sizes:  sizes,
		Hashes: hashes,
	}

	startTime := time.Now()
	err = conn.Write(1, eth.NewPooledTransactionHashesMsg, ann)
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to write to connection: %v", err)
	}
	fmt.Print("Done\n  Waiting for response... ")

	// Set timeout
	timeout := 30*time.Second + time.Duration(hashCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return 0, "ERROR", fmt.Errorf("failed to set read deadline: %v", err)
	}

	// Wait for node response
	for {
		msg, err := conn.ReadEth()
		if err != nil {
			if err == io.EOF {
				return 0, "DISCONNECT", nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, "TIMEOUT", nil
			}
			return 0, "ERROR", fmt.Errorf("failed to read eth msg: %v", err)
		}

		switch msg := msg.(type) {
		case *eth.GetPooledTransactionsPacket:
			elapsed := time.Since(startTime)
			requestedCount := len(msg.GetPooledTransactionsRequest)
			fmt.Printf("Done (%.2fs)\n", elapsed.Seconds())
			return requestedCount, "SUCCESS", nil

		case *eth.NewPooledTransactionHashesPacket:
			continue
		case *eth.TransactionsPacket:
			continue
		default:
			continue
		}
	}
}

// TestNewPooledTransactionHashesSoftLimitWithNonce tests with custom starting nonce
func TestNewPooledTransactionHashesSoftLimitWithNonce(config *Config, nodeIndex int, hashCount int, startNonce uint64, quiet bool) error {
	requested, status, err := TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(config, nodeIndex, hashCount, startNonce)
	_ = requested
	_ = status
	return err
}

// Original function for backwards compatibility (kept but now calls the detailed version)
func TestNewPooledTransactionHashesSoftLimitWithNonceOld(config *Config, nodeIndex int, hashCount int, startNonce uint64, quiet bool) error {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
	enodeStr := config.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[nodeIndex])
	if err != nil {
		return fmt.Errorf("failed to create suite: %v", err)
	}

	if !quiet {
		fmt.Printf("\n========================================\n")
		fmt.Printf("Testing %s with %d transaction hashes\n", elNames[nodeIndex], hashCount)
		fmt.Printf("Soft limit: 4096 items (~150 KiB)\n")
		fmt.Printf("========================================\n")
	}

	// Generate specified number of transactions
	var (
		from    = PredefinedAccounts[0].PrivateKey
		nonce   = startNonce
		hashes  = make([]common.Hash, hashCount)
		txTypes = make([]byte, hashCount)
		sizes   = make([]uint32, hashCount)
	)

	if !quiet {
		fmt.Printf("Starting nonce: %d, ending nonce: %d\n", nonce, nonce+uint64(hashCount)-1)
	}

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	if !quiet {
		fmt.Printf("Generating %d transactions...\n", hashCount)
	}
	for i := 0; i < hashCount; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   big.NewInt(3151908),
			Nonce:     nonce + uint64(i),
			GasTipCap: big.NewInt(3000000000),
			GasFeeCap: big.NewInt(30000000000),
			Gas:       21000,
		}
		tx := types.NewTx(inner)
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(3151908)), prik)
		if err != nil {
			return fmt.Errorf("failed to sign tx: %v", err)
		}
		hashes[i] = signedTx.Hash()
		txTypes[i] = signedTx.Type()
		sizes[i] = uint32(signedTx.Size())

		if !quiet && (i+1)%1000 == 0 {
			fmt.Printf("Generated %d/%d transactions\n", i+1, hashCount)
		}
	}
	if !quiet {
		fmt.Printf("✓ Generated %d transactions\n", hashCount)

		// Calculate message size
		// Each hash: 32 bytes, type: 1 byte, size: 4 bytes = 37 bytes/item
		estimatedSize := hashCount * 37
		fmt.Printf("Estimated message size: ~%d bytes (~%.2f KiB)\n", estimatedSize, float64(estimatedSize)/1024.0)
	}

	// Connect to node
	conn, err := s.Dial()
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}
	if !quiet {
		fmt.Printf("✓ Connected to peer\n")
	}

	// Send announcement
	ann := eth.NewPooledTransactionHashesPacket{
		Types:  txTypes,
		Sizes:  sizes,
		Hashes: hashes,
	}

	startTime := time.Now()
	err = conn.Write(1, eth.NewPooledTransactionHashesMsg, ann)
	if err != nil {
		return fmt.Errorf("failed to write to connection: %v", err)
	}
	if !quiet {
		fmt.Printf("✓ Sent NewPooledTransactionHashes announcement\n")
	}

	// Set timeout - dynamic based on transaction count
	// Base: 30s, add 10s per 1000 transactions
	timeout := 30*time.Second + time.Duration(hashCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second // Minimum 60 seconds for reliability
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return fmt.Errorf("failed to set read deadline: %v", err)
	}

	// Wait for node response
	if !quiet {
		fmt.Printf("\nWaiting for node response...\n")
	}
	requestReceived := false
	requestedCount := 0
	disconnected := false

	for {
		msg, err := conn.ReadEth()
		if err != nil {
			if err == io.EOF {
				fmt.Printf("⚠ Connection closed by peer\n")
				disconnected = true
				break
			}
			// May be timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("⏱ Read timeout - no response from node\n")
				break
			}
			return fmt.Errorf("failed to read eth msg: %v", err)
		}

		switch msg := msg.(type) {
		case *eth.GetPooledTransactionsPacket:
			elapsed := time.Since(startTime)
			requestReceived = true
			requestedCount = len(msg.GetPooledTransactionsRequest)

			if !quiet {
				fmt.Printf("\n✓ Received GetPooledTransactionsPacket\n")
				fmt.Printf("  Response time: %v\n", elapsed)
				fmt.Printf("  Requested transactions: %d/%d (%.2f%%)\n",
					requestedCount, hashCount, float64(requestedCount)*100.0/float64(hashCount))
				// Analyze node behavior
				if requestedCount == hashCount {
					fmt.Printf("  ✓ Node requested ALL announced transactions\n")
				} else if requestedCount == 4096 && hashCount > 4096 {
					fmt.Printf("  ✓ Node ENFORCED soft limit (4096 items)\n")
				} else if requestedCount < hashCount {
					fmt.Printf("  ⚠ Node requested PARTIAL transactions (possible soft limit: %d)\n", requestedCount)
				} else {
					fmt.Printf("  ⚠ Unexpected behavior\n")
				}
			}

			return nil

		case *eth.NewPooledTransactionHashesPacket:
			// Node may send its own transaction announcements, ignore
			if !quiet {
				fmt.Printf("  (Received NewPooledTransactionHashesPacket from node, ignoring)\n")
			}
			continue

		case *eth.TransactionsPacket:
			// Node may send transactions, ignore
			if !quiet {
				fmt.Printf("  (Received TransactionsPacket from node, ignoring)\n")
			}
			continue

		default:
			if !quiet {
				fmt.Printf("  ⚠ Received unexpected message type: %T\n", msg)
			}
			continue
		}
	}

	// Summarize results
	if !quiet {
		fmt.Printf("\n========================================\n")
		fmt.Printf("Test Summary for %s:\n", elNames[nodeIndex])
		fmt.Printf("  Announced: %d transactions\n", hashCount)
		if disconnected {
			fmt.Printf("  Result: ❌ Node DISCONNECTED (may reject oversized announcements)\n")
		} else if requestReceived {
			fmt.Printf("  Result: ✓ Node responded\n")
			if requestedCount == hashCount {
				fmt.Printf("  Behavior: Accepts all announcements (no soft limit enforced)\n")
			} else {
				fmt.Printf("  Behavior: Enforces limit at %d items\n", requestedCount)
			}
		} else {
			fmt.Printf("  Result: ⚠ No response (timeout or silent rejection)\n")
		}
		fmt.Printf("========================================\n\n")
	}

	return nil
}

// TestAllClientsSoftLimit tests soft limit implementation for all clients
func TestAllClientsSoftLimit(config *Config) {
	testCases := []struct {
		name  string
		count int
	}{
		{"Normal (50 items)", 50},
		{"Medium (1000 items)", 1000},
		{"At Limit (4096 items)", 4096},
		{"Over Limit (5000 items)", 5000},
		{"Well Over Limit (8192 items)", 8192},
		{"Extreme (10000 items)", 10000},
	}

	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}

	for nodeIndex, elName := range elNames {
		if nodeIndex >= len(config.P2P.BootstrapNodes) {
			fmt.Printf("Skipping %s (no node configured)\n", elName)
			continue
		}

		fmt.Printf("\n\n╔════════════════════════════════════════╗\n")
		fmt.Printf("║  Testing Client: %-20s ║\n", elName)
		fmt.Printf("╚════════════════════════════════════════╝\n")

		for _, tc := range testCases {
			fmt.Printf("\n--- Test Case: %s ---\n", tc.name)
			err := TestNewPooledTransactionHashesSoftLimit(config, nodeIndex, tc.count, false)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			}

			// Wait before next test
			time.Sleep(2 * time.Second)
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSoftLimitForReport runs soft limit tests for all clients and generates a concise report
func TestSoftLimitForReport(config *Config) {
	// Test scenarios focusing on boundary values
	testCases := []int{4096, 5000, 8192}
	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}

	// Store results: clientName -> [announced]requested
	type TestResult struct {
		announced int
		requested int
		status    string // "PASS", "FAIL", "ERROR", "DISCONNECT"
	}
	results := make(map[string]map[int]TestResult)

	fmt.Println("\nTesting all clients with key scenarios...")
	fmt.Println("Scenarios: 4096 items (at limit), 5000 items (over limit), 8192 items (2x limit)")
	fmt.Println(strings.Repeat("=", 80))

	// Test each client
	for nodeIndex, clientName := range elNames {
		if nodeIndex >= len(config.P2P.BootstrapNodes) {
			fmt.Printf("⚠ Skipping %s (not configured)\n", clientName)
			continue
		}

		results[clientName] = make(map[int]TestResult)
		fmt.Printf("\n[%s]\n", strings.ToUpper(clientName))

		for _, announced := range testCases {
			fmt.Printf("  Testing %d items... ", announced)

			// Retry mechanism for reliability (especially for slow clients like nethermind)
			var requested int
			var status string
			maxRetries := 2

			for attempt := 0; attempt <= maxRetries; attempt++ {
				requested, status = runQuietTest(config, nodeIndex, announced)

				// If successful, break
				if status == "SUCCESS" {
					break
				}

				// If timeout or error, retry
				if attempt < maxRetries && (status == "TIMEOUT" || status == "ERROR") {
					fmt.Printf("retry...")
					time.Sleep(2 * time.Second)
					continue
				}
			}

			results[clientName][announced] = TestResult{
				announced: announced,
				requested: requested,
				status:    status,
			}

			// Print concise result
			percentage := float64(requested) * 100.0 / float64(announced)
			symbol := "✓"
			if requested < announced && announced > 4096 {
				symbol = "⚠"
			}
			if status == "ERROR" || status == "TIMEOUT" || status == "DISCONNECT" {
				symbol = "❌"
			}

			fmt.Printf("%s %d/%d (%.0f%%) [%s]\n", symbol, requested, announced, percentage, status)

			time.Sleep(1 * time.Second)
		}
	}

	// Generate report table
	fmt.Println("\n" + strings.Repeat("=", 88))
	fmt.Println("                    SOFT LIMIT TEST REPORT")
	fmt.Println(strings.Repeat("=", 88))
	fmt.Printf("%-12s | %-10s | %-10s | %-10s | %-25s\n",
		"Client", "4096 items", "5000 items", "8192 items", "Status")
	fmt.Println(strings.Repeat("-", 88))

	passCount := 0
	for _, clientName := range elNames {
		if _, exists := results[clientName]; !exists {
			continue
		}

		r4096 := results[clientName][4096]
		r5000 := results[clientName][5000]
		r8192 := results[clientName][8192]

		// Check for errors/timeouts first
		status := ""
		if r4096.status == "TIMEOUT" || r5000.status == "TIMEOUT" || r8192.status == "TIMEOUT" {
			status = "⏱ TIMEOUT"
		} else if r4096.status == "ERROR" || r5000.status == "ERROR" || r8192.status == "ERROR" {
			status = "❌ ERROR"
		} else if r4096.status == "DISCONNECT" || r5000.status == "DISCONNECT" || r8192.status == "DISCONNECT" {
			status = "🔌 DISCONNECT"
		} else if r5000.requested == 4096 && r8192.requested == 4096 {
			// PASS: Both 5000 and 8192 tests limited to 4096
			status = "✅ PASS"
			passCount++
		} else if r5000.requested == 5000 && r8192.requested == 8192 {
			// FAIL: Accepts all announcements (no limit)
			status = "❌ FAIL (No limit)"
		} else if r5000.requested < 4096 || r8192.requested < 4096 {
			// PARTIAL: Has some limit but < 4096
			status = fmt.Sprintf("⚠ PARTIAL (limit=%d)", min(r5000.requested, r8192.requested))
		} else {
			status = "⚠ MIXED"
		}

		fmt.Printf("%-12s | %4d (100%%) | %4d (%3.0f%%) | %4d (%3.0f%%) | %-25s\n",
			clientName,
			r4096.requested,
			r5000.requested, float64(r5000.requested)*100.0/5000.0,
			r8192.requested, float64(r8192.requested)*100.0/8192.0,
			status)
	}

	fmt.Println(strings.Repeat("=", 88))
	fmt.Printf("\nSummary: %d/%d clients correctly enforce the 4096 soft limit\n",
		passCount, len(results))
	fmt.Println("\nStatus Legend:")
	fmt.Println("  ✅ PASS         - Correctly enforces 4096 soft limit")
	fmt.Println("  ❌ FAIL         - No limit enforced (accepts all)")
	fmt.Println("  ⚠ PARTIAL      - Has custom limit < 4096")
	fmt.Println("  ⚠ MIXED        - Inconsistent behavior")
	fmt.Println("  ⏱ TIMEOUT      - Request timed out (may need longer timeout)")
	fmt.Println("  🔌 DISCONNECT  - Connection closed by peer")
	fmt.Println("  ❌ ERROR       - Test error occurred")

	// Markdown format
	fmt.Println("\n" + strings.Repeat("-", 80))
	fmt.Println("Markdown format (copy-paste ready):")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println("\n## NewPooledTransactionHashes Soft Limit Test Results\n")
	fmt.Println("| Client     | 4096 items | 5000 items | 8192 items | Status               |")
	fmt.Println("|------------|-----------|-----------|-----------|----------------------|")

	for _, clientName := range elNames {
		if _, exists := results[clientName]; !exists {
			continue
		}

		r4096 := results[clientName][4096]
		r5000 := results[clientName][5000]
		r8192 := results[clientName][8192]

		status := ""
		if r4096.status == "TIMEOUT" || r5000.status == "TIMEOUT" || r8192.status == "TIMEOUT" {
			status = "⏱ Timeout"
		} else if r4096.status == "ERROR" || r5000.status == "ERROR" || r8192.status == "ERROR" {
			status = "❌ Error"
		} else if r4096.status == "DISCONNECT" || r5000.status == "DISCONNECT" || r8192.status == "DISCONNECT" {
			status = "🔌 Disconnect"
		} else if r5000.requested == 4096 && r8192.requested == 4096 {
			status = "✅ Enforced"
		} else if r5000.requested == 5000 && r8192.requested == 8192 {
			status = "❌ Not enforced"
		} else if r5000.requested < 4096 || r8192.requested < 4096 {
			status = fmt.Sprintf("⚠ Partial (limit=%d)", min(r5000.requested, r8192.requested))
		} else {
			status = "⚠ Mixed"
		}

		fmt.Printf("| %-10s | %4d (100%%) | %4d (%3.0f%%) | %4d (%3.0f%%) | %-20s |\n",
			clientName,
			r4096.requested,
			r5000.requested, float64(r5000.requested)*100.0/5000.0,
			r8192.requested, float64(r8192.requested)*100.0/8192.0,
			status)
	}

	fmt.Printf("\n**Summary:** %d/%d clients correctly enforce the 4096 soft limit\n",
		passCount, len(results))
}

// runQuietTest runs a test and returns the requested count
func runQuietTest(config *Config, nodeIndex int, hashCount int) (int, string) {
	// Use reasonable nonce value (same as single test mode)
	startNonce := uint64(70)
	return runQuietTestWithNonce(config, nodeIndex, hashCount, startNonce)
}

// runQuietTestWithNonce runs a test with custom starting nonce
func runQuietTestWithNonce(config *Config, nodeIndex int, hashCount int, startNonce uint64) (int, string) {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return 0, "ERROR"
	}

	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
	enodeStr := config.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return 0, "ERROR"
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[nodeIndex])
	if err != nil {
		return 0, "ERROR"
	}

	// Generate transactions
	var (
		from    = PredefinedAccounts[0].PrivateKey
		nonce   = startNonce
		hashes  = make([]common.Hash, hashCount)
		txTypes = make([]byte, hashCount)
		sizes   = make([]uint32, hashCount)
	)

	prik, err := crypto.HexToECDSA(from)
	if err != nil {
		return 0, "ERROR"
	}

	for i := 0; i < hashCount; i++ {
		inner := &types.DynamicFeeTx{
			ChainID:   big.NewInt(3151908),
			Nonce:     nonce + uint64(i),
			GasTipCap: big.NewInt(3000000000),
			GasFeeCap: big.NewInt(30000000000),
			Gas:       21000,
		}
		tx := types.NewTx(inner)
		signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(3151908)), prik)
		if err != nil {
			return 0, "ERROR"
		}
		hashes[i] = signedTx.Hash()
		txTypes[i] = signedTx.Type()
		sizes[i] = uint32(signedTx.Size())
	}

	// Connect and send
	conn, err := s.Dial()
	if err != nil {
		return 0, "ERROR"
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return 0, "ERROR"
	}

	ann := eth.NewPooledTransactionHashesPacket{
		Types:  txTypes,
		Sizes:  sizes,
		Hashes: hashes,
	}

	err = conn.Write(1, eth.NewPooledTransactionHashesMsg, ann)
	if err != nil {
		return 0, "ERROR"
	}

	// Dynamic timeout based on transaction count
	timeout := 30*time.Second + time.Duration(hashCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return 0, "ERROR"
	}

	// Wait for response
	for {
		msg, err := conn.ReadEth()
		if err != nil {
			if err == io.EOF {
				return 0, "DISCONNECT"
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, "TIMEOUT"
			}
			return 0, "ERROR"
		}

		switch msg := msg.(type) {
		case *eth.GetPooledTransactionsPacket:
			return len(msg.GetPooledTransactionsRequest), "SUCCESS"
		case *eth.NewPooledTransactionHashesPacket:
			continue
		case *eth.TransactionsPacket:
			continue
		default:
			continue
		}
	}
}

func sendTransaction(config *Config) error {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return err
	}
	enodeStr := config.P2P.BootstrapNodes[1]
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
	// hashFilePath := "/home/kkk/workspaces/github.com/AgnopraxLab/D2PFuzz/test/txhashes.txt"
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
		// Reth must handle recv content
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

func getPooledTxs(config *Config, nodeIndex int) error {
	jwtSecret, err := parseJWTSecretFromHexString(config.P2P.JWTSecret)
	if err != nil {
		return err
	}
	//0:"geth", 1:"nethermind", 2:"reth", 3:"erigon", 4:"besu"
	elNames := []string{"geth", "nethermind", "reth", "erigon", "besu"}
	enodeStr := config.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {

	}
	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), elNames[nodeIndex])
	if err != nil {

	}
	txHashes := []common.Hash{}

	// Read hash values from file
	// file, err := os.Open("/home/kkk/workspaces/github.com/AgnopraxLab/D2PFuzz/manual/txhashes.txt")
	file, err := os.Open("/home/kkk/workspaces/ethereum-package/tx_hashes.txt")
	// file, err := os.Open("/home/kkk/workspaces/ethereum-package/scripts/mempool_hashes.txt")
	if err != nil {
		fmt.Printf("Failed to open txhashes.txt: %v\n", err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and lines starting with #
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Convert hex string to common.Hash and add to array
		txHashes = append(txHashes, common.HexToHash(line))
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading txhashes.txt: %v\n", err)
		return err
	}

	fmt.Printf("Loaded %d transaction hashes from file\n", len(txHashes))

	// Query each transaction hash
	foundTxs, err := queryTransactionByHash(s, txHashes[:])
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
	} else {
		fmt.Printf("Query completed successfully, found %d transactions\n", len(foundTxs))
	}

	return nil
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

	return headers, nil
}

// headersMatch returns whether the received headers match the given request
func headersMatch(expected []*types.Header, headers []*types.Header) bool {
	return reflect.DeepEqual(expected, headers)
}

// PredefinedAccounts are the accounts available when using ethereum-package to create a local test environment
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
