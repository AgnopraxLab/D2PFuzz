package account

import (
	"fmt"

	"github.com/AgnopraxLab/D2PFuzz/config"
)

// NodeAccount represents single node account information
type NodeAccount struct {
	FromAccount config.Account
	ToAccount   config.Account
	Nonce       uint64
}

// NodeAccountManager manages independent accounts and nonce for each node
type NodeAccountManager struct {
	nodeAccounts map[int]*NodeAccount // Node index -> Node account information
	totalNodes   int
}

// NewNodeAccountManager creates node account manager
func NewNodeAccountManager(accounts []config.Account, nodeCount int) *NodeAccountManager {
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
func NewNodeAccountManagerWithNonces(accounts []config.Account, nodeCount int, initialNonces []uint64) *NodeAccountManager {
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

