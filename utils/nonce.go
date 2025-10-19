package utils

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/ethclient"

	"github.com/ethereum/go-ethereum/common"
	gethclient "github.com/ethereum/go-ethereum/ethclient"
)

const (
	// MaxNonceRetries is the maximum number of retry attempts for nonce retrieval
	MaxNonceRetries = 3

	// NonceRetryTimeout is the timeout for each nonce retrieval attempt
	NonceRetryTimeout = 10 * time.Second
)

// ParseNonceValue parses a nonce string value
// Returns (nonce, isAuto, error)
// - If value is "auto", returns (0, true, nil)
// - If value is numeric, returns (parsed_value, false, nil)
// - Otherwise returns (0, false, error)
func ParseNonceValue(value string) (uint64, bool, error) {
	value = strings.TrimSpace(value)

	if strings.ToLower(value) == "auto" {
		return 0, true, nil
	}

	nonce, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid nonce value '%s': %w", value, err)
	}

	return nonce, false, nil
}

// GetNonceWithRetry gets nonce from the network with retry mechanism
// Based on fuzzer/tx_fuzzer.go implementation
func GetNonceWithRetry(client *ethclient.Client, address common.Address, maxRetries int) (uint64, error) {
	var nonce uint64
	var err error

	// Create RPC client from node IP
	nodeIP := client.GetNodeIP()
	rpcURL := fmt.Sprintf("http://%s:8545", nodeIP) // Standard RPC port

	rpcClient, err := gethclient.Dial(rpcURL)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to RPC at %s: %w", rpcURL, err)
	}
	defer rpcClient.Close()

	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), NonceRetryTimeout)
		nonce, err = rpcClient.NonceAt(ctx, address, nil)
		cancel()

		if err == nil {
			return nonce, nil
		}

		// Exponential backoff before retry
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return 0, fmt.Errorf("failed to get nonce after %d retries: %w", maxRetries, err)
}

// ResolveNonce resolves a nonce string to an actual nonce value
// - If nonceStr is "auto", retrieves nonce from the network
// - If nonceStr is numeric, parses and returns it
// - Returns error if unable to resolve
func ResolveNonce(client *ethclient.Client, nonceStr string, address common.Address) (uint64, error) {
	nonce, isAuto, err := ParseNonceValue(nonceStr)
	if err != nil {
		return 0, err
	}

	if isAuto {
		// Get nonce from network with retry
		nonce, err = GetNonceWithRetry(client, address, MaxNonceRetries)
		if err != nil {
			return 0, fmt.Errorf("failed to auto-resolve nonce for address %s: %w", address.Hex(), err)
		}
	}

	return nonce, nil
}

// ResolveNonceList resolves a list of nonce strings for multiple accounts
// Returns a list of resolved nonces or error
func ResolveNonceList(client *ethclient.Client, nonceStrs []string, addresses []common.Address) ([]uint64, error) {
	if len(nonceStrs) != len(addresses) {
		return nil, fmt.Errorf("nonce list length (%d) doesn't match address list length (%d)",
			len(nonceStrs), len(addresses))
	}

	nonces := make([]uint64, len(nonceStrs))
	for i, nonceStr := range nonceStrs {
		nonce, err := ResolveNonce(client, nonceStr, addresses[i])
		if err != nil {
			return nil, fmt.Errorf("failed to resolve nonce at index %d: %w", i, err)
		}
		nonces[i] = nonce
	}

	return nonces, nil
}
