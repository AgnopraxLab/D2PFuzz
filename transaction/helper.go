package transaction

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
)

// QuickSend is a convenience function for sending a simple transaction
// This replaces the various sendTransactionWithAccountsAndNonce functions
func QuickSend(client *ethclient.Client, from, to config.Account, nonce uint64, chainID *big.Int) (common.Hash, error) {
	tx, err := NewBuilder(chainID).
		WithFrom(from).
		WithTo(to).
		WithNonce(nonce).
		WithType(TxTypeLegacy).
		WithGas(33554432).
		Build()

	if err != nil {
		return common.Hash{}, err
	}

	// Disable verification for QuickSend to match original behavior
	// In fast test environments, transactions may be included in blocks
	// before verification completes, causing GetPooledTransactions to fail
	opts := DefaultSendOptions()
	opts.Verify = false
	return Send(client, tx, opts)
}

// QuickSendDynamic sends a dynamic fee transaction
func QuickSendDynamic(client *ethclient.Client, from, to config.Account, nonce uint64, chainID *big.Int) (common.Hash, error) {
	tx, err := NewBuilder(chainID).
		WithFrom(from).
		WithTo(to).
		WithNonce(nonce).
		WithType(TxTypeDynamic).
		Build()

	if err != nil {
		return common.Hash{}, err
	}

	return Send(client, tx, DefaultSendOptions())
}

// BuildSimpleTx builds a simple transaction with minimal parameters
func BuildSimpleTx(from, to config.Account, nonce uint64, chainID *big.Int, txType TxType) (*types.Transaction, error) {
	return NewBuilder(chainID).
		WithFrom(from).
		WithTo(to).
		WithNonce(nonce).
		WithType(txType).
		Build()
}

// BuildBatchTxs builds a batch of transactions with sequential nonces
func BuildBatchTxs(from, to config.Account, startNonce uint64, count int, chainID *big.Int, txType TxType) ([]*types.Transaction, error) {
	txs := make([]*types.Transaction, count)

	for i := 0; i < count; i++ {
		tx, err := NewBuilder(chainID).
			WithFrom(from).
			WithTo(to).
			WithNonce(startNonce + uint64(i)).
			WithType(txType).
			Build()

		if err != nil {
			return nil, err
		}

		txs[i] = tx
	}

	return txs, nil
}

// ExtractHashes extracts hashes from a slice of transactions
func ExtractHashes(txs []*types.Transaction) []common.Hash {
	hashes := make([]common.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash()
	}
	return hashes
}

// ParseJWTSecretFromHexString parses hexadecimal string directly
func ParseJWTSecretFromHexString(hexString string) ([]byte, error) {
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
