package main

import (
	"math/big"
	"time"
)

// Chain related constants
const (
	// ChainID is the Ethereum chain ID for the test network
	ChainID = 3151908
)

// Gas related constants
const (
	// DefaultGas is the default gas limit for simple transfers
	DefaultGas = 21000

	// LargeGasLimit is used for complex transactions
	LargeGasLimit = 33554432

	// DefaultGasPrice is the default gas price in wei (20 Gwei)
	DefaultGasPrice = 20000000000

	// DefaultGasTipCap is the default priority fee in wei (3 Gwei)
	DefaultGasTipCap = 3000000000

	// DefaultGasFeeCap is the default max fee in wei (30 Gwei)
	DefaultGasFeeCap = 30000000000
)

// Transaction limits
const (
	// SoftLimitThreshold is the recommended soft limit for NewPooledTransactionHashes
	SoftLimitThreshold = 4096

	// MaxUint64Nonce is used for testing with very large nonces
	MaxUint64Nonce = ^uint64(0) // math.MaxUint64
)

// Timeout and delay constants
const (
	// DefaultTimeout is the default operation timeout
	DefaultTimeout = 60 * time.Second

	// DefaultReadTimeout is the default read timeout for connections
	DefaultReadTimeout = 12 * time.Second

	// ShortTimeout is used for quick operations
	ShortTimeout = 30 * time.Second

	// LongTimeout is used for operations that may take longer
	LongTimeout = 120 * time.Second

	// DefaultRetryDelay is the delay between retry attempts
	DefaultRetryDelay = 2 * time.Second

	// TransactionDelay is the delay between sending transactions
	TransactionDelay = 100 * time.Millisecond
)

// Request ID constants
const (
	// DefaultRequestID is used for protocol requests
	DefaultRequestID = 1234

	// GetPooledTxsRequestID is used specifically for GetPooledTransactions
	GetPooledTxsRequestID = 999
)

// Blob related constants (EIP-4844)
const (
	// MaxBlobsPerBlock is the maximum number of blobs per block
	MaxBlobsPerBlock = 6

	// TargetBlobsPerBlock is the target number of blobs per block
	TargetBlobsPerBlock = 3

	// BlobSize is the standard size of a blob (128 KB)
	BlobSize = 131072

	// FieldElementsPerBlob is the number of field elements in a blob
	FieldElementsPerBlob = 4096

	// BytesPerFieldElement is the number of bytes per field element
	BytesPerFieldElement = 32

	// TargetBlobGasPerBlock is the target blob gas per block (3 blobs)
	TargetBlobGasPerBlock = 393216

	// MaxBlobGasPerBlock is the maximum blob gas per block (6 blobs)
	MaxBlobGasPerBlock = 786432

	// BlobGasPerBlob is the gas cost per blob
	BlobGasPerBlob = 131072

	// MinBlobGasPrice is the minimum blob gas price (1 wei)
	MinBlobGasPrice = 1

	// BlobGasPriceUpdateFraction is used for blob gas price calculation
	BlobGasPriceUpdateFraction = 3338477

	// DefaultBlobGasPrice is the default blob gas price (1 Gwei)
	DefaultBlobGasPrice = 1000000000
)

// Helper functions to return big.Int values
var (
	// ChainIDBigInt returns the chain ID as *big.Int
	ChainIDBigInt = big.NewInt(ChainID)

	// DefaultGasPriceBigInt returns the default gas price as *big.Int
	DefaultGasPriceBigInt = big.NewInt(DefaultGasPrice)

	// DefaultGasTipCapBigInt returns the default tip cap as *big.Int
	DefaultGasTipCapBigInt = big.NewInt(DefaultGasTipCap)

	// DefaultGasFeeCapBigInt returns the default fee cap as *big.Int
	DefaultGasFeeCapBigInt = big.NewInt(DefaultGasFeeCap)

	// DefaultBlobGasPriceBigInt returns the default blob gas price as *big.Int
	DefaultBlobGasPriceBigInt = big.NewInt(DefaultBlobGasPrice)

	// OneWei represents 1 wei value
	OneWei = big.NewInt(1)
)

// CalculateDynamicTimeout returns a timeout based on transaction count
// Base: 30s, add 10s per 1000 transactions, minimum 60s
func CalculateDynamicTimeout(txCount int) time.Duration {
	timeout := 30*time.Second + time.Duration(txCount/1000)*10*time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	return timeout
}
