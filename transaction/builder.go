package transaction

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"

	"github.com/AgnopraxLab/D2PFuzz/config"
)

// TxType represents transaction type
type TxType string

const (
	TxTypeLegacy  TxType = "legacy"
	TxTypeDynamic TxType = "dynamic"
	TxTypeEIP1559 TxType = "eip1559"
	TxTypeBlob    TxType = "blob" // EIP-4844 blob transaction
)

// TxOptions holds transaction configuration options
type TxOptions struct {
	From      config.Account
	To        config.Account
	Nonce     uint64
	Value     *big.Int
	GasPrice  *big.Int
	GasTipCap *big.Int
	GasFeeCap *big.Int
	Gas       uint64
	Data      []byte
	ChainID   *big.Int
	TxType    TxType

	// Blob transaction specific (EIP-4844)
	MaxFeePerBlobGas    *big.Int
	BlobVersionedHashes []common.Hash
}

// Builder provides a fluent interface for building transactions
type Builder struct {
	opts TxOptions
}

// NewBuilder creates a new transaction builder with default values
func NewBuilder(chainID *big.Int) *Builder {
	return &Builder{
		opts: TxOptions{
			Value:     big.NewInt(1),
			Gas:       21000,
			GasPrice:  big.NewInt(1),
			GasTipCap: big.NewInt(1000000000),
			GasFeeCap: big.NewInt(20000000000),
			ChainID:   chainID,
			TxType:    TxTypeDynamic,
		},
	}
}

// WithFrom sets the sender account
func (b *Builder) WithFrom(from config.Account) *Builder {
	b.opts.From = from
	return b
}

// WithTo sets the recipient account
func (b *Builder) WithTo(to config.Account) *Builder {
	b.opts.To = to
	return b
}

// WithNonce sets the transaction nonce
func (b *Builder) WithNonce(nonce uint64) *Builder {
	b.opts.Nonce = nonce
	return b
}

// WithValue sets the transaction value
func (b *Builder) WithValue(value *big.Int) *Builder {
	b.opts.Value = value
	return b
}

// WithGasPrice sets the gas price (for legacy transactions)
func (b *Builder) WithGasPrice(gasPrice *big.Int) *Builder {
	b.opts.GasPrice = gasPrice
	return b
}

// WithGasTipCap sets the priority fee (for EIP-1559)
func (b *Builder) WithGasTipCap(gasTipCap *big.Int) *Builder {
	b.opts.GasTipCap = gasTipCap
	return b
}

// WithGasFeeCap sets the max fee (for EIP-1559)
func (b *Builder) WithGasFeeCap(gasFeeCap *big.Int) *Builder {
	b.opts.GasFeeCap = gasFeeCap
	return b
}

// WithGas sets the gas limit
func (b *Builder) WithGas(gas uint64) *Builder {
	b.opts.Gas = gas
	return b
}

// WithData sets the transaction data
func (b *Builder) WithData(data []byte) *Builder {
	b.opts.Data = data
	return b
}

// WithType sets the transaction type
func (b *Builder) WithType(txType TxType) *Builder {
	b.opts.TxType = txType
	return b
}

// Build creates and signs the transaction
func (b *Builder) Build() (*types.Transaction, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(b.opts.From.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Create transaction based on type
	var tx *types.Transaction
	toAddr := common.HexToAddress(b.opts.To.Address)

	switch b.opts.TxType {
	case TxTypeLegacy:
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    b.opts.Nonce,
			GasPrice: b.opts.GasPrice,
			Gas:      b.opts.Gas,
			To:       &toAddr,
			Value:    b.opts.Value,
			Data:     b.opts.Data,
		})
		// Sign with EIP155Signer
		signer := types.NewEIP155Signer(b.opts.ChainID)
		return types.SignTx(tx, signer, privateKey)

	case TxTypeDynamic, TxTypeEIP1559:
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   b.opts.ChainID,
			Nonce:     b.opts.Nonce,
			GasTipCap: b.opts.GasTipCap,
			GasFeeCap: b.opts.GasFeeCap,
			Gas:       b.opts.Gas,
			To:        &toAddr,
			Value:     b.opts.Value,
			Data:      b.opts.Data,
		})
		// Sign with LondonSigner
		signer := types.NewLondonSigner(b.opts.ChainID)
		return types.SignTx(tx, signer, privateKey)

	case TxTypeBlob:
		// For blob transactions, use the dedicated BlobTxBuilder in blob.go
		// This is just for completeness, but blob txs should use BlobTxBuilder
		if len(b.opts.BlobVersionedHashes) == 0 {
			return nil, fmt.Errorf("blob transaction requires at least one blob hash")
		}

		tx = types.NewTx(&types.BlobTx{
			ChainID:    uint256.MustFromBig(b.opts.ChainID),
			Nonce:      b.opts.Nonce,
			GasTipCap:  uint256.MustFromBig(b.opts.GasTipCap),
			GasFeeCap:  uint256.MustFromBig(b.opts.GasFeeCap),
			Gas:        b.opts.Gas,
			To:         toAddr,
			Value:      uint256.MustFromBig(b.opts.Value),
			Data:       b.opts.Data,
			BlobFeeCap: uint256.MustFromBig(b.opts.MaxFeePerBlobGas),
			BlobHashes: b.opts.BlobVersionedHashes,
		})
		// Sign with CancunSigner
		signer := types.NewCancunSigner(b.opts.ChainID)
		return types.SignTx(tx, signer, privateKey)

	default:
		return nil, fmt.Errorf("unsupported transaction type: %s", b.opts.TxType)
	}
}

// BuildUnsigned creates an unsigned transaction
func (b *Builder) BuildUnsigned() (*types.Transaction, error) {
	toAddr := common.HexToAddress(b.opts.To.Address)

	switch b.opts.TxType {
	case TxTypeLegacy:
		return types.NewTx(&types.LegacyTx{
			Nonce:    b.opts.Nonce,
			GasPrice: b.opts.GasPrice,
			Gas:      b.opts.Gas,
			To:       &toAddr,
			Value:    b.opts.Value,
			Data:     b.opts.Data,
		}), nil

	case TxTypeDynamic, TxTypeEIP1559:
		return types.NewTx(&types.DynamicFeeTx{
			ChainID:   b.opts.ChainID,
			Nonce:     b.opts.Nonce,
			GasTipCap: b.opts.GasTipCap,
			GasFeeCap: b.opts.GasFeeCap,
			Gas:       b.opts.Gas,
			To:        &toAddr,
			Value:     b.opts.Value,
			Data:      b.opts.Data,
		}), nil

	case TxTypeBlob:
		if len(b.opts.BlobVersionedHashes) == 0 {
			return nil, fmt.Errorf("blob transaction requires at least one blob hash")
		}

		return types.NewTx(&types.BlobTx{
			ChainID:    uint256.MustFromBig(b.opts.ChainID),
			Nonce:      b.opts.Nonce,
			GasTipCap:  uint256.MustFromBig(b.opts.GasTipCap),
			GasFeeCap:  uint256.MustFromBig(b.opts.GasFeeCap),
			Gas:        b.opts.Gas,
			To:         toAddr,
			Value:      uint256.MustFromBig(b.opts.Value),
			Data:       b.opts.Data,
			BlobFeeCap: uint256.MustFromBig(b.opts.MaxFeePerBlobGas),
			BlobHashes: b.opts.BlobVersionedHashes,
		}), nil

	default:
		return nil, fmt.Errorf("unsupported transaction type: %s", b.opts.TxType)
	}
}

// SignTransaction signs a transaction with the given private key
func SignTransaction(tx *types.Transaction, privateKey *ecdsa.PrivateKey, chainID *big.Int) (*types.Transaction, error) {
	var signer types.Signer

	switch tx.Type() {
	case types.LegacyTxType:
		signer = types.NewEIP155Signer(chainID)
	case types.DynamicFeeTxType:
		signer = types.NewLondonSigner(chainID)
	case types.BlobTxType:
		signer = types.NewCancunSigner(chainID)
	default:
		signer = types.LatestSignerForChainID(chainID)
	}

	return types.SignTx(tx, signer, privateKey)
}
