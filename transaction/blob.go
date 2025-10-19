package transaction

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"

	"github.com/AgnopraxLab/D2PFuzz/blob"
	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
)

// BlobTxBuilder provides a fluent interface for building blob transactions
type BlobTxBuilder struct {
	// Base transaction options
	from          config.Account
	to            config.Account
	nonce         uint64
	value         *big.Int
	gasTipCap     *big.Int
	gasFeeCap     *big.Int
	gas           uint64
	data          []byte
	chainID       *big.Int
	count         int
	blobsCount    int
	discriminator byte

	// Blob specific options
	blobs            []*blob.BlobData
	maxFeePerBlobGas *big.Int
}

// NewBlobTxBuilder creates a new blob transaction builder
func NewBlobTxBuilder(chainID *big.Int) *BlobTxBuilder {
	return &BlobTxBuilder{
		value:            big.NewInt(0), // Blob txs typically have 0 value
		gas:              21000,
		gasTipCap:        big.NewInt(3000000000),  // 3 Gwei
		gasFeeCap:        big.NewInt(30000000000), // 30 Gwei
		maxFeePerBlobGas: big.NewInt(1000000000),  // 1 Gwei
		chainID:          chainID,
		count:            2,   // hard code for now
		blobsCount:       3,   // hard code for now
		discriminator:    0x1, // hard code for now
		blobs:            make([]*blob.BlobData, 0),
	}
}

// WithFrom sets the sender account
func (b *BlobTxBuilder) WithFrom(from config.Account) *BlobTxBuilder {
	b.from = from
	return b
}

// WithTo sets the recipient account
func (b *BlobTxBuilder) WithTo(to config.Account) *BlobTxBuilder {
	b.to = to
	return b
}

// WithNonce sets the transaction nonce
func (b *BlobTxBuilder) WithNonce(nonce uint64) *BlobTxBuilder {
	b.nonce = nonce
	return b
}

// WithValue sets the transaction value
func (b *BlobTxBuilder) WithValue(value *big.Int) *BlobTxBuilder {
	b.value = value
	return b
}

// WithGasTipCap sets the priority fee
func (b *BlobTxBuilder) WithGasTipCap(gasTipCap *big.Int) *BlobTxBuilder {
	b.gasTipCap = gasTipCap
	return b
}

// WithGasFeeCap sets the max fee
func (b *BlobTxBuilder) WithGasFeeCap(gasFeeCap *big.Int) *BlobTxBuilder {
	b.gasFeeCap = gasFeeCap
	return b
}

// WithGas sets the gas limit
func (b *BlobTxBuilder) WithGas(gas uint64) *BlobTxBuilder {
	b.gas = gas
	return b
}

// WithData sets the transaction calldata
func (b *BlobTxBuilder) WithData(data []byte) *BlobTxBuilder {
	b.data = data
	return b
}

// WithMaxFeePerBlobGas sets the max fee per blob gas
func (b *BlobTxBuilder) WithMaxFeePerBlobGas(fee *big.Int) *BlobTxBuilder {
	b.maxFeePerBlobGas = fee
	return b
}

// AddBlob adds a blob from raw data
func (b *BlobTxBuilder) AddBlob(rawData []byte) error {
	if len(b.blobs) >= blob.MaxBlobsPerTransaction {
		return fmt.Errorf("maximum blobs per transaction reached (%d)", blob.MaxBlobsPerTransaction)
	}

	blobData, err := blob.ProcessBlobData(rawData)
	if err != nil {
		return fmt.Errorf("failed to process blob data: %w", err)
	}

	b.blobs = append(b.blobs, blobData)
	return nil
}

// AddBlobData adds a pre-processed blob
func (b *BlobTxBuilder) AddBlobData(blobData *blob.BlobData) error {
	if len(b.blobs) >= blob.MaxBlobsPerTransaction {
		return fmt.Errorf("maximum blobs per transaction reached (%d)", blob.MaxBlobsPerTransaction)
	}

	// Validate the blob data
	if err := blob.ValidateKZGProof(blobData); err != nil {
		return fmt.Errorf("invalid blob data: %w", err)
	}

	b.blobs = append(b.blobs, blobData)
	return nil
}

// AddRandomBlob adds a blob with random data
func (b *BlobTxBuilder) AddRandomBlob() error {
	blobData, err := blob.GenerateBlob(blob.GeneratorRandom, blob.BlobDataSize)
	if err != nil {
		return fmt.Errorf("failed to generate random blob: %w", err)
	}

	return b.AddBlobData(blobData)
}

// AddRandomBlobs adds multiple blobs with random data
func (b *BlobTxBuilder) AddRandomBlobs(count int) error {
	for i := 0; i < count; i++ {
		if err := b.AddRandomBlob(); err != nil {
			return fmt.Errorf("failed to add random blob %d: %w", i, err)
		}
	}
	return nil
}

// Build creates and signs the blob transaction
func (b *BlobTxBuilder) Build() (txs types.Transactions, err error) {
	// Validate we have at least one blob
	if len(b.blobs) == 0 {
		return nil, fmt.Errorf("at least one blob is required")
	}

	// Parse private key
	privateKey, err := crypto.HexToECDSA(b.from.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Extract versioned hashes from blobs
	versionedHashes := make([]common.Hash, len(b.blobs))
	for i, blobData := range b.blobs {
		versionedHashes[i] = blobData.VersionedHash
	}
	txs = make([]*types.Transaction, 0)
	//==========================================
	for i := 0; i < b.count; i++ {
		// Make blob data, max of 2 blobs per tx.
		blobdata := make([]byte, b.blobsCount%3)
		for j := range blobdata {
			blobdata[j] = b.discriminator
			b.blobsCount -= 1
		}
		inner := &types.BlobTx{
			ChainID:    uint256.MustFromBig(b.chainID),
			Nonce:      b.nonce + uint64(i),
			GasTipCap:  uint256.MustFromBig(b.gasTipCap),
			GasFeeCap:  uint256.MustFromBig(b.gasFeeCap),
			Gas:        b.gas,
			BlobFeeCap: uint256.MustFromBig(b.maxFeePerBlobGas),
			BlobHashes: ethtest.MakeSidecar(blobdata...).BlobHashes(),
			Sidecar:    ethtest.MakeSidecar(blobdata...),
		}
		tx, err := types.SignTx(types.NewTx(inner), types.NewCancunSigner(b.chainID), privateKey)
		if err != nil {
			panic("blob tx signing failed")
		}
		txs = append(txs, tx)
	}

	//==========================================

	// Build the transaction
	// toAddr := common.HexToAddress(b.to.Address)
	// tx := types.NewTx(&types.BlobTx{
	// 	ChainID:    uint256.MustFromBig(b.chainID),
	// 	Nonce:      b.nonce,
	// 	GasTipCap:  uint256.MustFromBig(b.gasTipCap),
	// 	GasFeeCap:  uint256.MustFromBig(b.gasFeeCap),
	// 	Gas:        b.gas,
	// 	To:         toAddr,
	// 	Value:      uint256.MustFromBig(b.value),
	// 	Data:       b.data,
	// 	BlobFeeCap: uint256.MustFromBig(b.maxFeePerBlobGas),
	// 	BlobHashes: versionedHashes,
	// })

	// // Sign the transaction
	// signer := types.NewCancunSigner(b.chainID)
	// signedTx, err := types.SignTx(tx, signer, privateKey)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to sign transaction: %w", err)
	// }

	// Create sidecar for network transmission
	// Note: All blobs share a single sidecar structure
	// blobs = make([]kzg4844.Blob, len(b.blobs))
	// commitments := make([]kzg4844.Commitment, len(b.blobs))
	// proofs := make([]kzg4844.Proof, len(b.blobs))

	// for i, blobData := range b.blobs {
	// 	blobs[i] = blobData.Blob
	// 	commitments[i] = blobData.Commitment
	// 	proofs[i] = blobData.Proof
	// }

	// sidecar := &types.BlobTxSidecar{
	// 	Blobs:       blobs,
	// 	Commitments: commitments,
	// 	Proofs:      proofs,
	// }

	// // Attach sidecar to the signed transaction
	// // This is CRITICAL for blob transactions to be recognized as Type-3
	// signedTx = signedTx.WithBlobTxSidecar(sidecar)

	// blobTx := &blob.BlobTransaction{
	// 	Tx:       signedTx,
	// 	Blobs:    b.blobs,
	// 	Sidecars: []types.BlobTxSidecar{*sidecar},
	// }

	// // Validate the complete blob transaction
	// if err := blob.ValidateBlobTransaction(blobTx); err != nil {
	// 	return nil, fmt.Errorf("blob transaction validation failed: %w", err)
	// }

	return txs, nil
}

// BuildUnsigned creates an unsigned blob transaction
func (b *BlobTxBuilder) BuildUnsigned() (*types.Transaction, error) {
	if len(b.blobs) == 0 {
		return nil, fmt.Errorf("at least one blob is required")
	}

	// Extract versioned hashes
	versionedHashes := make([]common.Hash, len(b.blobs))
	for i, blobData := range b.blobs {
		versionedHashes[i] = blobData.VersionedHash
	}

	toAddr := common.HexToAddress(b.to.Address)
	return types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(b.chainID),
		Nonce:      b.nonce,
		GasTipCap:  uint256.MustFromBig(b.gasTipCap),
		GasFeeCap:  uint256.MustFromBig(b.gasFeeCap),
		Gas:        b.gas,
		To:         toAddr,
		Value:      uint256.MustFromBig(b.value),
		Data:       b.data,
		BlobFeeCap: uint256.MustFromBig(b.maxFeePerBlobGas),
		BlobHashes: versionedHashes,
	}), nil
}

// GetBlobCount returns the current number of blobs
func (b *BlobTxBuilder) GetBlobCount() int {
	return len(b.blobs)
}

// EstimateBlobGas estimates the total blob gas for current blobs
func (b *BlobTxBuilder) EstimateBlobGas() (uint64, error) {
	return blob.EstimateBlobGas(len(b.blobs))
}

// EstimateBlobCost estimates the total blob gas cost
func (b *BlobTxBuilder) EstimateBlobCost() (*big.Int, error) {
	return blob.EstimateBlobCost(len(b.blobs), b.maxFeePerBlobGas)
}

// Note: Removed uint256ToBigInt helper - using uint256.MustFromBig directly

// CreateSimpleBlobTransaction is a convenience function to create a simple blob transaction
func CreateSimpleBlobTransaction(
	from, to config.Account,
	nonce uint64,
	blobCount int,
	chainID *big.Int,
) (types.Transactions, error) {
	builder := NewBlobTxBuilder(chainID).
		WithFrom(from).
		WithTo(to).
		WithNonce(nonce)

	// Add random blobs
	if err := builder.AddRandomBlobs(blobCount); err != nil {
		return nil, fmt.Errorf("failed to add blobs: %w", err)
	}

	tx, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build blob transaction: %w", err)
	}
	return tx, nil
}
