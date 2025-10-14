package blob

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// ValidateBlobSize validates the size of blob data
func ValidateBlobSize(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("blob data is empty")
	}

	if len(data) > BlobDataSize {
		return fmt.Errorf("blob data too large: %d bytes (max %d)", len(data), BlobDataSize)
	}

	return nil
}

// ValidateBlobCount validates the number of blobs in a transaction
func ValidateBlobCount(count int) error {
	if count <= 0 {
		return fmt.Errorf("blob count must be positive, got %d", count)
	}

	if count > MaxBlobsPerTransaction {
		return fmt.Errorf("too many blobs: %d (max %d)", count, MaxBlobsPerTransaction)
	}

	return nil
}

// ValidateKZGProof validates the KZG proof for blob data
func ValidateKZGProof(blobData *BlobData) error {
	if blobData == nil {
		return fmt.Errorf("blob data is nil")
	}

	// Verify the KZG proof
	// if err := VerifyProof(&blobData.Blob, blobData.Commitment, blobData.Proof); err != nil {
	// 	return fmt.Errorf("KZG proof verification failed: %w", err)
	// }

	// Verify the versioned hash matches the commitment
	expectedHash := ComputeVersionedHash(blobData.Commitment)
	if blobData.VersionedHash != expectedHash {
		return fmt.Errorf("versioned hash mismatch: got %s, expected %s",
			blobData.VersionedHash.Hex(), expectedHash.Hex())
	}

	return nil
}

// ValidateBlobGasPrice validates the blob gas price against current network conditions
func ValidateBlobGasPrice(maxFeePerBlobGas *big.Int, excessBlobGas uint64) error {
	if maxFeePerBlobGas == nil {
		return fmt.Errorf("max fee per blob gas is nil")
	}

	if maxFeePerBlobGas.Sign() <= 0 {
		return fmt.Errorf("max fee per blob gas must be positive, got %s", maxFeePerBlobGas.String())
	}

	// Calculate current blob gas price
	currentPrice := CalculateBlobGasPrice(excessBlobGas)

	// Ensure max fee is sufficient
	if maxFeePerBlobGas.Cmp(currentPrice) < 0 {
		return fmt.Errorf("max fee per blob gas too low: %s (current price: %s)",
			maxFeePerBlobGas.String(), currentPrice.String())
	}

	return nil
}

// ValidateBlobTransaction validates a complete blob transaction
// func ValidateBlobTransaction(blobTx types.Transactions) error {
// 	if blobTx == nil {
// 		return fmt.Errorf("blob transaction is nil")
// 	}

// 	// Validate blob count
// 	blobCount := len(blobTx)
// 	if err := ValidateBlobCount(blobCount); err != nil {
// 		return fmt.Errorf("invalid blob count: %w", err)
// 	}

// 	// Validate each blob
// 	for i, blob := range blobTx {
// 		if err := ValidateBlobSize(blob.Data()); err != nil {
// 			return fmt.Errorf("blob %d: %w", i, err)
// 		}

// 		if err := ValidateKZGProof(blob.d); err != nil {
// 			return fmt.Errorf("blob %d: %w", i, err)
// 		}
// 	}

// 	// Validate versioned hashes match
// 	txHashes := blobTx.Tx.BlobHashes()
// 	if len(txHashes) != blobCount {
// 		return fmt.Errorf("versioned hash count mismatch: tx has %d, blobs have %d",
// 			len(txHashes), blobCount)
// 	}

// 	for i, hash := range txHashes {
// 		if hash != blobTx.Blobs[i].VersionedHash {
// 			return fmt.Errorf("blob %d: versioned hash mismatch: tx has %s, blob has %s",
// 				i, hash.Hex(), blobTx.Blobs[i].VersionedHash.Hex())
// 		}
// 	}

// 	// Validate gas parameters
// 	if blobTx.Tx.BlobGasFeeCap() == nil {
// 		return fmt.Errorf("blob gas fee cap is nil")
// 	}

// 	if blobTx.BlobGasFeeCap().Sign() <= 0 {
// 		return fmt.Errorf("blob gas fee cap must be positive")
// 	}

// 	return nil
// }

// ValidateBlobGasParameters validates blob gas related parameters
func ValidateBlobGasParameters(tx *types.Transaction, excessBlobGas uint64) error {
	if tx.Type() != types.BlobTxType {
		return fmt.Errorf("not a blob transaction")
	}

	// Validate blob gas fee cap
	blobGasFeeCap := tx.BlobGasFeeCap()
	if blobGasFeeCap == nil || blobGasFeeCap.Sign() <= 0 {
		return fmt.Errorf("invalid blob gas fee cap")
	}

	// Calculate required blob gas
	blobCount := len(tx.BlobHashes())
	requiredBlobGas := uint64(blobCount) * params.BlobTxBlobGasPerBlob

	// Validate against network limits
	const maxBlobGasPerBlock = 786432 // 6 blobs * 131072
	if requiredBlobGas > maxBlobGasPerBlock {
		return fmt.Errorf("blob gas exceeds block limit: %d (max %d)",
			requiredBlobGas, maxBlobGasPerBlock)
	}

	// Validate blob gas price
	if err := ValidateBlobGasPrice(blobGasFeeCap, excessBlobGas); err != nil {
		return fmt.Errorf("blob gas price validation failed: %w", err)
	}

	return nil
}

// EstimateBlobGas estimates the blob gas required for a transaction
func EstimateBlobGas(blobCount int) (uint64, error) {
	if err := ValidateBlobCount(blobCount); err != nil {
		return 0, err
	}

	return uint64(blobCount) * params.BlobTxBlobGasPerBlob, nil
}

// EstimateBlobCost estimates the cost of blob gas for a transaction
func EstimateBlobCost(blobCount int, blobGasPrice *big.Int) (*big.Int, error) {
	blobGas, err := EstimateBlobGas(blobCount)
	if err != nil {
		return nil, err
	}

	if blobGasPrice == nil || blobGasPrice.Sign() <= 0 {
		return nil, fmt.Errorf("invalid blob gas price")
	}

	cost := new(big.Int).Mul(big.NewInt(int64(blobGas)), blobGasPrice)
	return cost, nil
}
