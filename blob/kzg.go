package blob

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

var (
	// kzgInitialized tracks whether KZG has been initialized
	kzgInitialized bool
	kzgMutex       sync.Mutex
)

// Note: We use go-ethereum's built-in KZG library which handles initialization automatically

// InitKZG initializes the KZG library with trusted setup
// This must be called before any KZG operations
func InitKZG() error {
	kzgMutex.Lock()
	defer kzgMutex.Unlock()

	if kzgInitialized {
		return nil
	}

	// The go-ethereum library automatically initializes KZG with embedded trusted setup
	// We just need to verify it's available by attempting a simple operation
	// This ensures the library is properly initialized
	var testBlob kzg4844.Blob
	_, err := kzg4844.BlobToCommitment(&testBlob)
	if err != nil {
		return fmt.Errorf("KZG library not properly initialized: %w", err)
	}

	kzgInitialized = true
	return nil
}

// ComputeCommitment computes the KZG commitment for a blob
func ComputeCommitment(blob *kzg4844.Blob) (kzg4844.Commitment, error) {
	if !kzgInitialized {
		if err := InitKZG(); err != nil {
			return kzg4844.Commitment{}, fmt.Errorf("KZG not initialized: %w", err)
		}
	}

	// Use go-ethereum's KZG library directly
	commitment, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return kzg4844.Commitment{}, fmt.Errorf("failed to compute commitment: %w", err)
	}
	return commitment, nil
}

// ComputeProof computes the KZG proof for a blob and commitment
func ComputeProof(blob *kzg4844.Blob, commitment kzg4844.Commitment) (kzg4844.Proof, error) {
	if !kzgInitialized {
		if err := InitKZG(); err != nil {
			return kzg4844.Proof{}, fmt.Errorf("KZG not initialized: %w", err)
		}
	}

	// Use go-ethereum's KZG library directly
	proof, err := kzg4844.ComputeBlobProof(blob, commitment)
	if err != nil {
		return kzg4844.Proof{}, fmt.Errorf("failed to compute proof: %w", err)
	}
	return proof, nil
}

// ComputeVersionedHash computes the versioned hash from a commitment
// Format: sha256(commitment)[0] | 0x01
func ComputeVersionedHash(commitment kzg4844.Commitment) common.Hash {
	hash := sha256.Sum256(commitment[:])

	// Set the first byte to 0x01 (version byte for EIP-4844)
	var versionedHash common.Hash
	copy(versionedHash[:], hash[:])
	versionedHash[0] = 0x01

	return versionedHash
}

// VerifyProof verifies a KZG proof for a blob and commitment
func VerifyProof(blob *kzg4844.Blob, commitment kzg4844.Commitment, proof kzg4844.Proof) error {
	if !kzgInitialized {
		if err := InitKZG(); err != nil {
			return fmt.Errorf("KZG not initialized: %w", err)
		}
	}

	// Use go-ethereum's KZG library directly
	if err := kzg4844.VerifyBlobProof(blob, commitment, proof); err != nil {
		return fmt.Errorf("KZG proof verification failed: %w", err)
	}
	return nil
}

// ProcessBlobData processes raw data into a complete BlobData structure
// This includes computing the commitment, proof, and versioned hash
func ProcessBlobData(rawData []byte) (*BlobData, error) {
	// Convert raw data to blob format
	var blob kzg4844.Blob
	if len(rawData) > len(blob) {
		return nil, fmt.Errorf("data too large: %d bytes (max %d)", len(rawData), len(blob))
	}
	copy(blob[:], rawData)

	// Compute commitment
	commitment, err := ComputeCommitment(&blob)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	// Compute proof
	proof, err := ComputeProof(&blob, commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to compute proof: %w", err)
	}

	// Compute versioned hash
	versionedHash := ComputeVersionedHash(commitment)

	return &BlobData{
		Raw:           rawData,
		Blob:          blob,
		Commitment:    commitment,
		Proof:         proof,
		VersionedHash: versionedHash,
	}, nil
}

// BatchProcessBlobs processes multiple raw data chunks into BlobData structures
func BatchProcessBlobs(rawDataList [][]byte) ([]*BlobData, error) {
	if len(rawDataList) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	if len(rawDataList) > MaxBlobsPerTransaction {
		return nil, fmt.Errorf("too many blobs: %d (max %d)", len(rawDataList), MaxBlobsPerTransaction)
	}

	blobs := make([]*BlobData, len(rawDataList))
	for i, rawData := range rawDataList {
		blobData, err := ProcessBlobData(rawData)
		if err != nil {
			return nil, fmt.Errorf("failed to process blob %d: %w", i, err)
		}
		blobs[i] = blobData
	}

	return blobs, nil
}
