package blob

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// BlobData represents a single blob with its cryptographic commitments
type BlobData struct {
	// Raw data (up to 128 KB)
	Raw []byte

	// Standard blob format (128 KB, properly formatted for KZG)
	Blob kzg4844.Blob

	// KZG commitment to the blob
	Commitment kzg4844.Commitment

	// KZG proof for the commitment
	Proof kzg4844.Proof

	// Versioned hash (sha256(commitment)[0] | 0x01)
	VersionedHash common.Hash
}

// BlobTransaction represents a complete blob transaction with all sidecars
type BlobTransaction struct {
	// The transaction itself (Type 3)
	Tx *types.Transaction

	// Associated blob data (1-6 blobs)
	Blobs []*BlobData

	// Sidecar format for network transmission
	Sidecars []types.BlobTxSidecar
}

// BlobDataSize is the standard size of a blob (128 KB)
const BlobDataSize = 131072

// MaxBlobsPerTransaction is the maximum number of blobs per transaction
const MaxBlobsPerTransaction = 6

// FieldElementsPerBlob is the number of field elements in a blob
const FieldElementsPerBlob = 4096

// BytesPerFieldElement is the number of bytes per field element
const BytesPerFieldElement = 32

// GeneratorType defines the type of blob data generator
type GeneratorType string

const (
	// GeneratorRandom generates random blob data
	GeneratorRandom GeneratorType = "random"

	// GeneratorPattern generates patterned blob data (for testing)
	GeneratorPattern GeneratorType = "pattern"

	// GeneratorZero generates zero-filled blob data
	GeneratorZero GeneratorType = "zero"

	// GeneratorL2Data simulates L2 rollup data format
	GeneratorL2Data GeneratorType = "l2-data"
)

// BlobGasParams holds blob gas pricing parameters
type BlobGasParams struct {
	// Current excess blob gas
	ExcessBlobGas uint64

	// Current blob gas price
	BlobGasPrice uint64

	// Max fee per blob gas willing to pay
	MaxFeePerBlobGas uint64
}
