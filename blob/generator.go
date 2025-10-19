package blob

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Generator defines the interface for blob data generators
type Generator interface {
	// Generate creates blob data of the specified size
	Generate(size int) ([]byte, error)

	// Type returns the generator type
	Type() GeneratorType
}

// RandomGenerator generates random blob data
type RandomGenerator struct{}

func (g *RandomGenerator) Type() GeneratorType {
	return GeneratorRandom
}

func (g *RandomGenerator) Generate(size int) ([]byte, error) {
	if size <= 0 || size > BlobDataSize {
		return nil, fmt.Errorf("invalid size: %d (must be 1-%d)", size, BlobDataSize)
	}

	data := make([]byte, size)

	// Generate valid field elements for BLS12-381
	// Each field element is 32 bytes, and must be < field modulus
	// To ensure validity, we clear the top byte of each 32-byte chunk
	numFieldElements := (size + BytesPerFieldElement - 1) / BytesPerFieldElement

	for i := 0; i < numFieldElements; i++ {
		start := i * BytesPerFieldElement
		end := start + BytesPerFieldElement
		if end > size {
			end = size
		}

		// Generate random bytes for this field element
		chunk := data[start:end]
		if _, err := rand.Read(chunk); err != nil {
			return nil, fmt.Errorf("failed to generate random data: %w", err)
		}

		// Clear the top byte to ensure the value is less than the BLS12-381 field modulus
		// This prevents "scalar is not canonical" errors
		if len(chunk) == BytesPerFieldElement {
			chunk[0] = 0
		}
	}

	return data, nil
}

// PatternGenerator generates patterned blob data for testing
type PatternGenerator struct {
	Pattern []byte
}

func (g *PatternGenerator) Type() GeneratorType {
	return GeneratorPattern
}

func (g *PatternGenerator) Generate(size int) ([]byte, error) {
	if size <= 0 || size > BlobDataSize {
		return nil, fmt.Errorf("invalid size: %d (must be 1-%d)", size, BlobDataSize)
	}

	if len(g.Pattern) == 0 {
		// Default pattern: repeating 0x00 to 0xFF
		g.Pattern = make([]byte, 256)
		for i := 0; i < 256; i++ {
			g.Pattern[i] = byte(i)
		}
	}

	data := make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = g.Pattern[i%len(g.Pattern)]
	}

	// Ensure each 32-byte field element is valid by clearing the top byte
	numFieldElements := (size + BytesPerFieldElement - 1) / BytesPerFieldElement
	for i := 0; i < numFieldElements; i++ {
		offset := i * BytesPerFieldElement
		if offset < size {
			data[offset] = 0
		}
	}

	return data, nil
}

// ZeroGenerator generates zero-filled blob data
type ZeroGenerator struct{}

func (g *ZeroGenerator) Type() GeneratorType {
	return GeneratorZero
}

func (g *ZeroGenerator) Generate(size int) ([]byte, error) {
	if size <= 0 || size > BlobDataSize {
		return nil, fmt.Errorf("invalid size: %d (must be 1-%d)", size, BlobDataSize)
	}

	return make([]byte, size), nil
}

// L2DataGenerator simulates L2 rollup data format
type L2DataGenerator struct {
	BatchNumber uint64
	TxCount     int
}

func (g *L2DataGenerator) Type() GeneratorType {
	return GeneratorL2Data
}

func (g *L2DataGenerator) Generate(size int) ([]byte, error) {
	if size <= 0 || size > BlobDataSize {
		return nil, fmt.Errorf("invalid size: %d (must be 1-%d)", size, BlobDataSize)
	}

	data := make([]byte, size)

	// Skip first byte (will be cleared for field element validity)
	offset := 1

	// Header: version (1 byte) + batch number (8 bytes) + tx count (4 bytes)
	if offset < size {
		data[offset] = 0x01 // version
		offset++
	}

	if offset+8 <= size {
		binary.BigEndian.PutUint64(data[offset:], g.BatchNumber)
		offset += 8
	}

	if offset+4 <= size {
		binary.BigEndian.PutUint32(data[offset:], uint32(g.TxCount))
		offset += 4
	}

	// Fill remaining with simulated transaction data
	if offset < size {
		if _, err := rand.Read(data[offset:]); err != nil {
			return nil, fmt.Errorf("failed to generate L2 data: %w", err)
		}
	}

	// Ensure each 32-byte field element is valid by clearing the top byte
	numFieldElements := (size + BytesPerFieldElement - 1) / BytesPerFieldElement
	for i := 0; i < numFieldElements; i++ {
		fieldOffset := i * BytesPerFieldElement
		if fieldOffset < size {
			data[fieldOffset] = 0
		}
	}

	return data, nil
}

// NewGenerator creates a new generator based on the specified type
func NewGenerator(genType GeneratorType) (Generator, error) {
	switch genType {
	case GeneratorRandom:
		return &RandomGenerator{}, nil
	case GeneratorPattern:
		return &PatternGenerator{}, nil
	case GeneratorZero:
		return &ZeroGenerator{}, nil
	case GeneratorL2Data:
		return &L2DataGenerator{
			BatchNumber: 1,
			TxCount:     100,
		}, nil
	default:
		return nil, fmt.Errorf("unknown generator type: %s", genType)
	}
}

// GenerateBlob generates a single blob with the specified generator and size
func GenerateBlob(genType GeneratorType, size int) (*BlobData, error) {
	generator, err := NewGenerator(genType)
	if err != nil {
		return nil, err
	}

	rawData, err := generator.Generate(size)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data: %w", err)
	}

	// Process the raw data into a complete BlobData structure
	blobData, err := ProcessBlobData(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to process blob data: %w", err)
	}

	return blobData, nil
}

// GenerateBlobs generates multiple blobs
func GenerateBlobs(genType GeneratorType, count int, sizePerBlob int) ([]*BlobData, error) {
	if count <= 0 || count > MaxBlobsPerTransaction {
		return nil, fmt.Errorf("invalid blob count: %d (must be 1-%d)", count, MaxBlobsPerTransaction)
	}

	blobs := make([]*BlobData, count)
	for i := 0; i < count; i++ {
		blob, err := GenerateBlob(genType, sizePerBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to generate blob %d: %w", i, err)
		}
		blobs[i] = blob
	}

	return blobs, nil
}

// GenerateRandomBlobs is a convenience function to generate random blobs
func GenerateRandomBlobs(count int) ([]*BlobData, error) {
	return GenerateBlobs(GeneratorRandom, count, BlobDataSize)
}

// CalculateBlobGasPrice calculates the blob gas price based on excess blob gas
// Formula: fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas, BLOB_GASPRICE_UPDATE_FRACTION)
func CalculateBlobGasPrice(excessBlobGas uint64) *big.Int {
	const (
		minBlobGasPrice            = 1
		blobGasPriceUpdateFraction = 3338477
	)

	if excessBlobGas == 0 {
		return big.NewInt(minBlobGasPrice)
	}

	// Simplified fake exponential calculation
	// In production, use the exact EIP-4844 formula
	price := big.NewInt(minBlobGasPrice)
	excess := big.NewInt(int64(excessBlobGas))
	factor := big.NewInt(blobGasPriceUpdateFraction)

	// price = MIN_BLOB_GASPRICE * e^(excess_blob_gas / BLOB_GASPRICE_UPDATE_FRACTION)
	// Approximation: price ≈ MIN_BLOB_GASPRICE * (1 + excess_blob_gas / factor)
	result := new(big.Int).Mul(price, new(big.Int).Add(factor, excess))
	result.Div(result, factor)

	return result
}
