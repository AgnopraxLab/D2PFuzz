package strategies

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/AgnopraxLab/D2PFuzz/mutation"
)

// ETH protocol message codes (from go-ethereum/eth/protocols/eth)
const (
	// ETH protocol message codes
	StatusMsg          = 0x00
	NewBlockHashesMsg  = 0x01
	TransactionsMsg    = 0x02
	GetBlockHeadersMsg = 0x03
	BlockHeadersMsg    = 0x04
	GetBlockBodiesMsg  = 0x05
	BlockBodiesMsg     = 0x06
	NewBlockMsg        = 0x07
	GetNodeDataMsg     = 0x0d
	NodeDataMsg        = 0x0e
	GetReceiptsMsg     = 0x0f
	ReceiptsMsg        = 0x10
)

// ETHMutator implements mutation strategies for ETH protocol messages
type ETHMutator struct {
	rng *mathrand.Rand
}

// NewETHMutator creates a new ETH protocol mutator
func NewETHMutator(seed int64) *ETHMutator {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &ETHMutator{
		rng: mathrand.New(mathrand.NewSource(seed)),
	}
}

// Name returns the name of this mutation strategy
func (e *ETHMutator) Name() string {
	return "ETH Protocol Mutator"
}

// CanMutate checks if this strategy can mutate the given data
func (e *ETHMutator) CanMutate(data []byte) bool {
	// Try to decode as RLP to see if it's a valid ETH message
	if len(data) < 1 {
		return false
	}
	
	// Basic RLP structure check
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	_, _, err := stream.Kind()
	return err == nil
}

// Priority returns the priority of this strategy
func (e *ETHMutator) Priority() int {
	return 100 // High priority for ETH protocol messages
}

// Mutate applies ETH protocol specific mutations
func (e *ETHMutator) Mutate(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	// Try to identify message type and apply specific mutations
	mutatedData, err := e.mutateETHMessage(data, config)
	if err != nil {
		// Fallback to generic mutations if specific mutation fails
		return e.applyGenericMutations(data, config)
	}

	return mutatedData, nil
}

// mutateETHMessage applies specific mutations based on message type
func (e *ETHMutator) mutateETHMessage(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	// Try to decode the message to identify its type
	var decoded interface{}
	err := rlp.DecodeBytes(data, &decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %v", err)
	}

	// Apply mutations based on the decoded structure
	switch v := decoded.(type) {
	case []interface{}:
		// List structure - could be various message types
		return e.mutateListMessage(v, config)
	case []byte:
		// Byte array - apply byte-level mutations
		return e.mutateByteArray(v, config)
	case string:
		// String data - apply string mutations
		return e.mutateString(v, config)
	case *big.Int:
		// Big integer - apply numeric mutations
		return e.mutateBigInt(v, config)
	default:
		// Unknown type - apply generic mutations
		return e.applyGenericMutations(data, config)
	}
}

// mutateListMessage mutates list-based messages (most ETH messages)
func (e *ETHMutator) mutateListMessage(list []interface{}, config *mutation.MutationConfig) ([]byte, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("empty list")
	}

	// Create a copy of the list for mutation
	mutatedList := make([]interface{}, len(list))
	copy(mutatedList, list)

	// Apply field-level mutations
	for i := 0; i < len(mutatedList); i++ {
		if e.rng.Float64() < config.ETH.FieldMutationRate {
			mutatedList[i] = e.mutateField(mutatedList[i], config)
		}
	}

	// Occasionally add/remove fields
	if e.rng.Float64() < 0.1 { // 10% chance
		if e.rng.Intn(2) == 0 && len(mutatedList) > 1 {
			// Remove a random field
			index := e.rng.Intn(len(mutatedList))
			mutatedList = append(mutatedList[:index], mutatedList[index+1:]...)
		} else {
			// Add a random field
			randomField := e.generateRandomField()
			mutatedList = append(mutatedList, randomField)
		}
	}

	// Encode back to RLP
	return rlp.EncodeToBytes(mutatedList)
}

// mutateField applies mutations to individual fields
func (e *ETHMutator) mutateField(field interface{}, config *mutation.MutationConfig) interface{} {
	switch v := field.(type) {
	case []byte:
		return e.mutateBytes(v, config)
	case string:
		return e.mutateStringField(v, config)
	case *big.Int:
		return e.mutateBigIntField(v, config)
	case uint64:
		return e.mutateUint64(v, config)
	case []interface{}:
		// Nested list - recursively mutate
		for i := 0; i < len(v); i++ {
			if e.rng.Float64() < config.ETH.FieldMutationRate {
				v[i] = e.mutateField(v[i], config)
			}
		}
		return v
	default:
		// Unknown type - return as is or generate random data
		if e.rng.Float64() < 0.1 {
			return e.generateRandomField()
		}
		return field
	}
}

// mutateBytes applies byte-level mutations
func (e *ETHMutator) mutateBytes(data []byte, config *mutation.MutationConfig) []byte {
	if len(data) == 0 {
		return data
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Bit flipping
	if e.rng.Float64() < 0.3 {
		index := e.rng.Intn(len(mutated))
		bit := e.rng.Intn(8)
		mutated[index] ^= 1 << bit
	}

	// Byte replacement
	if e.rng.Float64() < 0.2 {
		index := e.rng.Intn(len(mutated))
		mutated[index] = byte(e.rng.Intn(256))
	}

	// Length mutations
	if e.rng.Float64() < 0.1 {
		if e.rng.Intn(2) == 0 && len(mutated) > 1 {
			// Truncate
			newLen := e.rng.Intn(len(mutated))
			mutated = mutated[:newLen]
		} else {
			// Extend
			extraBytes := make([]byte, e.rng.Intn(32)+1)
			rand.Read(extraBytes)
			mutated = append(mutated, extraBytes...)
		}
	}

	return mutated
}

// mutateStringField applies string-specific mutations
func (e *ETHMutator) mutateStringField(s string, config *mutation.MutationConfig) string {
	if len(s) == 0 {
		return s
	}

	// Convert to bytes, mutate, and convert back
	bytes := []byte(s)
	mutatedBytes := e.mutateBytes(bytes, config)
	return string(mutatedBytes)
}

// mutateBigIntField applies big integer mutations
func (e *ETHMutator) mutateBigIntField(bi *big.Int, config *mutation.MutationConfig) *big.Int {
	if bi == nil {
		return big.NewInt(int64(e.rng.Uint64()))
	}

	result := new(big.Int).Set(bi)

	// Various numeric mutations
	switch e.rng.Intn(6) {
	case 0:
		// Add random value
		randomValue := big.NewInt(int64(e.rng.Uint32()))
		result.Add(result, randomValue)
	case 1:
		// Subtract random value
		randomValue := big.NewInt(int64(e.rng.Uint32()))
		result.Sub(result, randomValue)
	case 2:
		// Multiply by small factor
		factor := big.NewInt(int64(e.rng.Intn(10) + 1))
		result.Mul(result, factor)
	case 3:
		// Set to maximum value
		result.SetUint64(config.ETH.MaxGasLimit)
	case 4:
		// Set to zero
		result.SetInt64(0)
	case 5:
		// Bit manipulation
		if result.BitLen() > 0 {
			bitIndex := e.rng.Intn(result.BitLen())
			if result.Bit(bitIndex) == 0 {
				result.SetBit(result, bitIndex, 1)
			} else {
				result.SetBit(result, bitIndex, 0)
			}
		}
	}

	return result
}

// mutateUint64 applies uint64 mutations
func (e *ETHMutator) mutateUint64(val uint64, config *mutation.MutationConfig) uint64 {
	switch e.rng.Intn(5) {
	case 0:
		return val + uint64(e.rng.Intn(1000))
	case 1:
		if val > 1000 {
			return val - uint64(e.rng.Intn(1000))
		}
		return val
	case 2:
		return config.ETH.MaxBlockNumber
	case 3:
		return 0
	case 4:
		return ^uint64(0) // Max uint64
	default:
		return val
	}
}

// generateRandomField generates a random field for injection
func (e *ETHMutator) generateRandomField() interface{} {
	switch e.rng.Intn(4) {
	case 0:
		// Random bytes
		length := e.rng.Intn(64) + 1
		bytes := make([]byte, length)
		rand.Read(bytes)
		return bytes
	case 1:
		// Random string
		length := e.rng.Intn(32) + 1
		bytes := make([]byte, length)
		for i := range bytes {
			bytes[i] = byte(e.rng.Intn(95) + 32) // Printable ASCII
		}
		return string(bytes)
	case 2:
		// Random big int
		return big.NewInt(int64(e.rng.Uint64()))
	case 3:
		// Random uint64
		return e.rng.Uint64()
	default:
		return []byte{}
	}
}

// mutateByteArray applies mutations to byte arrays
func (e *ETHMutator) mutateByteArray(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	mutated := e.mutateBytes(data, config)
	return rlp.EncodeToBytes(mutated)
}

// mutateString applies mutations to strings
func (e *ETHMutator) mutateString(s string, config *mutation.MutationConfig) ([]byte, error) {
	mutated := e.mutateStringField(s, config)
	return rlp.EncodeToBytes(mutated)
}

// mutateBigInt applies mutations to big integers
func (e *ETHMutator) mutateBigInt(bi *big.Int, config *mutation.MutationConfig) ([]byte, error) {
	mutated := e.mutateBigIntField(bi, config)
	return rlp.EncodeToBytes(mutated)
}

// applyGenericMutations applies generic byte-level mutations as fallback
func (e *ETHMutator) applyGenericMutations(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Apply random mutations
	numMutations := e.rng.Intn(5) + 1
	for i := 0; i < numMutations; i++ {
		if len(mutated) == 0 {
			break
		}

		switch e.rng.Intn(4) {
		case 0:
			// Bit flip
			index := e.rng.Intn(len(mutated))
			bit := e.rng.Intn(8)
			mutated[index] ^= 1 << bit
		case 1:
			// Byte replacement
			index := e.rng.Intn(len(mutated))
			mutated[index] = byte(e.rng.Intn(256))
		case 2:
			// Insert random byte
			index := e.rng.Intn(len(mutated) + 1)
			randomByte := byte(e.rng.Intn(256))
			mutated = append(mutated[:index], append([]byte{randomByte}, mutated[index:]...)...)
		case 3:
			// Delete byte
			if len(mutated) > 1 {
				index := e.rng.Intn(len(mutated))
				mutated = append(mutated[:index], mutated[index+1:]...)
			}
		}
	}

	return mutated, nil
}

// MutateStatusMessage specifically mutates ETH Status messages
func (e *ETHMutator) MutateStatusMessage(status interface{}, config *mutation.MutationConfig) ([]byte, error) {
	// This would be called for known Status message structures
	// Implementation depends on the specific status message format
	return rlp.EncodeToBytes(status)
}

// MutateTransactionMessage specifically mutates transaction messages
func (e *ETHMutator) MutateTransactionMessage(txs []*types.Transaction, config *mutation.MutationConfig) ([]byte, error) {
	if len(txs) == 0 {
		return rlp.EncodeToBytes(txs)
	}

	// Mutate individual transactions
	mutatedTxs := make([]*types.Transaction, len(txs))
	copy(mutatedTxs, txs)

	for i, tx := range mutatedTxs {
		if e.rng.Float64() < config.ETH.FieldMutationRate {
			// Create a mutated transaction
			// This is a simplified example - real implementation would be more sophisticated
			mutatedTxs[i] = e.mutateTransaction(tx, config)
		}
	}

	return rlp.EncodeToBytes(mutatedTxs)
}

// mutateTransaction mutates a single transaction
func (e *ETHMutator) mutateTransaction(tx *types.Transaction, config *mutation.MutationConfig) *types.Transaction {
	// This is a simplified mutation - real implementation would handle all transaction fields
	// For now, return the original transaction
	return tx
}