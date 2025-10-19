package strategies

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/AgnopraxLab/D2PFuzz/mutation"
)

// RLP encoding constants
const (
	// RLP type indicators
	RLP_STRING_SHORT = 0x80 // [0x80, 0xb7] - short string
	RLP_STRING_LONG  = 0xb8 // [0xb8, 0xbf] - long string
	RLP_LIST_SHORT   = 0xc0 // [0xc0, 0xf7] - short list
	RLP_LIST_LONG    = 0xf8 // [0xf8, 0xff] - long list
)

// RLPMutator implements mutation strategies specifically for RLP encoding
type RLPMutator struct {
	rng *mathrand.Rand
}

// NewRLPMutator creates a new RLP mutator
func NewRLPMutator(seed int64) *RLPMutator {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &RLPMutator{
		rng: mathrand.New(mathrand.NewSource(seed)),
	}
}

// Name returns the name of this mutation strategy
func (r *RLPMutator) Name() string {
	return "RLP Encoding Mutator"
}

// CanMutate checks if this strategy can mutate the given data
func (r *RLPMutator) CanMutate(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// Check if data looks like RLP encoded
	return r.isValidRLP(data)
}

// Priority returns the priority of this strategy
func (r *RLPMutator) Priority() int {
	return 90 // High priority for RLP data
}

// Mutate applies RLP-specific mutations
func (r *RLPMutator) Mutate(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	// Choose mutation strategy
	strategies := []func([]byte, *mutation.MutationConfig) ([]byte, error){
		r.mutateLengthFields,
		r.mutateTypeIndicators,
		r.mutateStructure,
		r.corruptData,
		r.injectMalformedRLP,
	}

	// Apply random strategy
	strategyIndex := r.rng.Intn(len(strategies))
	return strategies[strategyIndex](data, config)
}

// isValidRLP performs basic RLP validation
func (r *RLPMutator) isValidRLP(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Try to decode as RLP
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	_, _, err := stream.Kind()
	return err == nil
}

// mutateLengthFields mutates RLP length encoding
func (r *RLPMutator) mutateLengthFields(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) < 2 {
		return data, nil
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Find and mutate length fields
	for i := 0; i < len(mutated); i++ {
		b := mutated[i]
		
		// Check if this byte is a length indicator
		if r.isLengthIndicator(b) {
			if r.rng.Float64() < config.RLP.LengthMutationRate {
				mutated[i] = r.mutateLengthByte(b)
				
				// If it's a long form, also mutate the length bytes
				if r.isLongForm(b) {
					lengthBytes := r.getLengthByteCount(b)
					for j := 1; j <= lengthBytes && i+j < len(mutated); j++ {
						if r.rng.Float64() < 0.5 {
							mutated[i+j] = byte(r.rng.Intn(256))
						}
					}
				}
			}
		}
	}

	return mutated, nil
}

// mutateTypeIndicators mutates RLP type indicators to cause type confusion
func (r *RLPMutator) mutateTypeIndicators(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Mutate type indicators
	for i := 0; i < len(mutated); i++ {
		b := mutated[i]
		
		if r.isTypeIndicator(b) && r.rng.Float64() < config.RLP.TypeMutationRate {
			// Convert between different RLP types
			mutated[i] = r.mutateTypeByte(b)
		}
	}

	return mutated, nil
}

// mutateStructure mutates the nested structure of RLP data
func (r *RLPMutator) mutateStructure(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if r.rng.Float64() > config.RLP.StructureMutationRate {
		return data, nil
	}

	// Try to decode and re-encode with structural changes
	var decoded interface{}
	err := rlp.DecodeBytes(data, &decoded)
	if err != nil {
		// If decoding fails, apply raw structural mutations
		return r.mutateRawStructure(data, config)
	}

	// Apply structural mutations to decoded data
	mutatedDecoded := r.mutateDecodedStructure(decoded, config, 0)
	
	// Re-encode
	return rlp.EncodeToBytes(mutatedDecoded)
}

// corruptData applies data corruption mutations
func (r *RLPMutator) corruptData(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	if len(data) == 0 || r.rng.Float64() > config.RLP.CorruptionRate {
		return data, nil
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Corrupt random bytes
	numCorruptions := r.rng.Intn(config.RLP.MaxCorruptBytes) + 1
	for i := 0; i < numCorruptions && i < len(mutated); i++ {
		index := r.rng.Intn(len(mutated))
		mutated[index] = byte(r.rng.Intn(256))
	}

	return mutated, nil
}

// injectMalformedRLP injects malformed RLP structures
func (r *RLPMutator) injectMalformedRLP(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	// Create various malformed RLP patterns
	malformedPatterns := [][]byte{
		// Invalid length encoding
		{0xb8, 0x00}, // Long string with zero length
		{0xf8, 0x00}, // Long list with zero length
		
		// Inconsistent length
		{0x85, 0x01, 0x02}, // Claims 5 bytes but only has 2
		{0xc3, 0x01},       // Claims 3 bytes list but only has 1
		
		// Invalid type transitions
		{0x80, 0xc0}, // String followed by list marker
		{0xc0, 0x80}, // List followed by string marker
		
		// Extreme values
		{0xbf, 0xff, 0xff, 0xff, 0xff}, // Maximum long string length
		{0xff, 0xff, 0xff, 0xff, 0xff}, // Maximum long list length
	}

	// Choose random pattern
	pattern := malformedPatterns[r.rng.Intn(len(malformedPatterns))]
	
	// Inject at random position
	if len(data) == 0 {
		return pattern, nil
	}
	
	insertPos := r.rng.Intn(len(data) + 1)
	result := make([]byte, 0, len(data)+len(pattern))
	result = append(result, data[:insertPos]...)
	result = append(result, pattern...)
	result = append(result, data[insertPos:]...)
	
	return result, nil
}

// Helper functions for RLP analysis

// isLengthIndicator checks if a byte is an RLP length indicator
func (r *RLPMutator) isLengthIndicator(b byte) bool {
	return b >= 0x80 // All RLP encoded data starts with 0x80 or higher
}

// isLongForm checks if the encoding uses long form
func (r *RLPMutator) isLongForm(b byte) bool {
	return (b >= 0xb8 && b <= 0xbf) || (b >= 0xf8 && b <= 0xff)
}

// getLengthByteCount returns the number of bytes used to encode length
func (r *RLPMutator) getLengthByteCount(b byte) int {
	if b >= 0xb8 && b <= 0xbf {
		return int(b - 0xb7)
	}
	if b >= 0xf8 && b <= 0xff {
		return int(b - 0xf7)
	}
	return 0
}

// isTypeIndicator checks if a byte indicates RLP type
func (r *RLPMutator) isTypeIndicator(b byte) bool {
	return b >= 0x80
}

// mutateLengthByte mutates a length encoding byte
func (r *RLPMutator) mutateLengthByte(b byte) byte {
	switch {
	case b < 0x80:
		// Single byte, make it a short string
		return 0x80 + byte(r.rng.Intn(56))
	case b >= 0x80 && b <= 0xb7:
		// Short string, randomize length
		return 0x80 + byte(r.rng.Intn(56))
	case b >= 0xb8 && b <= 0xbf:
		// Long string, change length byte count
		return 0xb8 + byte(r.rng.Intn(8))
	case b >= 0xc0 && b <= 0xf7:
		// Short list, randomize length
		return 0xc0 + byte(r.rng.Intn(56))
	case b >= 0xf8 && b <= 0xff:
		// Long list, change length byte count
		return 0xf8 + byte(r.rng.Intn(8))
	default:
		return b
	}
}

// mutateTypeByte converts between RLP types
func (r *RLPMutator) mutateTypeByte(b byte) byte {
	switch {
	case b >= 0x80 && b <= 0xbf:
		// String -> List
		if b <= 0xb7 {
			// Short string -> Short list
			return 0xc0 + (b - 0x80)
		} else {
			// Long string -> Long list
			return 0xf8 + (b - 0xb8)
		}
	case b >= 0xc0 && b <= 0xff:
		// List -> String
		if b <= 0xf7 {
			// Short list -> Short string
			return 0x80 + (b - 0xc0)
		} else {
			// Long list -> Long string
			return 0xb8 + (b - 0xf8)
		}
	default:
		return b
	}
}

// mutateRawStructure applies raw byte-level structural mutations
func (r *RLPMutator) mutateRawStructure(data []byte, config *mutation.MutationConfig) ([]byte, error) {
	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Insert random RLP markers
	if r.rng.Float64() < 0.3 {
		markers := []byte{0x80, 0xc0, 0x81, 0xc1} // Various RLP type markers
		marker := markers[r.rng.Intn(len(markers))]
		insertPos := r.rng.Intn(len(mutated) + 1)
		
		result := make([]byte, 0, len(mutated)+1)
		result = append(result, mutated[:insertPos]...)
		result = append(result, marker)
		result = append(result, mutated[insertPos:]...)
		mutated = result
	}

	// Remove random bytes
	if r.rng.Float64() < 0.2 && len(mutated) > 1 {
		removePos := r.rng.Intn(len(mutated))
		mutated = append(mutated[:removePos], mutated[removePos+1:]...)
	}

	return mutated, nil
}

// mutateDecodedStructure mutates the logical structure of decoded RLP data
func (r *RLPMutator) mutateDecodedStructure(data interface{}, config *mutation.MutationConfig, depth int) interface{} {
	if depth > config.RLP.MaxNestingLevel {
		return data
	}

	switch v := data.(type) {
	case []interface{}:
		// Mutate list structure
		return r.mutateList(v, config, depth)
	case []byte:
		// Mutate byte array
		return r.mutateByteArray(v, config)
	case string:
		// Mutate string
		return r.mutateString(v, config)
	case *big.Int:
		// Mutate big integer
		return r.mutateBigInt(v, config)
	case uint64:
		// Mutate uint64
		return r.mutateUint64(v, config)
	default:
		return data
	}
}

// mutateList mutates list structures
func (r *RLPMutator) mutateList(list []interface{}, config *mutation.MutationConfig, depth int) []interface{} {
	if len(list) == 0 {
		return list
	}

	mutated := make([]interface{}, len(list))
	copy(mutated, list)

	// Recursively mutate elements
	for i := 0; i < len(mutated); i++ {
		if r.rng.Float64() < 0.3 {
			mutated[i] = r.mutateDecodedStructure(mutated[i], config, depth+1)
		}
	}

	// Structural mutations
	if r.rng.Float64() < 0.1 {
		if r.rng.Intn(2) == 0 && len(mutated) > 1 {
			// Remove element
			index := r.rng.Intn(len(mutated))
			mutated = append(mutated[:index], mutated[index+1:]...)
		} else {
			// Add element
			newElement := r.generateRandomElement()
			mutated = append(mutated, newElement)
		}
	}

	return mutated
}

// Helper mutation functions

func (r *RLPMutator) mutateByteArray(data []byte, config *mutation.MutationConfig) []byte {
	if len(data) == 0 {
		return data
	}

	mutated := make([]byte, len(data))
	copy(mutated, data)

	// Random byte mutations
	for i := 0; i < len(mutated); i++ {
		if r.rng.Float64() < 0.1 {
			mutated[i] = byte(r.rng.Intn(256))
		}
	}

	return mutated
}

func (r *RLPMutator) mutateString(s string, config *mutation.MutationConfig) string {
	bytes := []byte(s)
	mutatedBytes := r.mutateByteArray(bytes, config)
	return string(mutatedBytes)
}

func (r *RLPMutator) mutateBigInt(bi *big.Int, config *mutation.MutationConfig) *big.Int {
	if bi == nil {
		return big.NewInt(int64(r.rng.Uint64()))
	}

	result := new(big.Int).Set(bi)
	
	// Apply random mutations
	switch r.rng.Intn(4) {
	case 0:
		result.Add(result, big.NewInt(int64(r.rng.Uint32())))
	case 1:
		result.Sub(result, big.NewInt(int64(r.rng.Uint32())))
	case 2:
		result.SetInt64(0)
	case 3:
		result.SetUint64(^uint64(0)) // Max value
	}

	return result
}

func (r *RLPMutator) mutateUint64(val uint64, config *mutation.MutationConfig) uint64 {
	switch r.rng.Intn(4) {
	case 0:
		return val + uint64(r.rng.Uint32())
	case 1:
		return val - uint64(r.rng.Uint32())
	case 2:
		return 0
	case 3:
		return ^uint64(0) // Max value
	default:
		return val
	}
}

func (r *RLPMutator) generateRandomElement() interface{} {
	switch r.rng.Intn(4) {
	case 0:
		// Random bytes
		length := r.rng.Intn(32) + 1
		bytes := make([]byte, length)
		rand.Read(bytes)
		return bytes
	case 1:
		// Random string
		length := r.rng.Intn(16) + 1
		bytes := make([]byte, length)
		for i := range bytes {
			bytes[i] = byte(r.rng.Intn(95) + 32) // Printable ASCII
		}
		return string(bytes)
	case 2:
		// Random big int
		return big.NewInt(int64(r.rng.Uint64()))
	case 3:
		// Random uint64
		return r.rng.Uint64()
	default:
		return []byte{}
	}
}