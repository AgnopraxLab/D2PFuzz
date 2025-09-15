package mutation

import (
	"fmt"
	"time"
)

// MutationConfig holds configuration for mutation operations
type MutationConfig struct {
	// General mutation settings
	Enabled      bool    `yaml:"enabled"`
	MutationRate float64 `yaml:"mutation_rate"` // Probability of mutation (0.0 to 1.0)
	Seed         int64   `yaml:"seed"`          // Random seed, 0 means use current time
	
	// ETH Protocol specific settings
	ETH ETHMutationConfig `yaml:"eth"`
	
	// RLP encoding specific settings
	RLP RLPMutationConfig `yaml:"rlp"`
	
	// Performance settings
	MaxMutationSize int           `yaml:"max_mutation_size"` // Maximum size of data to mutate
	Timeout         time.Duration `yaml:"timeout"`           // Timeout for mutation operations
	
	// Logging and debugging
	Verbose     bool `yaml:"verbose"`      // Enable verbose logging
	DebugMode   bool `yaml:"debug_mode"`   // Enable debug mode
	LogMutations bool `yaml:"log_mutations"` // Log all mutations
}

// ETHMutationConfig holds ETH protocol specific mutation settings
type ETHMutationConfig struct {
	// Protocol message mutation
	MutateStatus      bool    `yaml:"mutate_status"`       // Mutate Status messages
	MutateNewBlock    bool    `yaml:"mutate_new_block"`    // Mutate NewBlock messages
	MutateTransactions bool   `yaml:"mutate_transactions"` // Mutate Transaction messages
	MutateHeaders     bool    `yaml:"mutate_headers"`      // Mutate BlockHeaders messages
	MutateBodies      bool    `yaml:"mutate_bodies"`       // Mutate BlockBodies messages
	
	// Field-specific mutation rates
	FieldMutationRate float64 `yaml:"field_mutation_rate"` // Rate for individual field mutations
	
	// Value ranges for mutations
	MaxBlockNumber uint64 `yaml:"max_block_number"` // Maximum block number for mutations
	MaxGasLimit    uint64 `yaml:"max_gas_limit"`    // Maximum gas limit for mutations
	MaxGasPrice    uint64 `yaml:"max_gas_price"`    // Maximum gas price for mutations
	
	// Protocol version settings
	TargetProtocolVersion uint `yaml:"target_protocol_version"` // Target ETH protocol version
	MutateProtocolVersion bool `yaml:"mutate_protocol_version"` // Allow protocol version mutations
}

// RLPMutationConfig holds RLP encoding specific mutation settings
type RLPMutationConfig struct {
	// Length field mutations
	MutateLengths    bool    `yaml:"mutate_lengths"`     // Mutate RLP length fields
	LengthMutationRate float64 `yaml:"length_mutation_rate"` // Rate for length mutations
	
	// Type confusion attacks
	MutateTypes     bool    `yaml:"mutate_types"`      // Enable type confusion mutations
	TypeMutationRate float64 `yaml:"type_mutation_rate"` // Rate for type mutations
	
	// Structure mutations
	MutateStructure bool    `yaml:"mutate_structure"`      // Mutate nested structures
	MaxNestingLevel int     `yaml:"max_nesting_level"`     // Maximum nesting level for mutations
	StructureMutationRate float64 `yaml:"structure_mutation_rate"` // Rate for structure mutations
	
	// Data corruption
	CorruptData     bool    `yaml:"corrupt_data"`       // Enable data corruption
	CorruptionRate  float64 `yaml:"corruption_rate"`    // Rate for data corruption
	MaxCorruptBytes int     `yaml:"max_corrupt_bytes"`  // Maximum bytes to corrupt
}

// DefaultMutationConfig returns a default mutation configuration
func DefaultMutationConfig() *MutationConfig {
	return &MutationConfig{
		Enabled:      true,
		MutationRate: 0.1, // 10% mutation rate
		Seed:         0,   // Use current time
		
		ETH: ETHMutationConfig{
			MutateStatus:          true,
			MutateNewBlock:        true,
			MutateTransactions:    true,
			MutateHeaders:         true,
			MutateBodies:          true,
			FieldMutationRate:     0.05, // 5% field mutation rate
			MaxBlockNumber:        1000000,
			MaxGasLimit:           15000000,
			MaxGasPrice:           100000000000, // 100 Gwei
			TargetProtocolVersion: 68,
			MutateProtocolVersion: false,
		},
		
		RLP: RLPMutationConfig{
			MutateLengths:         true,
			LengthMutationRate:    0.02, // 2% length mutation rate
			MutateTypes:           true,
			TypeMutationRate:      0.01, // 1% type mutation rate
			MutateStructure:       true,
			MaxNestingLevel:       10,
			StructureMutationRate: 0.03, // 3% structure mutation rate
			CorruptData:           true,
			CorruptionRate:        0.01, // 1% corruption rate
			MaxCorruptBytes:       16,
		},
		
		MaxMutationSize: 1024 * 1024, // 1MB
		Timeout:         30 * time.Second,
		
		Verbose:      false,
		DebugMode:    false,
		LogMutations: false,
	}
}

// Validate validates the mutation configuration
func (c *MutationConfig) Validate() error {
	if c.MutationRate < 0.0 || c.MutationRate > 1.0 {
		return fmt.Errorf("mutation_rate must be between 0.0 and 1.0, got %f", c.MutationRate)
	}
	
	if c.ETH.FieldMutationRate < 0.0 || c.ETH.FieldMutationRate > 1.0 {
		return fmt.Errorf("eth.field_mutation_rate must be between 0.0 and 1.0, got %f", c.ETH.FieldMutationRate)
	}
	
	if c.RLP.LengthMutationRate < 0.0 || c.RLP.LengthMutationRate > 1.0 {
		return fmt.Errorf("rlp.length_mutation_rate must be between 0.0 and 1.0, got %f", c.RLP.LengthMutationRate)
	}
	
	if c.MaxMutationSize <= 0 {
		return fmt.Errorf("max_mutation_size must be positive, got %d", c.MaxMutationSize)
	}
	
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %v", c.Timeout)
	}
	
	return nil
}

// Clone creates a deep copy of the mutation configuration
func (c *MutationConfig) Clone() *MutationConfig {
	return &MutationConfig{
		Enabled:      c.Enabled,
		MutationRate: c.MutationRate,
		Seed:         c.Seed,
		ETH:          c.ETH,
		RLP:          c.RLP,
		MaxMutationSize: c.MaxMutationSize,
		Timeout:      c.Timeout,
		Verbose:      c.Verbose,
		DebugMode:    c.DebugMode,
		LogMutations: c.LogMutations,
	}
}