package mutation

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// MutationStrategy defines the interface for different mutation strategies
type MutationStrategy interface {
	// Name returns the name of the mutation strategy
	Name() string
	
	// Mutate applies mutation to the input data and returns mutated data
	Mutate(data []byte, config *MutationConfig) ([]byte, error)
	
	// CanMutate checks if this strategy can mutate the given data
	CanMutate(data []byte) bool
	
	// Priority returns the priority of this strategy (higher = more priority)
	Priority() int
}

// MutationResult represents the result of a mutation operation
type MutationResult struct {
	OriginalData []byte
	MutatedData  []byte
	Strategy     string
	Timestamp    time.Time
	Success      bool
	Error        error
}

// Mutator is the main mutation manager that coordinates different strategies
type Mutator struct {
	strategies []MutationStrategy
	config     *MutationConfig
	logger     utils.Logger
	rng        *rand.Rand
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewMutator creates a new mutation manager
func NewMutator(config *MutationConfig, logger utils.Logger) *Mutator {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Initialize random number generator
	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	
	return &Mutator{
		strategies: make([]MutationStrategy, 0),
		config:     config,
		logger:     logger,
		rng:        rand.New(rand.NewSource(seed)),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterStrategy registers a new mutation strategy
func (m *Mutator) RegisterStrategy(strategy MutationStrategy) {
	m.strategies = append(m.strategies, strategy)
	m.logger.Info("Registered mutation strategy: %s", strategy.Name())
}

// GetStrategies returns all registered strategies
func (m *Mutator) GetStrategies() []MutationStrategy {
	return m.strategies
}

// Mutate applies mutation using the most suitable strategy
func (m *Mutator) Mutate(data []byte) (*MutationResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input data")
	}

	// Find suitable strategies
	suitableStrategies := make([]MutationStrategy, 0)
	for _, strategy := range m.strategies {
		if strategy.CanMutate(data) {
			suitableStrategies = append(suitableStrategies, strategy)
		}
	}

	if len(suitableStrategies) == 0 {
		return nil, fmt.Errorf("no suitable mutation strategy found")
	}

	// Select strategy based on priority and randomness
	selectedStrategy := m.selectStrategy(suitableStrategies)

	// Apply mutation
	result := &MutationResult{
		OriginalData: make([]byte, len(data)),
		Strategy:     selectedStrategy.Name(),
		Timestamp:    time.Now(),
	}
	copy(result.OriginalData, data)

	mutatedData, err := selectedStrategy.Mutate(data, m.config)
	if err != nil {
		result.Success = false
		result.Error = err
		m.logger.Error("Mutation failed with strategy %s: %v", selectedStrategy.Name(), err)
		return result, err
	}

	result.MutatedData = mutatedData
	result.Success = true
	m.logger.Debug("Successfully mutated %d bytes using strategy %s", len(data), selectedStrategy.Name())

	return result, nil
}

// MutateMultiple applies multiple mutations to the same data
func (m *Mutator) MutateMultiple(data []byte, count int) ([]*MutationResult, error) {
	if count <= 0 {
		return nil, fmt.Errorf("invalid mutation count: %d", count)
	}

	results := make([]*MutationResult, 0, count)
	for i := 0; i < count; i++ {
		result, err := m.Mutate(data)
		if err != nil {
			m.logger.Warn("Mutation %d/%d failed: %v", i+1, count, err)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// selectStrategy selects a strategy based on priority and randomness
func (m *Mutator) selectStrategy(strategies []MutationStrategy) MutationStrategy {
	if len(strategies) == 1 {
		return strategies[0]
	}

	// Sort by priority (higher priority first)
	maxPriority := 0
	for _, strategy := range strategies {
		if strategy.Priority() > maxPriority {
			maxPriority = strategy.Priority()
		}
	}

	// Collect strategies with highest priority
	highPriorityStrategies := make([]MutationStrategy, 0)
	for _, strategy := range strategies {
		if strategy.Priority() == maxPriority {
			highPriorityStrategies = append(highPriorityStrategies, strategy)
		}
	}

	// Randomly select from high priority strategies
	index := m.rng.Intn(len(highPriorityStrategies))
	return highPriorityStrategies[index]
}

// Stop stops the mutator and cleans up resources
func (m *Mutator) Stop() {
	m.cancel()
	m.logger.Info("Mutator stopped")
}

// GetConfig returns the current mutation configuration
func (m *Mutator) GetConfig() *MutationConfig {
	return m.config
}

// UpdateConfig updates the mutation configuration
func (m *Mutator) UpdateConfig(config *MutationConfig) {
	m.config = config
	m.logger.Info("Mutation configuration updated")
}

// GetStats returns mutation statistics
func (m *Mutator) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["registered_strategies"] = len(m.strategies)
	stats["config"] = m.config
	return stats
}