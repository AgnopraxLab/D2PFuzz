package fuzzer

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/mutation"
	"github.com/AgnopraxLab/D2PFuzz/mutation/generators"
	"github.com/AgnopraxLab/D2PFuzz/mutation/strategies"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// TransactionRecord records detailed information about each transaction
type TransactionRecord struct {
	Hash          common.Hash     `json:"hash"`
	From          common.Address  `json:"from"`
	To            *common.Address `json:"to"`
	Value         *big.Int        `json:"value"`
	Gas           uint64          `json:"gas"`
	GasPrice      *big.Int        `json:"gasPrice"`
	GasFeeCap     *big.Int        `json:"gasFeeCap,omitempty"`
	GasTipCap     *big.Int        `json:"gasTipCap,omitempty"`
	Nonce         uint64          `json:"nonce"`
	Data          []byte          `json:"data"`
	TxType        uint8           `json:"txType"`
	SentTime      time.Time       `json:"sentTime"`
	MinedTime     *time.Time      `json:"minedTime,omitempty"`
	ConfirmedTime *time.Time      `json:"confirmedTime,omitempty"`
	Status        string          `json:"status"` // pending, mined, failed, confirmed
	GasUsed       *uint64         `json:"gasUsed,omitempty"`
	BlockNumber   *uint64         `json:"blockNumber,omitempty"`
	Error         string          `json:"error,omitempty"`
	MutationUsed  bool            `json:"mutationUsed"`
	MutationType  string          `json:"mutationType,omitempty"`
}

// TxFuzzer represents a transaction fuzzer with enhanced stress testing capabilities
type TxFuzzer struct {
	// Basic components
	client   *ethclient.Client
	accounts []config.Account
	chainID  *big.Int
	logger   utils.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	rng      *rand.Rand

	// Mutation components
	mutationConfig *mutation.MutationConfig
	ethGenerator   *generators.ETHGenerator
	ethMutator     *strategies.ETHMutator
	rlpMutator     *strategies.RLPMutator

	// Transaction tracking
	txRecords       map[common.Hash]*TransactionRecord
	recordsMutex    sync.RWMutex
	stats           *TxStats
	statsMutex      sync.RWMutex // Protect stats updates
	successTxHashes []string     // 成功发送的交易哈希值列表
	failedTxHashes  []string     // 发送失败的交易哈希值列表
	hashMutex       sync.RWMutex // 保护哈希值列表的互斥锁

	// Multi-node support
	clients         map[string]*ethclient.Client // Multiple RPC clients
	clientsMutex    sync.RWMutex
	nodeHealth      map[string]bool // Node health status
	healthMutex     sync.RWMutex
	circuitBreakers map[string]*CircuitBreaker // Circuit breakers per endpoint

	// Load pattern control
	currentTPS int          // Current TPS for dynamic load patterns
	tpsMutex   sync.RWMutex // Protect TPS updates

	// System monitoring
	systemMetrics *SystemMetrics
	metricsMutex  sync.RWMutex
}

// TxStats holds statistics about transaction fuzzing
type TxStats struct {
	TotalSent      int64     `json:"totalSent"`
	TotalMined     int64     `json:"totalMined"`
	TotalFailed    int64     `json:"totalFailed"`
	TotalPending   int64     `json:"totalPending"`
	MutationUsed   int64     `json:"mutationUsed"`
	RandomUsed     int64     `json:"randomUsed"`
	StartTime      time.Time `json:"startTime"`
	LastUpdateTime time.Time `json:"lastUpdateTime"`
	mutex          sync.RWMutex
}

// LoadPattern defines different load testing patterns
type LoadPattern struct {
	Type        string        `json:"type"`        // "constant", "ramp", "spike", "wave"
	StartTPS    int           `json:"startTPS"`    // Starting TPS
	PeakTPS     int           `json:"peakTPS"`     // Peak TPS
	RampTime    time.Duration `json:"rampTime"`    // Time to reach peak
	SustainTime time.Duration `json:"sustainTime"` // Time to sustain peak
	StepSize    int           `json:"stepSize"`    // TPS increment per step
}

// MultiNodeConfig holds multi-node configuration
type MultiNodeConfig struct {
	RPCEndpoints        []string           `json:"rpcEndpoints"`        // Multiple RPC endpoints
	LoadDistribution    map[string]float64 `json:"loadDistribution"`    // Load distribution per endpoint
	FailoverEnabled     bool               `json:"failoverEnabled"`     // Enable failover
	HealthCheckInterval time.Duration      `json:"healthCheckInterval"` // Health check interval
	MaxRetries          int                `json:"maxRetries"`          // Max retries per endpoint
	RetryDelay          time.Duration      `json:"retryDelay"`          // Delay between retries
}

// SystemMetrics holds system performance metrics
type SystemMetrics struct {
	CPUUsage    float64                  `json:"cpuUsage"`
	MemoryUsage float64                  `json:"memoryUsage"`
	NetworkIO   map[string]int64         `json:"networkIO"`
	NodeLatency map[string]time.Duration `json:"nodeLatency"`
	ErrorRates  map[string]float64       `json:"errorRates"`
	Timestamp   time.Time                `json:"timestamp"`
}

// CircuitBreaker represents a circuit breaker for error handling
type CircuitBreaker struct {
	maxFailures  int
	resetTimeout time.Duration
	failures     int
	lastFailTime time.Time
	state        string // "closed", "open", "half-open"
	mutex        sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        "closed",
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	// Check if circuit should be reset
	if cb.state == "open" && time.Since(cb.lastFailTime) > cb.resetTimeout {
		cb.state = "half-open"
		cb.failures = 0
	}

	// If circuit is open, return error immediately
	if cb.state == "open" {
		return fmt.Errorf("circuit breaker is open")
	}

	// Execute function
	err := fn()

	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()

		// Open circuit if max failures reached
		if cb.failures >= cb.maxFailures {
			cb.state = "open"
		}
		return err
	}

	// Reset on success
	if cb.state == "half-open" {
		cb.state = "closed"
	}
	cb.failures = 0

	return nil
}

// RetryConfig represents retry configuration
type RetryConfig struct {
	MaxRetries    int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// RetryWithBackoff executes a function with exponential backoff retry
func RetryWithBackoff(config RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * config.BackoffFactor)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// TxFuzzConfig holds configuration for transaction fuzzing
type TxFuzzConfig struct {
	// Basic configuration
	RPCEndpoint     string
	ChainID         int64
	MaxGasPrice     *big.Int
	MaxGasLimit     uint64
	TxPerSecond     int
	FuzzDuration    time.Duration
	Seed            int64
	UseMutation     bool
	MutationRatio   float64 // 0.0-1.0, ratio of transactions using mutation vs random generation
	EnableTracking  bool
	OutputFile      string
	ConfirmBlocks   uint64 // Number of blocks to wait for confirmation
	SuccessHashFile string // 成功交易哈希文件路径
	FailedHashFile  string // 失败交易哈希文件路径

	// Enhanced configuration for stress testing
	MultiNode       *MultiNodeConfig `json:"multiNode,omitempty"`   // Multi-node configuration
	LoadPattern     *LoadPattern     `json:"loadPattern,omitempty"` // Load pattern configuration
	EnableMetrics   bool             `json:"enableMetrics"`         // Enable system metrics collection
	MetricsInterval time.Duration    `json:"metricsInterval"`       // Metrics collection interval
}

// NewTxFuzzer creates a new transaction fuzzer with enhanced stress testing capabilities
func NewTxFuzzer(cfg *TxFuzzConfig, accounts []config.Account, logger utils.Logger) (*TxFuzzer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize random number generator
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	// Initialize statistics
	stats := &TxStats{
		StartTime:      time.Now(),
		LastUpdateTime: time.Now(),
	}

	// Create base fuzzer
	tf := &TxFuzzer{
		accounts:      accounts,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		rng:           rng,
		txRecords:     make(map[common.Hash]*TransactionRecord),
		stats:         stats,
		clients:       make(map[string]*ethclient.Client),
		nodeHealth:    make(map[string]bool),
		currentTPS:    cfg.TxPerSecond,
		systemMetrics: &SystemMetrics{NetworkIO: make(map[string]int64), NodeLatency: make(map[string]time.Duration), ErrorRates: make(map[string]float64)},
	}

	// Setup RPC connections (multi-node or single-node)
	if cfg.MultiNode != nil && len(cfg.MultiNode.RPCEndpoints) > 0 {
		// Multi-node setup
		tf.circuitBreakers = make(map[string]*CircuitBreaker)
		for _, endpoint := range cfg.MultiNode.RPCEndpoints {
			client, err := ethclient.Dial(endpoint)
			if err != nil {
				logger.Error("Failed to connect to endpoint %s: %v", endpoint, err)
				tf.nodeHealth[endpoint] = false
				continue
			}
			tf.clients[endpoint] = client
			tf.nodeHealth[endpoint] = true

			// Create circuit breaker for each endpoint with proper defaults
			maxRetries := cfg.MultiNode.MaxRetries
			if maxRetries == 0 {
				maxRetries = 3
			}
			retryDelay := cfg.MultiNode.RetryDelay
			if retryDelay == 0 {
				retryDelay = time.Second
			}
			tf.circuitBreakers[endpoint] = NewCircuitBreaker(
				maxRetries,
				retryDelay*5, // Reset timeout is 5x retry delay
			)
		}

		if len(tf.clients) == 0 {
			return nil, fmt.Errorf("failed to connect to any RPC endpoints")
		}

		// Use first healthy client as primary
		for endpoint, client := range tf.clients {
			tf.client = client
			logger.Info("Using %s as primary RPC endpoint", endpoint)
			break
		}
	} else {
		// Single-node setup
		client, err := ethclient.Dial(cfg.RPCEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Ethereum client: %v", err)
		}
		tf.client = client
		tf.clients[cfg.RPCEndpoint] = client
		tf.nodeHealth[cfg.RPCEndpoint] = true

		// Initialize circuit breakers for single node
		tf.circuitBreakers = make(map[string]*CircuitBreaker)
		tf.circuitBreakers[cfg.RPCEndpoint] = NewCircuitBreaker(3, 30*time.Second)
	}

	// Get chain ID
	chainID := big.NewInt(cfg.ChainID)
	if cfg.ChainID == 0 {
		chainID, err := tf.client.ChainID(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get chain ID: %v", err)
		}
		tf.chainID = chainID
	} else {
		tf.chainID = chainID
	}

	// Initialize mutation components if enabled
	if cfg.UseMutation {
		mutationConfig := mutation.DefaultMutationConfig()
		mutationConfig.ETH.TargetProtocolVersion = uint(chainID.Uint64())
		tf.mutationConfig = mutationConfig
		tf.ethGenerator = generators.NewETHGenerator(mutationConfig)
		tf.ethMutator = strategies.NewETHMutator(seed)
		tf.rlpMutator = strategies.NewRLPMutator(seed)
	}

	// Start health monitoring for multi-node setup
	if cfg.MultiNode != nil && cfg.MultiNode.HealthCheckInterval > 0 {
		go tf.startHealthMonitoring(cfg.MultiNode.HealthCheckInterval)
	}

	// Start system metrics collection if enabled
	if cfg.EnableMetrics && cfg.MetricsInterval > 0 {
		go tf.startMetricsCollection(cfg.MetricsInterval)
	}

	return tf, nil
}

// Start begins the transaction fuzzing process with enhanced load patterns
func (tf *TxFuzzer) Start(cfg *TxFuzzConfig) error {
	tf.logger.Info("Starting enhanced transaction fuzzing with seed: %d", tf.rng.Int63())

	// Initialize load pattern if specified
	if cfg.LoadPattern != nil {
		go tf.manageLoadPattern(cfg)
	}

	// Get current TPS (may be dynamic)
	tf.tpsMutex.RLock()
	currentTPS := tf.currentTPS
	tf.tpsMutex.RUnlock()

	ticker := time.NewTicker(time.Second / time.Duration(currentTPS))
	defer ticker.Stop()

	timeout := time.After(cfg.FuzzDuration)
	txCount := 0

	for {
		select {
		case <-tf.ctx.Done():
			tf.logger.Info("Transaction fuzzing stopped, sent %d transactions", txCount)
			return nil
		case <-timeout:
			tf.logger.Info("Transaction fuzzing completed, sent %d transactions", txCount)
			return nil
		case <-ticker.C:
			// Update ticker if TPS changed
			tf.tpsMutex.RLock()
			newTPS := tf.currentTPS
			tf.tpsMutex.RUnlock()

			if newTPS != currentTPS {
				currentTPS = newTPS
				ticker.Stop()
				ticker = time.NewTicker(time.Second / time.Duration(currentTPS))
			}

			if err := tf.sendRandomTransaction(cfg); err != nil {
				tf.logger.Error("Failed to send transaction: %v", err)
			} else {
				txCount++
				if txCount%100 == 0 {
					tf.logger.Info("Sent %d transactions (Current TPS: %d)", txCount, currentTPS)
				}
			}
		}
	}
}

// manageLoadPattern manages dynamic load patterns
func (tf *TxFuzzer) manageLoadPattern(cfg *TxFuzzConfig) {
	pattern := cfg.LoadPattern
	if pattern == nil {
		return
	}

	tf.logger.Info("Starting load pattern: %s", pattern.Type)

	switch pattern.Type {
	case "ramp":
		tf.executeRampPattern(pattern)
	case "spike":
		tf.executeSpikePattern(pattern)
	case "wave":
		tf.executeWavePattern(pattern)
	default:
		tf.logger.Info("Using constant load pattern")
	}
}

// executeRampPattern executes a ramp load pattern
func (tf *TxFuzzer) executeRampPattern(pattern *LoadPattern) {
	steps := int(pattern.RampTime.Seconds())
	if steps <= 0 {
		steps = 1
	}

	tpsIncrement := float64(pattern.PeakTPS-pattern.StartTPS) / float64(steps)

	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.StartTPS
	tf.tpsMutex.Unlock()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	currentStep := 0
	for range ticker.C {
		if currentStep >= steps {
			break
		}

		newTPS := pattern.StartTPS + int(float64(currentStep)*tpsIncrement)
		tf.tpsMutex.Lock()
		tf.currentTPS = newTPS
		tf.tpsMutex.Unlock()

		tf.logger.Debug("Ramp pattern: TPS = %d (step %d/%d)", newTPS, currentStep+1, steps)
		currentStep++
	}

	// Sustain peak TPS
	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.PeakTPS
	tf.tpsMutex.Unlock()

	tf.logger.Info("Reached peak TPS: %d, sustaining for %v", pattern.PeakTPS, pattern.SustainTime)
}

// executeSpikePattern executes a spike load pattern
func (tf *TxFuzzer) executeSpikePattern(pattern *LoadPattern) {
	// Start with base TPS
	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.StartTPS
	tf.tpsMutex.Unlock()

	// Wait for ramp time, then spike
	time.Sleep(pattern.RampTime)

	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.PeakTPS
	tf.tpsMutex.Unlock()

	tf.logger.Info("Spike pattern: TPS spiked to %d", pattern.PeakTPS)

	// Sustain spike
	time.Sleep(pattern.SustainTime)

	// Return to base TPS
	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.StartTPS
	tf.tpsMutex.Unlock()

	tf.logger.Info("Spike pattern: TPS returned to %d", pattern.StartTPS)
}

// executeWavePattern executes a wave load pattern
func (tf *TxFuzzer) executeWavePattern(pattern *LoadPattern) {
	tf.tpsMutex.Lock()
	tf.currentTPS = pattern.StartTPS
	tf.tpsMutex.Unlock()

	ticker := time.NewTicker(time.Second * 5) // Wave every 5 seconds
	defer ticker.Stop()

	waveUp := true
	for range ticker.C {
		select {
		case <-tf.ctx.Done():
			return
		default:
		}

		var newTPS int
		if waveUp {
			newTPS = pattern.PeakTPS
		} else {
			newTPS = pattern.StartTPS
		}

		tf.tpsMutex.Lock()
		tf.currentTPS = newTPS
		tf.tpsMutex.Unlock()

		tf.logger.Debug("Wave pattern: TPS = %d", newTPS)
		waveUp = !waveUp
	}
}

// startHealthMonitoring monitors the health of RPC endpoints
func (tf *TxFuzzer) startHealthMonitoring(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-ticker.C:
			tf.checkNodeHealth()
		}
	}
}

// checkNodeHealth checks the health of all RPC endpoints
func (tf *TxFuzzer) checkNodeHealth() {
	tf.clientsMutex.RLock()
	clients := make(map[string]*ethclient.Client)
	for endpoint, client := range tf.clients {
		clients[endpoint] = client
	}
	tf.clientsMutex.RUnlock()

	for endpoint, client := range clients {
		start := time.Now()
		_, err := client.ChainID(context.Background())
		latency := time.Since(start)

		tf.healthMutex.Lock()
		tf.nodeHealth[endpoint] = (err == nil)
		tf.healthMutex.Unlock()

		tf.metricsMutex.Lock()
		tf.systemMetrics.NodeLatency[endpoint] = latency
		if err != nil {
			tf.systemMetrics.ErrorRates[endpoint]++
		}
		tf.metricsMutex.Unlock()

		if err != nil {
			tf.logger.Error("Health check failed for %s: %v", endpoint, err)
		} else {
			tf.logger.Debug("Health check passed for %s (latency: %v)", endpoint, latency)
		}
	}
}

// startMetricsCollection collects system metrics
func (tf *TxFuzzer) startMetricsCollection(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-ticker.C:
			tf.collectSystemMetrics()
		}
	}
}

// StartWithContext starts the fuzzing process with context support
func (tf *TxFuzzer) StartWithContext(ctx context.Context, cfg *TxFuzzConfig) error {
	// Store context for use in other methods
	tf.ctx = ctx

	// Initialize current TPS from config
	tf.tpsMutex.Lock()
	tf.currentTPS = cfg.TxPerSecond
	tf.tpsMutex.Unlock()

	// Start the regular Start method
	return tf.Start(cfg)
}

// GetEnhancedStats returns comprehensive statistics including per-node metrics
func (tf *TxFuzzer) GetEnhancedStats() *TxStats {
	tf.statsMutex.RLock()
	defer tf.statsMutex.RUnlock()

	// Create a copy of the stats
	stats := &TxStats{
		TotalSent:      tf.stats.TotalSent,
		TotalMined:     tf.stats.TotalMined,
		TotalFailed:    tf.stats.TotalFailed,
		TotalPending:   tf.stats.TotalPending,
		MutationUsed:   tf.stats.MutationUsed,
		RandomUsed:     tf.stats.RandomUsed,
		StartTime:      tf.stats.StartTime,
		LastUpdateTime: tf.stats.LastUpdateTime,
	}

	return stats
}

// GetSystemMetrics returns current system metrics
func (tf *TxFuzzer) GetSystemMetrics() *SystemMetrics {
	tf.metricsMutex.RLock()
	defer tf.metricsMutex.RUnlock()

	if tf.systemMetrics == nil {
		return &SystemMetrics{
			CPUUsage:    0.0,
			MemoryUsage: 0.0,
			NetworkIO:   make(map[string]int64),
			NodeLatency: make(map[string]time.Duration),
			ErrorRates:  make(map[string]float64),
			Timestamp:   time.Now(),
		}
	}

	// Create a copy to avoid race conditions
	metrics := &SystemMetrics{
		CPUUsage:    tf.systemMetrics.CPUUsage,
		MemoryUsage: tf.systemMetrics.MemoryUsage,
		NetworkIO:   make(map[string]int64),
		NodeLatency: make(map[string]time.Duration),
		ErrorRates:  make(map[string]float64),
		Timestamp:   tf.systemMetrics.Timestamp,
	}

	// Copy maps
	for k, v := range tf.systemMetrics.NetworkIO {
		metrics.NetworkIO[k] = v
	}
	for k, v := range tf.systemMetrics.NodeLatency {
		metrics.NodeLatency[k] = v
	}
	for k, v := range tf.systemMetrics.ErrorRates {
		metrics.ErrorRates[k] = v
	}

	return metrics
}

// GetHealthStatus returns the health status of all nodes
func (tf *TxFuzzer) GetHealthStatus() map[string]bool {
	tf.healthMutex.RLock()
	defer tf.healthMutex.RUnlock()

	health := make(map[string]bool)
	for endpoint, status := range tf.nodeHealth {
		health[endpoint] = status
	}

	return health
}

// GetCurrentTPS returns the current transactions per second
func (tf *TxFuzzer) GetCurrentTPS() int {
	tf.tpsMutex.RLock()
	defer tf.tpsMutex.RUnlock()
	return tf.currentTPS
}

// PrintRealTimeStats prints real-time statistics to console
func (tf *TxFuzzer) PrintRealTimeStats() {
	stats := tf.GetEnhancedStats()
	metrics := tf.GetSystemMetrics()
	health := tf.GetHealthStatus()

	tf.logger.Info("=== Real-Time Fuzzing Statistics ===")
	tf.logger.Info("Current TPS: %d", tf.GetCurrentTPS())
	tf.logger.Info("Total Sent: %d", stats.TotalSent)
	tf.logger.Info("Total Mined: %d", stats.TotalMined)
	tf.logger.Info("Total Failed: %d", stats.TotalFailed)
	tf.logger.Info("Total Pending: %d", stats.TotalPending)
	tf.logger.Info("Mutation Used: %d", stats.MutationUsed)
	tf.logger.Info("Random Used: %d", stats.RandomUsed)

	if stats.TotalSent > 0 {
		successRate := float64(stats.TotalMined) / float64(stats.TotalSent) * 100
		tf.logger.Info("Success Rate: %.2f%%", successRate)
	}

	tf.logger.Info("=== System Metrics ===")
	tf.logger.Info("CPU Usage: %.1f%%", metrics.CPUUsage)
	tf.logger.Info("Memory Usage: %.1f%%", metrics.MemoryUsage)
	tf.logger.Info("Last Updated: %s", metrics.Timestamp.Format("15:04:05"))

	tf.logger.Info("=== Node Health ===")
	for endpoint, healthy := range health {
		status := "DOWN"
		if healthy {
			status = "UP"
		}

		latency := "N/A"
		if lat, exists := metrics.NodeLatency[endpoint]; exists {
			latency = lat.String()
		}

		tf.logger.Info("  %s: %s (Latency: %s)", endpoint, status, latency)
	}

	tf.logger.Info("=============================")
}

// collectSystemMetrics collects system performance metrics
func (tf *TxFuzzer) collectSystemMetrics() {
	tf.metricsMutex.Lock()
	defer tf.metricsMutex.Unlock()

	if tf.systemMetrics == nil {
		tf.systemMetrics = &SystemMetrics{
			NetworkIO:   make(map[string]int64),
			NodeLatency: make(map[string]time.Duration),
			ErrorRates:  make(map[string]float64),
		}
	}

	// Update timestamp
	tf.systemMetrics.Timestamp = time.Now()

	// Simulate CPU and memory usage collection
	// In a real implementation, you would use system calls or libraries like gopsutil
	tf.systemMetrics.CPUUsage = float64(tf.rng.Intn(100))
	tf.systemMetrics.MemoryUsage = float64(tf.rng.Intn(100))

	tf.logger.Debug("Collected system metrics: CPU=%.2f%%, Memory=%.2f%%",
		tf.systemMetrics.CPUUsage, tf.systemMetrics.MemoryUsage)
}

// sendTransactionWithRetry sends a transaction with retry and circuit breaker protection
func (tf *TxFuzzer) sendTransactionWithRetry(endpoint string, tx *types.Transaction, cfg *TxFuzzConfig) error {
	client := tf.getHealthyClient(endpoint)
	if client == nil {
		return fmt.Errorf("no healthy client available for endpoint: %s", endpoint)
	}

	// Get circuit breaker for this endpoint
	tf.clientsMutex.RLock()
	cb, exists := tf.circuitBreakers[endpoint]
	tf.clientsMutex.RUnlock()

	if !exists {
		return fmt.Errorf("no circuit breaker found for endpoint: %s", endpoint)
	}

	// Configure retry settings using config values
	maxRetries := 3
	retryDelay := 100 * time.Millisecond

	if cfg.MultiNode != nil {
		if cfg.MultiNode.MaxRetries > 0 {
			maxRetries = cfg.MultiNode.MaxRetries
		}
		if cfg.MultiNode.RetryDelay > 0 {
			retryDelay = cfg.MultiNode.RetryDelay
		}
	}

	retryConfig := RetryConfig{
		MaxRetries:    maxRetries,
		InitialDelay:  retryDelay,
		MaxDelay:      retryDelay * 20,
		BackoffFactor: 2.0,
	}

	// Execute with circuit breaker and retry
	return cb.Call(func() error {
		return RetryWithBackoff(retryConfig, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			return client.SendTransaction(ctx, tx)
		})
	})
}

// getHealthyClient returns a healthy client for the given endpoint
func (tf *TxFuzzer) getHealthyClient(endpoint string) *ethclient.Client {
	tf.clientsMutex.RLock()
	defer tf.clientsMutex.RUnlock()

	tf.healthMutex.RLock()
	defer tf.healthMutex.RUnlock()

	if healthy, exists := tf.nodeHealth[endpoint]; exists && healthy {
		if client, exists := tf.clients[endpoint]; exists {
			return client
		}
	}

	return nil
}

// selectHealthyEndpoint selects a healthy endpoint using round-robin
func (tf *TxFuzzer) selectHealthyEndpoint() string {
	tf.healthMutex.RLock()
	defer tf.healthMutex.RUnlock()

	var healthyEndpoints []string
	for endpoint, healthy := range tf.nodeHealth {
		if healthy {
			healthyEndpoints = append(healthyEndpoints, endpoint)
		}
	}

	if len(healthyEndpoints) == 0 {
		return ""
	}

	// Simple round-robin selection
	index := int(atomic.LoadInt64(&tf.stats.TotalSent)) % len(healthyEndpoints)
	return healthyEndpoints[index]
}

// checkAllEndpointsHealth checks health of all configured endpoints
func (tf *TxFuzzer) checkAllEndpointsHealth() {
	tf.clientsMutex.RLock()
	clients := make(map[string]*ethclient.Client)
	for k, v := range tf.clients {
		clients[k] = v
	}
	tf.clientsMutex.RUnlock()

	for endpoint, client := range clients {
		healthy := tf.checkEndpointHealth(client)

		tf.healthMutex.Lock()
		oldHealth := tf.nodeHealth[endpoint]
		tf.nodeHealth[endpoint] = healthy
		tf.healthMutex.Unlock()

		// Log health status changes
		if oldHealth != healthy {
			if healthy {
				tf.logger.Info("Endpoint %s is now healthy", endpoint)
			} else {
				tf.logger.Warn("Endpoint %s is now unhealthy", endpoint)
			}
		}
	}
}

// checkEndpointHealth checks if an endpoint is healthy
func (tf *TxFuzzer) checkEndpointHealth(client *ethclient.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get the latest block number as a health check
	_, err := client.BlockNumber(ctx)
	return err == nil
}

// sendRandomTransaction generates and sends a random transaction with enhanced error handling
func (tf *TxFuzzer) sendRandomTransaction(cfg *TxFuzzConfig) error {
	// Select a healthy endpoint
	endpoint := tf.selectHealthyEndpoint()
	if endpoint == "" {
		return fmt.Errorf("no healthy endpoints available")
	}

	// Get a random account
	account := tf.accounts[tf.rng.Intn(len(tf.accounts))]
	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get client for the selected endpoint
	client := tf.getHealthyClient(endpoint)
	if client == nil {
		return fmt.Errorf("no healthy client available for endpoint: %s", endpoint)
	}

	// Get nonce with retry
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := tf.getNonceWithRetry(client, address, 3)
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}

	// Generate transaction
	tx, mutationUsed, mutationType, err := tf.generateTransaction(privateKey, nonce, cfg)
	if err != nil {
		return fmt.Errorf("failed to generate transaction: %w", err)
	}

	// Send transaction with retry and circuit breaker
	startTime := time.Now()
	err = tf.sendTransactionWithRetry(endpoint, tx, cfg)
	latency := time.Since(startTime)

	// Update metrics
	tf.updateTransactionMetrics(endpoint, err, latency)

	if err != nil {
		tf.updateStats("failed", mutationUsed)
		tf.logger.Debug("Failed to send transaction: %v", err)
		return err
	}

	// Record successful transaction
	tf.recordTransaction(tx, mutationUsed, mutationType)
	tf.updateStats("sent", mutationUsed)

	// Start monitoring if tracking is enabled
	if cfg.EnableTracking {
		go tf.monitorTransaction(tx.Hash(), cfg.ConfirmBlocks)
	}

	tf.logger.Debug("Transaction sent: %s (endpoint: %s, latency: %v)",
		tx.Hash().Hex(), endpoint, latency)

	return nil
}

// recordTransaction records a transaction in the tracking system
func (tf *TxFuzzer) recordTransaction(tx *types.Transaction, mutationUsed bool, mutationType string) {
	record := &TransactionRecord{
		Hash:         tx.Hash(),
		From:         tf.getFromAddress(tx),
		To:           tx.To(),
		Value:        tx.Value(),
		Gas:          tx.Gas(),
		GasPrice:     tx.GasPrice(),
		Nonce:        tx.Nonce(),
		Data:         tx.Data(),
		TxType:       tx.Type(),
		SentTime:     time.Now(),
		Status:       "pending",
		MutationUsed: mutationUsed,
		MutationType: mutationType,
	}

	// Handle different transaction types
	if tx.Type() == types.DynamicFeeTxType {
		record.GasFeeCap = tx.GasFeeCap()
		record.GasTipCap = tx.GasTipCap()
	}

	tf.recordsMutex.Lock()
	tf.txRecords[tx.Hash()] = record
	tf.recordsMutex.Unlock()
}

// getFromAddress extracts the from address from a transaction
func (tf *TxFuzzer) getFromAddress(tx *types.Transaction) common.Address {
	signer := types.NewEIP155Signer(tf.chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		// Fallback to zero address if we can't determine sender
		return common.Address{}
	}
	return from
}

// selectHealthyClient selects a healthy client using round-robin load balancing
func (tf *TxFuzzer) selectHealthyClient() (*ethclient.Client, string, error) {
	tf.clientsMutex.RLock()
	tf.healthMutex.RLock()
	defer tf.clientsMutex.RUnlock()
	defer tf.healthMutex.RUnlock()

	var healthyEndpoints []string
	for endpoint, healthy := range tf.nodeHealth {
		if healthy {
			healthyEndpoints = append(healthyEndpoints, endpoint)
		}
	}

	if len(healthyEndpoints) == 0 {
		// Fallback to any available client if no health info
		for endpoint := range tf.clients {
			healthyEndpoints = append(healthyEndpoints, endpoint)
		}
	}

	if len(healthyEndpoints) == 0 {
		return nil, "", fmt.Errorf("no clients available")
	}

	// Simple round-robin selection
	selectedEndpoint := healthyEndpoints[tf.rng.Intn(len(healthyEndpoints))]
	client := tf.clients[selectedEndpoint]

	return client, selectedEndpoint, nil
}

// getNonceWithRetry gets nonce with retry mechanism
func (tf *TxFuzzer) getNonceWithRetry(client *ethclient.Client, address common.Address, maxRetries int) (uint64, error) {
	var nonce uint64
	var err error

	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(tf.ctx, 10*time.Second)
		nonce, err = client.NonceAt(ctx, address, nil)
		cancel()

		if err == nil {
			return nonce, nil
		}

		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second) // Exponential backoff
		}
	}

	return 0, err
}

// updateTransactionMetrics updates transaction-related metrics
func (tf *TxFuzzer) updateTransactionMetrics(endpoint string, err error, latency time.Duration) {
	tf.metricsMutex.Lock()
	defer tf.metricsMutex.Unlock()

	if tf.systemMetrics.NodeLatency == nil {
		tf.systemMetrics.NodeLatency = make(map[string]time.Duration)
	}
	if tf.systemMetrics.ErrorRates == nil {
		tf.systemMetrics.ErrorRates = make(map[string]float64)
	}

	tf.systemMetrics.NodeLatency[endpoint] = latency
	if err != nil {
		tf.systemMetrics.ErrorRates[endpoint]++
	}
}

// updateErrorRate updates error rate for a specific endpoint
func (tf *TxFuzzer) updateErrorRate(endpoint string) {
	tf.metricsMutex.Lock()
	defer tf.metricsMutex.Unlock()

	if tf.systemMetrics.ErrorRates == nil {
		tf.systemMetrics.ErrorRates = make(map[string]float64)
	}
	tf.systemMetrics.ErrorRates[endpoint]++
}

// generateTransaction creates a transaction using mutation or random generation
func (tf *TxFuzzer) generateTransaction(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, bool, string, error) {
	// Decide whether to use mutation or random generation
	useMutation := cfg.UseMutation && tf.rng.Float64() < cfg.MutationRatio

	if useMutation && tf.ethGenerator != nil {
		// Use mutation-based generation
		return tf.generateMutatedTx(privateKey, nonce, cfg)
	} else {
		// Use random generation
		tx, err := tf.generateRandomTx(privateKey, nonce, cfg)
		return tx, false, "random", err
	}
}

// generateMutatedTx creates a transaction using mutation strategies
func (tf *TxFuzzer) generateMutatedTx(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, bool, string, error) {
	// Generate a base transaction using ETH generator
	message, err := tf.ethGenerator.GenerateRandomMessage()
	if err != nil {
		return nil, false, "", err
	}

	// Try to mutate the message
	if tf.ethMutator != nil && tf.ethMutator.CanMutate(message) {
		mutatedMessage, err := tf.ethMutator.Mutate(message, tf.mutationConfig)
		if err == nil {
			// Try to convert mutated message to transaction
			if tx := tf.messageToTransaction(mutatedMessage, privateKey, nonce); tx != nil {
				return tx, true, "eth_mutator", nil
			}
		}
	}

	// Fallback to random generation with RLP mutation
	tx, err := tf.generateRandomTx(privateKey, nonce, cfg)
	if err != nil {
		return nil, false, "", err
	}

	// Try RLP mutation on the transaction
	if tf.rlpMutator != nil {
		txBytes, err := tx.MarshalBinary()
		if err == nil && tf.rlpMutator.CanMutate(txBytes) {
			mutatedBytes, err := tf.rlpMutator.Mutate(txBytes, tf.mutationConfig)
			if err == nil {
				// Try to decode mutated bytes back to transaction
				var mutatedTx types.Transaction
				if err := mutatedTx.UnmarshalBinary(mutatedBytes); err == nil {
					return &mutatedTx, true, "rlp_mutator", nil
				}
			}
		}
	}

	return tx, true, "mutation_fallback", nil
}

// messageToTransaction converts a mutated message to a transaction (simplified)
func (tf *TxFuzzer) messageToTransaction(message []byte, privateKey *ecdsa.PrivateKey, nonce uint64) *types.Transaction {
	// This is a simplified conversion - in practice, you'd need to parse the message
	// and extract transaction fields. For now, return nil to fallback to random generation
	return nil
}

// generateRandomTx creates a random transaction using basic random generation
func (tf *TxFuzzer) generateRandomTx(privateKey *ecdsa.PrivateKey, nonce uint64, cfg *TxFuzzConfig) (*types.Transaction, error) {
	// Use tx-fuzz to generate random transaction parameters
	txType := tf.rng.Intn(3) // 0: Legacy, 1: EIP-1559, 2: EIP-2930

	// Generate random recipient address
	to := tf.generateRandomAddress()

	// Generate random value (0 to 1 ETH)
	value := big.NewInt(tf.rng.Int63n(1000000000000000000)) // 0 to 1 ETH in wei

	// Generate random gas limit
	gasLimit := uint64(21000 + tf.rng.Intn(int(cfg.MaxGasLimit-21000)))

	// Generate random data
	data := tf.generateRandomData()

	var tx *types.Transaction
	var err error

	switch txType {
	case 0: // Legacy transaction
		gasPrice := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		tx = types.NewTransaction(nonce, *to, value, gasLimit, gasPrice, data)
	case 1: // EIP-1559 transaction
		maxFeePerGas := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		maxPriorityFeePerGas := big.NewInt(tf.rng.Int63n(maxFeePerGas.Int64()))
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   tf.chainID,
			Nonce:     nonce,
			To:        to,
			Value:     value,
			Gas:       gasLimit,
			GasFeeCap: maxFeePerGas,
			GasTipCap: maxPriorityFeePerGas,
			Data:      data,
		})
	case 2: // EIP-2930 transaction (Access List)
		gasPrice := big.NewInt(tf.rng.Int63n(cfg.MaxGasPrice.Int64()))
		tx = types.NewTx(&types.AccessListTx{
			ChainID:    tf.chainID,
			Nonce:      nonce,
			To:         to,
			Value:      value,
			Gas:        gasLimit,
			GasPrice:   gasPrice,
			Data:       data,
			AccessList: tf.generateRandomAccessList(),
		})
	}

	// Sign the transaction with appropriate signer
	var signer types.Signer
	switch tx.Type() {
	case types.LegacyTxType:
		signer = types.NewEIP155Signer(tf.chainID)
	case types.AccessListTxType:
		signer = types.NewEIP2930Signer(tf.chainID)
	case types.DynamicFeeTxType:
		signer = types.NewLondonSigner(tf.chainID)
	default:
		signer = types.NewEIP155Signer(tf.chainID)
	}

	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return signedTx, nil
}

// generateRandomAddress creates a random Ethereum address
func (tf *TxFuzzer) generateRandomAddress() *common.Address {
	addr := make([]byte, 20)
	tf.rng.Read(addr)
	address := common.BytesToAddress(addr)
	return &address
}

// generateRandomData creates random transaction data
func (tf *TxFuzzer) generateRandomData() []byte {
	length := tf.rng.Intn(1024) // 0 to 1KB of data
	data := make([]byte, length)
	tf.rng.Read(data)
	return data
}

// generateRandomAccessList creates a random access list for EIP-2930 transactions
func (tf *TxFuzzer) generateRandomAccessList() types.AccessList {
	listLength := tf.rng.Intn(5) // 0 to 4 entries
	accessList := make(types.AccessList, listLength)

	for i := 0; i < listLength; i++ {
		addr := tf.generateRandomAddress()
		storageKeys := make([]common.Hash, tf.rng.Intn(3)) // 0 to 2 storage keys
		for j := range storageKeys {
			key := make([]byte, 32)
			tf.rng.Read(key)
			storageKeys[j] = common.BytesToHash(key)
		}
		accessList[i] = types.AccessTuple{
			Address:     *addr,
			StorageKeys: storageKeys,
		}
	}

	return accessList
}

// Stop stops the transaction fuzzing process
func (tf *TxFuzzer) Stop() {
	if tf.cancel != nil {
		tf.cancel()
	}
}

// updateStats updates the transaction statistics
func (tf *TxFuzzer) updateStats(status string, mutationUsed bool) {
	tf.stats.mutex.Lock()
	defer tf.stats.mutex.Unlock()

	switch status {
	case "sent":
		tf.stats.TotalSent++
	case "mined":
		tf.stats.TotalMined++
	case "failed":
		tf.stats.TotalFailed++
	case "pending":
		tf.stats.TotalPending++
	}

	if mutationUsed {
		tf.stats.MutationUsed++
	} else {
		tf.stats.RandomUsed++
	}

	tf.stats.LastUpdateTime = time.Now()
}

// monitorTransaction monitors a transaction until it's mined or fails
func (tf *TxFuzzer) monitorTransaction(txHash common.Hash, confirmBlocks uint64) {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()

	timeout := time.After(10 * time.Minute) // Timeout after 10 minutes

	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-timeout:
			// Mark as failed due to timeout
			tf.recordsMutex.Lock()
			if record, exists := tf.txRecords[txHash]; exists {
				record.Status = "failed"
				record.Error = "timeout"
			}
			tf.recordsMutex.Unlock()
			tf.updateStats("failed", false)
			return
		case <-ticker.C:
			// Check transaction receipt
			receipt, err := tf.client.TransactionReceipt(tf.ctx, txHash)
			if err != nil {
				continue // Transaction not mined yet
			}

			// Transaction mined, update record
			tf.recordsMutex.Lock()
			if record, exists := tf.txRecords[txHash]; exists {
				now := time.Now()
				record.MinedTime = &now
				record.Status = "mined"
				record.GasUsed = &receipt.GasUsed
				blockNum := receipt.BlockNumber.Uint64()
				record.BlockNumber = &blockNum

				if receipt.Status == types.ReceiptStatusFailed {
					record.Status = "failed"
					record.Error = "transaction reverted"
					tf.updateStats("failed", record.MutationUsed)
				} else {
					tf.updateStats("mined", record.MutationUsed)
				}
			}
			tf.recordsMutex.Unlock()

			// Wait for confirmation blocks if needed
			if confirmBlocks > 0 {
				go tf.waitForConfirmation(txHash, receipt.BlockNumber.Uint64(), confirmBlocks)
			}
			return
		}
	}
}

// waitForConfirmation waits for the specified number of confirmation blocks
func (tf *TxFuzzer) waitForConfirmation(txHash common.Hash, minedBlock uint64, confirmBlocks uint64) {
	ticker := time.NewTicker(15 * time.Second) // Check every 15 seconds
	defer ticker.Stop()

	for {
		select {
		case <-tf.ctx.Done():
			return
		case <-ticker.C:
			currentBlock, err := tf.client.BlockNumber(tf.ctx)
			if err != nil {
				continue
			}

			if currentBlock >= minedBlock+confirmBlocks {
				// Transaction confirmed
				tf.recordsMutex.Lock()
				if record, exists := tf.txRecords[txHash]; exists {
					now := time.Now()
					record.ConfirmedTime = &now
					record.Status = "confirmed"
				}
				tf.recordsMutex.Unlock()
				return
			}
		}
	}
}

// GetStats returns current transaction statistics
func (tf *TxFuzzer) GetStats() TxStats {
	tf.stats.mutex.RLock()
	defer tf.stats.mutex.RUnlock()

	// Create a copy without the mutex to avoid copying lock value
	return TxStats{
		TotalSent:      tf.stats.TotalSent,
		TotalMined:     tf.stats.TotalMined,
		TotalFailed:    tf.stats.TotalFailed,
		TotalPending:   tf.stats.TotalPending,
		MutationUsed:   tf.stats.MutationUsed,
		RandomUsed:     tf.stats.RandomUsed,
		StartTime:      tf.stats.StartTime,
		LastUpdateTime: tf.stats.LastUpdateTime,
	}
}

// GetTransactionRecords returns all transaction records
func (tf *TxFuzzer) GetTransactionRecords() map[common.Hash]*TransactionRecord {
	tf.recordsMutex.RLock()
	defer tf.recordsMutex.RUnlock()

	// Create a copy to avoid race conditions
	records := make(map[common.Hash]*TransactionRecord)
	for hash, record := range tf.txRecords {
		records[hash] = record
	}
	return records
}

// ExportRecordsJSON exports transaction records as JSON
func (tf *TxFuzzer) ExportRecordsJSON() ([]byte, error) {
	records := tf.GetTransactionRecords()
	return json.Marshal(records)
}

// ExportSuccessHashes exports successful transaction hashes to a file
func (tf *TxFuzzer) ExportSuccessHashes(filename string) error {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()

	if len(tf.successTxHashes) == 0 {
		return fmt.Errorf("no successful transaction hashes to export")
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}
	defer file.Close()

	for _, hash := range tf.successTxHashes {
		if _, err := file.WriteString(hash + "\n"); err != nil {
			return fmt.Errorf("failed to write hash to file: %v", err)
		}
	}

	return nil
}

// ExportFailedHashes exports failed transaction hashes to a file
func (tf *TxFuzzer) ExportFailedHashes(filename string) error {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()

	if len(tf.failedTxHashes) == 0 {
		return fmt.Errorf("no failed transaction hashes to export")
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}
	defer file.Close()

	for _, hash := range tf.failedTxHashes {
		if _, err := file.WriteString(hash + "\n"); err != nil {
			return fmt.Errorf("failed to write hash to file: %v", err)
		}
	}

	return nil
}

// GetSuccessHashes returns a copy of successful transaction hashes
func (tf *TxFuzzer) GetSuccessHashes() []string {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()

	hashes := make([]string, len(tf.successTxHashes))
	copy(hashes, tf.successTxHashes)
	return hashes
}

// GetFailedHashes returns a copy of failed transaction hashes
func (tf *TxFuzzer) GetFailedHashes() []string {
	tf.hashMutex.RLock()
	defer tf.hashMutex.RUnlock()

	hashes := make([]string, len(tf.failedTxHashes))
	copy(hashes, tf.failedTxHashes)
	return hashes
}

// Close closes the fuzzer and cleans up resources
func (tf *TxFuzzer) Close() error {
	tf.Stop()
	if tf.client != nil {
		tf.client.Close()
	}
	return nil
}
