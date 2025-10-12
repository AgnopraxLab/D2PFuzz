package config

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Mode       string           `yaml:"mode"`
	P2P        P2PConfig        `yaml:"p2p"`
	Fuzzing    FuzzingConfig    `yaml:"fuzzing"`
	TxFuzzing  TxFuzzingConfig  `yaml:"tx_fuzz"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Output     OutputConfig     `yaml:"output"`
	Log        LogConfig        `yaml:"log"`
	Paths      PathsConfig      `yaml:"paths"`
	Test       TestConfig       `yaml:"test"`
	Accounts   []Account        `yaml:"accounts"`

	// Transaction defaults - can be configured or use defaults
	ChainIDValue          int64  `yaml:"chain_id"`
	DefaultGasTipCapValue string `yaml:"default_gas_tip_cap"` // in wei, e.g. "3000000000"
	DefaultGasFeeCapValue string `yaml:"default_gas_fee_cap"` // in wei, e.g. "30000000000"

	// Computed fields (initialized from above values)
	ChainID          *big.Int
	DefaultGasTipCap *big.Int
	DefaultGasFeeCap *big.Int
}

type Account struct {
	Address    string `yaml:"address"`     // 公钥地址
	PrivateKey string `yaml:"private_key"` // 私钥（不含0x前缀）
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	Timeout int    `yaml:"timeout"`
}

// P2PConfig holds P2P network configuration
type P2PConfig struct {
	MaxPeers       int      `yaml:"max_peers"`
	ListenPort     int      `yaml:"listen_port"`
	BootstrapNodes []string `yaml:"bootstrap_nodes"`
	JWTSecret      string   `yaml:"jwt_secret"`
	NodeNames      []string `yaml:"node_names"`
}

// FuzzingConfig holds fuzzing-related configuration
type FuzzingConfig struct {
	Enabled       bool     `yaml:"enabled"`
	MaxIterations int      `yaml:"max_iterations"`
	MutationRate  float64  `yaml:"mutation_rate"`
	Seed          int64    `yaml:"seed"`
	Protocols     []string `yaml:"protocols"`
}

// TxFuzzingConfig holds transaction fuzzing configuration
type TxFuzzingConfig struct {
	Enabled         bool   `yaml:"enabled"`
	RPCEndpoint     string `yaml:"rpc_endpoint"`
	ChainID         int64  `yaml:"chain_id"`
	MaxGasPrice     int64  `yaml:"max_gas_price"` // in wei
	MaxGasLimit     uint64 `yaml:"max_gas_limit"`
	TxPerSecond     int    `yaml:"tx_per_second"`
	FuzzDurationSec int    `yaml:"fuzz_duration_sec"`
	Seed            int64  `yaml:"seed"`
	UseAccounts     bool   `yaml:"use_accounts"` // whether to use predefined accounts
}

// TxFuzzerConfig holds transaction fuzzer configuration
type TxFuzzerConfig struct {
	TxPerSecond     int      `yaml:"tx_per_second"`
	FuzzDurationSec int      `yaml:"fuzz_duration_sec"`
	RPCEndpoints    []string `yaml:"rpc_endpoints"`
	// Error handling and retry configuration
	MaxRetries       int           `yaml:"max_retries" json:"maxRetries"`             // Maximum retry attempts
	RetryDelay       time.Duration `yaml:"retry_delay" json:"retryDelay"`             // Delay between retries
	CircuitBreaker   bool          `yaml:"circuit_breaker" json:"circuitBreaker"`     // Enable circuit breaker
	FailureThreshold int           `yaml:"failure_threshold" json:"failureThreshold"` // Circuit breaker failure threshold
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled        bool   `yaml:"enabled"`
	LogLevel       string `yaml:"log_level"`
	MetricsPort    int    `yaml:"metrics_port"`
	ReportInterval int    `yaml:"report_interval"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	Directory string `yaml:"directory"`
	Format    string `yaml:"format"`
	Compress  bool   `yaml:"compress"`
}

// LogConfig holds log configuration
type LogConfig struct {
	Directory      string `yaml:"directory"`
	Template       string `yaml:"template"`
	AutoGenerate   bool   `yaml:"auto_generate"`
	IncludeDetails bool   `yaml:"include_details"`
}

// PathsConfig holds file paths configuration
type PathsConfig struct {
	TxHashes    string `yaml:"tx_hashes"`
	TxHashesExt string `yaml:"tx_hashes_ext"`
}

// TestConfig holds test-related configuration
type TestConfig struct {
	Mode                  string         `yaml:"mode"`
	SingleNodeIndex       int            `yaml:"single_node_index"`
	SingleNodeNonce       string         `yaml:"single_node_nonce"` // "auto" or numeric string
	SingleNodeBatchSize   int            `yaml:"single_node_batch_size"`
	MultiNodeBatchSize    int            `yaml:"multi_node_batch_size"`
	MultiNodeNonces       []string       `yaml:"multi_node_nonces"` // Array of "auto" or numeric strings
	SoftLimitScenarios    []int          `yaml:"soft_limit_scenarios"`
	DefaultTimeoutSeconds int            `yaml:"default_timeout_seconds"`
	GetPooledTxsNodeIndex int            `yaml:"get_pooled_txs_node_index"`
	BlobTest              BlobTestConfig `yaml:"blob_test"`

	// New per-mode sections (backward compatible): if set in YAML, tests will prefer these
	Common          CommonTestConfig            `yaml:"common"`
	SingleNode      SingleNodeTestConfig        `yaml:"single_node"`
	MultiNode       MultiNodeTestConfig         `yaml:"multi_node"`
	SoftLimit       SoftLimitTestModeConfig     `yaml:"soft_limit"`
	SoftLimitSingle SoftLimitSingleModeConfig   `yaml:"soft_limit_single"`
	SoftLimitReport SoftLimitReportModeConfig   `yaml:"soft_limit_report"`
	GetPooledTxs    GetPooledTxsTestConfig      `yaml:"get_pooled_txs"`
	OneTransaction  OneTransactionTestConfig    `yaml:"one_transaction"`
	LargeTxs        LargeTransactionsTestConfig `yaml:"large_transactions"`
	BlobSingle      BlobSingleTestConfig        `yaml:"blob_single"`
	BlobMulti       BlobMultiTestConfig         `yaml:"blob_multi"`
}

// BlobTestConfig holds blob transaction test configuration
type BlobTestConfig struct {
	// Basic configuration
	BlobCount        int    `yaml:"blob_count"`           // Number of blobs per transaction (1-6)
	BlobDataSize     int    `yaml:"blob_data_size"`       // Size of blob data in bytes
	MaxFeePerBlobGas string `yaml:"max_fee_per_blob_gas"` // Max fee per blob gas (in wei)

	// Test scenarios
	Scenarios []string `yaml:"scenarios"` // random, pattern, zero, l2-data

	// Node configuration
	SingleNodeIndex  int   `yaml:"single_node_index"`  // Node index for single-node tests
	MultiNodeIndices []int `yaml:"multi_node_indices"` // Node indices for multi-node tests

	// Nonce configuration for blob tests
	SingleNodeNonce string   `yaml:"single_node_nonce"` // "auto" or numeric string
	MultiNodeNonces []string `yaml:"multi_node_nonces"` // Array of "auto" or numeric strings

	// Account configuration
	FromAccountIndex int `yaml:"from_account_index"` // Index of sender account (default: 0)
	ToAccountIndex   int `yaml:"to_account_index"`   // Index of receiver account (default: 1)

	// Verification configuration
	VerifyBeaconAPI   bool   `yaml:"verify_beacon_api"`   // Whether to verify via Beacon API
	BeaconEndpoint    string `yaml:"beacon_endpoint"`     // Beacon node endpoint
	VerifyAfterBlocks int    `yaml:"verify_after_blocks"` // Wait N blocks before verification

	// Batch test configuration
	BatchSize    int `yaml:"batch_size"`       // Number of transactions per batch
	TotalBlobTxs int `yaml:"total_blob_txs"`   // Total number of blob transactions to send
	SendInterval int `yaml:"send_interval_ms"` // Interval between sends in milliseconds

	// Stress test configuration
	StressTestDuration int  `yaml:"stress_test_duration_sec"` // Duration for stress test in seconds
	MaxConcurrent      int  `yaml:"max_concurrent"`           // Max concurrent blob txs
	FillBlobs          bool `yaml:"fill_blobs"`               // Fill all 6 blobs per tx
}

// CommonTestConfig holds defaults and common knobs
type CommonTestConfig struct {
	TimeoutSeconds         int    `yaml:"timeout_seconds"`
	RetryCount             int    `yaml:"retry_count"`
	DelayBetweenRequestsMS int    `yaml:"delay_between_requests_ms"`
	DefaultGasLimit        uint64 `yaml:"default_gas_limit"`
	DefaultGasTipCap       string `yaml:"default_gas_tip_cap"`
	DefaultGasFeeCap       string `yaml:"default_gas_fee_cap"`
}

// SingleNodeTestConfig contains single-node test overrides
type SingleNodeTestConfig struct {
	NodeIndex          int    `yaml:"node_index"`
	Nonce              string `yaml:"nonce"`
	BatchSize          int    `yaml:"batch_size"`
	AccountStrategy    string `yaml:"account_strategy"` // predefined, random, custom
	FromAccountIndex   int    `yaml:"from_account_index"`
	ToAccountIndex     int    `yaml:"to_account_index"`
	VerifyTransactions bool   `yaml:"verify_transactions"`
	SaveHashes         bool   `yaml:"save_hashes"`
}

// MultiNodeTestConfig contains multi-node test overrides
type MultiNodeTestConfig struct {
	BatchSize          int      `yaml:"batch_size"`
	Nonces             []string `yaml:"nonces"`
	AccountStrategy    string   `yaml:"account_strategy"`
	VerifyTransactions bool     `yaml:"verify_transactions"`
	SaveHashes         bool     `yaml:"save_hashes"`
	ParallelExecution  bool     `yaml:"parallel_execution"`
}

// SoftLimitTestModeConfig configures soft limit (all clients) test
type SoftLimitTestModeConfig struct {
	Scenarios         []int  `yaml:"scenarios"`
	TimeoutMultiplier int    `yaml:"timeout_multiplier"`
	MinTimeoutSeconds int    `yaml:"min_timeout_seconds"`
	MaxTimeoutSeconds int    `yaml:"max_timeout_seconds"`
	TestAllNodes      bool   `yaml:"test_all_nodes"`
	ReportFormat      string `yaml:"report_format"` // detailed, summary, json
}

// SoftLimitSingleModeConfig for single client soft limit
type SoftLimitSingleModeConfig struct {
	NodeIndex      int    `yaml:"node_index"`
	HashCount      int    `yaml:"hash_count"`
	Nonce          string `yaml:"nonce"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	VerifyResponse bool   `yaml:"verify_response"`
}

// SoftLimitReportModeConfig for report generation
type SoftLimitReportModeConfig struct {
	IncludeDetails bool `yaml:"include_details"`
}

// GetPooledTxsTestConfig configures pooled tx query test
type GetPooledTxsTestConfig struct {
	NodeIndex    int    `yaml:"node_index"`
	HashFilePath string `yaml:"hash_file_path"`
	FallbackPath string `yaml:"fallback_file_path"`
	VerifyHashes bool   `yaml:"verify_hashes"`
	PrintResults bool   `yaml:"print_results"`
}

// OneTransactionTestConfig configures single tx test
type OneTransactionTestConfig struct {
	NodeIndex        int    `yaml:"node_index"`
	Nonce            string `yaml:"nonce"`
	FromAccountIndex int    `yaml:"from_account_index"`
	ToAccountIndex   int    `yaml:"to_account_index"`
	ValueWei         string `yaml:"value"`
	VerifyInPool     bool   `yaml:"verify_in_pool"`
	PrintTx          bool   `yaml:"print_transaction"`
}

// LargeTransactionsTestConfig configures large batch tx test
type LargeTransactionsTestConfig struct {
	NodeIndex        int    `yaml:"node_index"`
	TransactionCount int    `yaml:"transaction_count"`
	NonceStart       string `yaml:"nonce_start"` // number or max_uint64
	FromAccountIndex int    `yaml:"from_account_index"`
	ToAccountIndex   int    `yaml:"to_account_index"`
	ValueWei         string `yaml:"value"`
	SaveHashes       bool   `yaml:"save_hashes"`
	BatchSend        bool   `yaml:"batch_send"`
}

// BlobSingleTestConfig configures blob single-node test
type BlobSingleTestConfig struct {
	NodeIndex          int    `yaml:"node_index"`
	Nonce              string `yaml:"nonce"`
	BlobCount          int    `yaml:"blob_count"`
	BlobDataSize       int    `yaml:"blob_data_size"`
	MaxFeePerBlobGas   string `yaml:"max_fee_per_blob_gas"`
	GeneratorType      string `yaml:"generator_type"` // random, pattern, zero, l2-data
	TotalTransactions  int    `yaml:"total_transactions"`
	SendIntervalMS     int    `yaml:"send_interval_ms"`
	VerifyTransactions bool   `yaml:"verify_transactions"`
	SaveHashes         bool   `yaml:"save_hashes"`
	FromAccountIndex   int    `yaml:"from_account_index"` // Index of sender account in accounts array (default: 0)
	ToAccountIndex     int    `yaml:"to_account_index"`   // Index of receiver account in accounts array (default: 1)
}

// BlobMultiTestConfig configures blob multi-node test
type BlobMultiTestConfig struct {
	NodeIndices        []int    `yaml:"node_indices"`
	Nonces             []string `yaml:"nonces"`
	BlobCount          int      `yaml:"blob_count"`
	BlobDataSize       int      `yaml:"blob_data_size"`
	MaxFeePerBlobGas   string   `yaml:"max_fee_per_blob_gas"`
	GeneratorType      string   `yaml:"generator_type"`
	TotalTransactions  int      `yaml:"total_transactions"`
	SendIntervalMS     int      `yaml:"send_interval_ms"`
	ParallelExecution  bool     `yaml:"parallel_execution"`
	VerifyTransactions bool     `yaml:"verify_transactions"`
	SaveHashes         bool     `yaml:"save_hashes"`
}

// LoadConfig loads configuration from the specified YAML file
func LoadConfig(configPath string) (*Config, error) {
	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Initialize transaction defaults from config values or use defaults
	if config.ChainIDValue == 0 {
		config.ChainIDValue = 3151908 // Default chain ID
	}
	config.ChainID = big.NewInt(config.ChainIDValue)

	// Parse gas tip cap (default: 3 Gwei)
	if config.DefaultGasTipCapValue == "" {
		config.DefaultGasTipCap = big.NewInt(3000000000)
	} else {
		gasTipCap, ok := new(big.Int).SetString(config.DefaultGasTipCapValue, 10)
		if !ok {
			return nil, fmt.Errorf("invalid default_gas_tip_cap value: %s", config.DefaultGasTipCapValue)
		}
		config.DefaultGasTipCap = gasTipCap
	}

	// Parse gas fee cap (default: 30 Gwei)
	if config.DefaultGasFeeCapValue == "" {
		config.DefaultGasFeeCap = big.NewInt(30000000000)
	} else {
		gasFeeCap, ok := new(big.Int).SetString(config.DefaultGasFeeCapValue, 10)
		if !ok {
			return nil, fmt.Errorf("invalid default_gas_fee_cap value: %s", config.DefaultGasFeeCapValue)
		}
		config.DefaultGasFeeCap = gasFeeCap
	}

	return &config, nil
}

// GetServerAddress returns the full server address
func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// GetOutputPath returns the full output directory path
func (c *Config) GetOutputPath() string {
	return c.Output.Directory
}

// GetLogPath returns the full log directory path
func (c *Config) GetLogPath() string {
	return c.Log.Directory
}

func (c *Config) GetAccountss() []Account {
	return c.Accounts
}

// IsFuzzingEnabled returns whether fuzzing is enabled
func (c *Config) IsFuzzingEnabled() bool {
	return c.Fuzzing.Enabled
}

// IsMonitoringEnabled returns whether monitoring is enabled
func (c *Config) IsMonitoringEnabled() bool {
	return c.Monitoring.Enabled
}

// GetNodeName returns the node name by index
func (c *Config) GetNodeName(index int) string {
	if index < 0 || index >= len(c.P2P.NodeNames) {
		return ""
	}
	return c.P2P.NodeNames[index]
}

// GetNodeCount returns the number of configured nodes
func (c *Config) GetNodeCount() int {
	return len(c.P2P.BootstrapNodes)
}

// GetTestMode returns the test mode
func (c *Config) GetTestMode() string {
	return c.Test.Mode
}

// IsTxFuzzingEnabled returns true if transaction fuzzing is enabled
func (c *Config) IsTxFuzzingEnabled() bool {
	return c.TxFuzzing.Enabled
}

// GetTxFuzzingConfig returns the transaction fuzzing configuration
func (c *Config) GetTxFuzzingConfig() TxFuzzingConfig {
	return c.TxFuzzing
}

// PrintConfig prints the current configuration (for debugging)
func (c *Config) PrintConfig() {
	fmt.Printf("=== D2PFuzz Configuration ===\n")
	fmt.Printf("Mode: %s\n", c.Mode)
	fmt.Printf("Server: %s:%d\n", c.Server.Host, c.Server.Port)
	fmt.Printf("P2P Max Peers: %d\n", c.P2P.MaxPeers)
	fmt.Printf("P2P Listen Port: %d\n", c.P2P.ListenPort)
	fmt.Printf("Fuzzing Enabled: %t\n", c.Fuzzing.Enabled)
	if c.Fuzzing.Enabled {
		fmt.Printf("  Max Iterations: %d\n", c.Fuzzing.MaxIterations)
		fmt.Printf("  Mutation Rate: %.2f\n", c.Fuzzing.MutationRate)
		fmt.Printf("  Protocols: %v\n", c.Fuzzing.Protocols)
	}
	fmt.Printf("Transaction Fuzzing Enabled: %t\n", c.TxFuzzing.Enabled)
	if c.TxFuzzing.Enabled {
		fmt.Printf("  RPC Endpoint: %s\n", c.TxFuzzing.RPCEndpoint)
		fmt.Printf("  Chain ID: %d\n", c.TxFuzzing.ChainID)
		fmt.Printf("  Max Gas Price: %d wei\n", c.TxFuzzing.MaxGasPrice)
		fmt.Printf("  Tx Per Second: %d\n", c.TxFuzzing.TxPerSecond)
		fmt.Printf("  Duration: %d seconds\n", c.TxFuzzing.FuzzDurationSec)
	}
	fmt.Printf("Monitoring Enabled: %t\n", c.Monitoring.Enabled)
	fmt.Printf("Output Directory: %s\n", c.Output.Directory)
	fmt.Printf("Accounts Count: %d\n", len(c.Accounts))
	fmt.Printf("==============================\n")
}
