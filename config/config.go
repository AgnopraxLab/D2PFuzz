package config

import (
	"fmt"
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
	Mode                  string   `yaml:"mode"`
	SingleNodeIndex       int      `yaml:"single_node_index"`
	SingleNodeNonce       uint64   `yaml:"single_node_nonce"`
	SingleNodeBatchSize   int      `yaml:"single_node_batch_size"`
	MultiNodeBatchSize    int      `yaml:"multi_node_batch_size"`
	MultiNodeNonces       []uint64 `yaml:"multi_node_nonces"`
	SoftLimitScenarios    []int    `yaml:"soft_limit_scenarios"`
	DefaultTimeoutSeconds int      `yaml:"default_timeout_seconds"`
	GetPooledTxsNodeIndex int      `yaml:"get_pooled_txs_node_index"`
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
