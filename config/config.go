package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Mode       string           `yaml:"mode"`
	P2P        P2PConfig        `yaml:"p2p"`
	Fuzzing    FuzzingConfig    `yaml:"fuzzing"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Output     OutputConfig     `yaml:"output"`
	Report     ReportConfig     `yaml:"report"`
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
}

// FuzzingConfig holds fuzzing-related configuration
type FuzzingConfig struct {
	Enabled       bool     `yaml:"enabled"`
	MaxIterations int      `yaml:"max_iterations"`
	MutationRate  float64  `yaml:"mutation_rate"`
	Seed          int64    `yaml:"seed"`
	Protocols     []string `yaml:"protocols"`
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

// ReportConfig holds report generation configuration
type ReportConfig struct {
	Directory      string `yaml:"directory"`
	Template       string `yaml:"template"`
	AutoGenerate   bool   `yaml:"auto_generate"`
	IncludeDetails bool   `yaml:"include_details"`
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

// GetReportPath returns the full report directory path
func (c *Config) GetReportPath() string {
	return c.Report.Directory
}

// IsFuzzingEnabled returns whether fuzzing is enabled
func (c *Config) IsFuzzingEnabled() bool {
	return c.Fuzzing.Enabled
}

// IsMonitoringEnabled returns whether monitoring is enabled
func (c *Config) IsMonitoringEnabled() bool {
	return c.Monitoring.Enabled
}

// PrintConfig prints the current configuration (for debugging)
func (c *Config) PrintConfig() {
	fmt.Println("=== D2PFuzz Configuration ===")
	fmt.Printf("Server: %s\n", c.GetServerAddress())
	fmt.Printf("P2P Listen Port: %d\n", c.P2P.ListenPort)
	fmt.Printf("Max Peers: %d\n", c.P2P.MaxPeers)
	fmt.Printf("Fuzzing Enabled: %t\n", c.IsFuzzingEnabled())
	fmt.Printf("Max Iterations: %d\n", c.Fuzzing.MaxIterations)
	fmt.Printf("Protocols: %v\n", c.Fuzzing.Protocols)
	fmt.Printf("Output Directory: %s\n", c.GetOutputPath())
	fmt.Printf("Report Directory: %s\n", c.GetReportPath())
	fmt.Printf("Monitoring Enabled: %t\n", c.IsMonitoringEnabled())
	fmt.Println("==============================")
}