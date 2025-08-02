package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadConfig tests loading configuration from file
func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test_config.yaml")

	// Write test configuration
	configContent := `
server:
  host: "localhost"
  port: 8080
  timeout: 30

mode: "fuzzing"

p2p:
  max_peers: 25
  listen_port: 30304
  bootstrap_nodes:
    - "enode://test1@127.0.0.1:30303"
    - "enode://test2@127.0.0.1:30304"

fuzzing:
  enabled: true
  max_iterations: 1000
  mutation_rate: 0.1
  seed: 12345
  protocols:
    - "eth"
    - "snap"

monitoring:
  enabled: true
  log_level: "debug"
  metrics_port: 9090
  report_interval: 60

output:
  directory: "/tmp/fuzz_output"
  format: "json"
  compress: true

log:
  directory: "/tmp/fuzz_reports"
  template: "report_template.html"
  auto_generate: true
  include_details: true
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the configuration
	config, err := LoadConfig(configFile)

	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify Server configuration
	assert.Equal(t, "localhost", config.Server.Host)
	assert.Equal(t, 8080, config.Server.Port)
	assert.Equal(t, 30, config.Server.Timeout)

	// Verify Mode
	assert.Equal(t, "fuzzing", config.Mode)

	// Verify P2P configuration
	assert.Equal(t, 25, config.P2P.MaxPeers)
	assert.Equal(t, 30304, config.P2P.ListenPort)
	assert.Len(t, config.P2P.BootstrapNodes, 2)
	assert.Equal(t, "enode://test1@127.0.0.1:30303", config.P2P.BootstrapNodes[0])
	assert.Equal(t, "enode://test2@127.0.0.1:30304", config.P2P.BootstrapNodes[1])

	// Verify Fuzzing configuration
	assert.True(t, config.Fuzzing.Enabled)
	assert.Equal(t, 1000, config.Fuzzing.MaxIterations)
	assert.Equal(t, 0.1, config.Fuzzing.MutationRate)
	assert.Equal(t, int64(12345), config.Fuzzing.Seed)
	assert.Len(t, config.Fuzzing.Protocols, 2)
	assert.Contains(t, config.Fuzzing.Protocols, "eth")
	assert.Contains(t, config.Fuzzing.Protocols, "snap")

	// Verify Monitoring configuration
	assert.True(t, config.Monitoring.Enabled)
	assert.Equal(t, "debug", config.Monitoring.LogLevel)
	assert.Equal(t, 9090, config.Monitoring.MetricsPort)
	assert.Equal(t, 60, config.Monitoring.ReportInterval)

	// Verify Output configuration
	assert.Equal(t, "/tmp/fuzz_output", config.Output.Directory)
	assert.Equal(t, "json", config.Output.Format)
	assert.True(t, config.Output.Compress)

	// Verify Log configuration
	assert.Equal(t, "/tmp/fuzz_reports", config.Log.Directory)
	assert.Equal(t, "report_template.html", config.Log.Template)
	assert.True(t, config.Log.AutoGenerate)
	assert.True(t, config.Log.IncludeDetails)
}

// TestLoadConfig_NonExistentFile tests loading config from non-existent file
func TestLoadConfig_NonExistentFile(t *testing.T) {
	config, err := LoadConfig("/non/existent/config.yaml")

	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestLoadConfig_InvalidYAML tests loading config with invalid YAML
func TestLoadConfig_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "invalid_config.yaml")

	// Write invalid YAML
	invalidYAML := `
p2p:
  max_peers: 25
  listen_port: 30304
    invalid_indentation: true
fuzzing:
  enabled: [invalid yaml structure
`

	err := os.WriteFile(configFile, []byte(invalidYAML), 0644)
	require.NoError(t, err)

	config, err := LoadConfig(configFile)

	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestLoadConfig_PartialConfig tests loading config with missing sections
func TestLoadConfig_PartialConfig(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "partial_config.yaml")

	// Write partial configuration (only P2P section)
	partialConfig := `
p2p:
  max_peers: 15
  listen_port: 30305
  bootstrap_nodes:
    - "enode://test@127.0.0.1:30303"
`

	err := os.WriteFile(configFile, []byte(partialConfig), 0644)
	require.NoError(t, err)

	config, err := LoadConfig(configFile)

	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify P2P configuration is loaded
	assert.Equal(t, 15, config.P2P.MaxPeers)
	assert.Equal(t, 30305, config.P2P.ListenPort)
	assert.Len(t, config.P2P.BootstrapNodes, 1)

	// Verify missing sections have zero values
	assert.False(t, config.Fuzzing.Enabled)
	assert.Equal(t, 0, config.Fuzzing.MaxIterations)
	assert.Empty(t, config.Fuzzing.Protocols)
	assert.Empty(t, config.Output.Directory)
	assert.Empty(t, config.Log.Directory)
}

// TestConfig_DefaultValues tests default configuration values
func TestConfig_DefaultValues(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "empty_config.yaml")

	// Write empty configuration
	err := os.WriteFile(configFile, []byte(""), 0644)
	require.NoError(t, err)

	config, err := LoadConfig(configFile)

	assert.NoError(t, err)
	assert.NotNil(t, config)

	// All values should be zero/empty (Go's default values)
	assert.Equal(t, 0, config.P2P.MaxPeers)
	assert.Equal(t, 0, config.P2P.ListenPort)
	assert.Empty(t, config.P2P.BootstrapNodes)
	assert.False(t, config.Fuzzing.Enabled)
	assert.Equal(t, 0, config.Fuzzing.MaxIterations)
	assert.Empty(t, config.Fuzzing.Protocols)
	assert.Empty(t, config.Output.Directory)
	assert.Empty(t, config.Log.Directory)
	assert.Empty(t, config.Server.Host)
	assert.Equal(t, 0, config.Server.Port)
}

// TestServerConfig_Structure tests Server configuration structure
func TestServerConfig_Structure(t *testing.T) {
	serverConfig := &ServerConfig{
		Host:    "192.168.1.100",
		Port:    8080,
		Timeout: 60,
	}

	assert.Equal(t, "192.168.1.100", serverConfig.Host)
	assert.Equal(t, 8080, serverConfig.Port)
	assert.Equal(t, 60, serverConfig.Timeout)
}

// TestP2PConfig_Structure tests P2P configuration structure
func TestP2PConfig_Structure(t *testing.T) {
	p2pConfig := &P2PConfig{
		MaxPeers:   50,
		ListenPort: 30303,
		BootstrapNodes: []string{
			"enode://node1@192.168.1.1:30303",
			"enode://node2@192.168.1.2:30303",
			"enode://node3@192.168.1.3:30303",
		},
	}

	assert.Equal(t, 50, p2pConfig.MaxPeers)
	assert.Equal(t, 30303, p2pConfig.ListenPort)
	assert.Len(t, p2pConfig.BootstrapNodes, 3)
	assert.Equal(t, "enode://node1@192.168.1.1:30303", p2pConfig.BootstrapNodes[0])
	assert.Equal(t, "enode://node2@192.168.1.2:30303", p2pConfig.BootstrapNodes[1])
	assert.Equal(t, "enode://node3@192.168.1.3:30303", p2pConfig.BootstrapNodes[2])
}

// TestFuzzingConfig_Structure tests Fuzzing configuration structure
func TestFuzzingConfig_Structure(t *testing.T) {
	fuzzingConfig := &FuzzingConfig{
		Enabled:       true,
		MaxIterations: 5000,
		MutationRate:  0.2,
		Seed:          98765,
		Protocols: []string{
			"eth",
			"snap",
			"les",
		},
	}

	assert.True(t, fuzzingConfig.Enabled)
	assert.Equal(t, 5000, fuzzingConfig.MaxIterations)
	assert.Equal(t, 0.2, fuzzingConfig.MutationRate)
	assert.Equal(t, int64(98765), fuzzingConfig.Seed)
	assert.Len(t, fuzzingConfig.Protocols, 3)
	assert.Contains(t, fuzzingConfig.Protocols, "eth")
	assert.Contains(t, fuzzingConfig.Protocols, "snap")
	assert.Contains(t, fuzzingConfig.Protocols, "les")
}

// TestMonitoringConfig_Structure tests Monitoring configuration structure
func TestMonitoringConfig_Structure(t *testing.T) {
	monitoringConfig := &MonitoringConfig{
		Enabled:        true,
		LogLevel:       "info",
		MetricsPort:    9090,
		ReportInterval: 120,
	}

	assert.True(t, monitoringConfig.Enabled)
	assert.Equal(t, "info", monitoringConfig.LogLevel)
	assert.Equal(t, 9090, monitoringConfig.MetricsPort)
	assert.Equal(t, 120, monitoringConfig.ReportInterval)
}

// TestOutputConfig_Structure tests Output configuration structure
func TestOutputConfig_Structure(t *testing.T) {
	outputConfig := &OutputConfig{
		Directory: "/var/log/d2pfuzz/output",
		Format:    "xml",
		Compress:  false,
	}

	assert.Equal(t, "/var/log/d2pfuzz/output", outputConfig.Directory)
	assert.Equal(t, "xml", outputConfig.Format)
	assert.False(t, outputConfig.Compress)
}

// TestLogConfig_Structure tests Log configuration structure
func TestLogConfig_Structure(t *testing.T) {
	logConfig := &LogConfig{
		Directory:      "/var/log/d2pfuzz/reports",
		Template:       "custom_template.html",
		AutoGenerate:   false,
		IncludeDetails: false,
	}

	assert.Equal(t, "/var/log/d2pfuzz/reports", logConfig.Directory)
	assert.Equal(t, "custom_template.html", logConfig.Template)
	assert.False(t, logConfig.AutoGenerate)
	assert.False(t, logConfig.IncludeDetails)
}

// TestConfig_HelperMethods tests the helper methods of Config
func TestConfig_HelperMethods(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Fuzzing: FuzzingConfig{
			Enabled: true,
		},
		Monitoring: MonitoringConfig{
			Enabled: true,
		},
		Output: OutputConfig{
			Directory: "/tmp/output",
		},
		Log: LogConfig{
			Directory: "/tmp/logs",
		},
	}

	// Test helper methods
	assert.Equal(t, "localhost:8080", config.GetServerAddress())
	assert.Equal(t, "/tmp/output", config.GetOutputPath())
	assert.Equal(t, "/tmp/logs", config.GetLogPath())
	assert.True(t, config.IsFuzzingEnabled())
	assert.True(t, config.IsMonitoringEnabled())
}

// BenchmarkLoadConfig benchmarks loading configuration
func BenchmarkLoadConfig(b *testing.B) {
	tempDir := b.TempDir()
	configFile := filepath.Join(tempDir, "bench_config.yaml")

	// Write benchmark configuration
	configContent := `
server:
  host: "localhost"
  port: 8080

p2p:
  max_peers: 25
  listen_port: 30304
  bootstrap_nodes:
    - "enode://test1@127.0.0.1:30303"
    - "enode://test2@127.0.0.1:30304"

fuzzing:
  enabled: true
  max_iterations: 1000
  protocols:
    - "eth"
    - "snap"

output:
  directory: "/tmp/fuzz_output"

log:
  directory: "/tmp/fuzz_reports"
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadConfig(configFile)
		if err != nil {
			b.Fatal(err)
		}
	}
}