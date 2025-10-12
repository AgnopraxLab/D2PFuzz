# D2PFuzz

D2PFuzz is a fuzzer tool for analyze the Ethernet DevP2P protocol. It is able to generate data corresponding to various sub-protocols including discv4 (e.g., Ping, Pong, etc.), discv5, rlpx, and eth according to the specification of Ethernet network communication protocols. and constructs data sequences according to the chain state and time, and adds mutation functions to them to detect the security of Ethernet network communication protocols.

## Project Structure

```
D2PFuzz/
├── cmd/                # Command-line tools directory
│   ├── livefuzzer/    # Transaction fuzzer tool
│   └── manual/        # Manual testing tool
├── config/             # Configuration modules
├── devp2p/             # P2P network protocol modules
├── fuzzer/             # Fuzzing core modules
├── account/            # Account management
├── ethclient/          # Unified client management
├── transaction/        # Transaction building
├── testing/            # Test runner framework
├── mutation/           # Mutation strategies
├── utils/              # Utility functions
├── logs/               # Log files directory
├── output/             # Reports storage directory
├── scripts/            # Helper scripts
├── stress_test/        # Stress testing directory
├── templates/          # Template config files
├── config.yaml         # Main configuration file
├── constants.go        # Global constants
└── main.go             # Program entry point
```
## Quick Start

```bash
# Clone the project
git clone https://github.com/AgnopraxLab/D2PFuzz.git
cd D2PFuzz

# Install dependencies
go mod tidy
```
### Test Environment

This project utilizes [ethereum-package](https://github.com/ethpandaops/ethereum-package) to initiate the test environment.
This script is used to deploy a local test environment for Ethereum nodes.
```bash
./scripts/run_ethereum_network.sh -c <your_ethereumpackage_config.yaml>
```
For more details, please refer to SCRIPTS_USAGE.md in the `scripts` directory.

### Prepare the configuration file
Using the script from the previous step will result in a file named output.txt.
This file contains the enode values and rpc_urls of all nodes in the local environment.
You need to locate the enode address inside and place it in the YAML configuration file.
You can find the template configuration file in the `template` directory

## run the D2PFuzz
The following are the three main functions of this project

### Manual Test

A command-line tool for testing Ethereum P2P nodes.

#### Features
- Single node testing - Test specific nodes independently
- Multi-node testing - Test all configured nodes simultaneously
- Soft limit testing - Validate NewPooledTransactionHashes soft limit implementation
- GetPooledTransactions testing - Test transaction pool queries

#### Quick Start

**1. Build the tool:**
```bash
cd cmd/manual
go build -o manual
```

**2. Configure (edit `cmd/manual/config.yaml`):**
```yaml
test:
  mode: "single"              # Test mode
  single_node_index: 4        # Which node to test (0-4)
  single_node_batch_size: 1   # Number of transactions
```

**3. Run tests:**
```bash
# Use default config
./manual

# Specify custom config
./manual -config /path/to/config.yaml

# Override test mode from command line
./manual -mode multi

# List all available test modes
./manual --list

# Show version
./manual --version
```

#### Available Test Modes

| Mode | Description |
|------|-------------|
| `single` | Test a single specific node |
| `multi` | Test all configured nodes |
| `test-soft-limit` | Test soft limit for all clients |
| `test-soft-limit-single` | Test soft limit for one client |
| `test-soft-limit-report` | Generate soft limit test report |
| `GetPooledTxs` | Test GetPooledTransactions protocol |
| `oneTransaction` | Send a single transaction |
| `largeTransactions` | Send large batch of transactions |

#### Configuration

The manual tool uses its own `config.yaml` in `cmd/manual/` directory, independent from the root project configuration:

```yaml
# P2P Configuration
p2p:
  jwt_secret: "..."
  node_names:
    - "geth-lighthouse"
    - "netherhmind-teku"
    - "besu-prysm"
    - "besu-lodestar"
    - "geth-nimbus"
  bootstrap_nodes: [...]

# Test Configuration
test:
  mode: "single"
  single_node_index: 4
  single_node_nonce: 1
  single_node_batch_size: 1
  multi_node_batch_size: 20
  multi_node_nonces: [0, 0, 0, 0, 0]
  soft_limit_scenarios: [4096, 5000, 8192]
```

#### Example Usage

**Single Node Test:**
```bash
cd cmd/manual
./manual -mode single
# Tests node 4 (configured in config.yaml) with 1 transaction
```

**Multi-Node Test:**
```bash
./manual -mode multi
# Tests all 5 configured nodes with 20 transactions each
```

**Soft Limit Testing:**
```bash
./manual -mode test-soft-limit-report
# Generates comprehensive soft limit test report for all clients
```

**Custom Configuration:**
```bash
./manual -config my-test-config.yaml -mode single
# Use custom config file
```

### stress test
```bash
cd stress_test
./run_stress_test.sh
```

### tx-fuzz
```bash
cd cmd
./livefuzzer spam --seed <seed> --sk <private_key> -rpc <rpc_url>
```
Replace `<seed>` with a random number to ensure the reproducibility of the test results.
Replace `<private_key>` with the private key of the account you want to use for fuzzing.
Replace `<rpc_url>` with the RPC URL of the node you want to connect to.

You can view more details through [tx-fuzz](https://github.com/MariusVanDerWijden/tx-fuzz/blob/master/README.md).


## Core Configuration Parameters

### Transaction Fuzzing Configuration (tx_fuzz)

#### Basic Parameters

- **enabled**: `true/false` - Whether to enable transaction fuzzing
- **chain_id**: `3151908` - Blockchain network ID
- **tx_per_second**: `10` - **TPS Setting** - Number of transactions sent per second
- **fuzz_duration_sec**: `60` - Fuzzing duration in seconds
- **seed**: `0` - Random seed (0 means use random seed)
- **use_accounts**: `true` - Whether to use predefined accounts

#### Gas Related Parameters

- **max_gas_price**: `20000000000` - Maximum gas price (in wei, 20 Gwei)
- **max_gas_limit**: `8000000` - Maximum gas limit

#### Multi-node Configuration

- **rpc_endpoints**: RPC node list
  ```yaml
  rpc_endpoints:
    - "http://172.16.0.11:8545"
    - "http://172.16.0.12:8545"
    - "http://172.16.0.13:8545"
    - "http://172.16.0.14:8545"
    - "http://172.16.0.15:8545"
  ```

#### Error Handling and Retry

- **max_retries**: `3` - Maximum number of retries
- **retry_delay**: `1s` - Retry interval time
- **circuit_breaker**: `true` - Whether to enable circuit breaker
- **failure_threshold**: `5` - Circuit breaker failure threshold

#### Load Pattern

- **load_pattern_type**: Load pattern type
  - `"constant"` - Constant TPS
  - `"ramp"` - Gradual increase mode (recommended)
  - `"spike"` - Burst mode
  - `"wave"` - Wave mode

## Key Parameter Tuning Guide

### 1. TPS (Transactions Per Second) Tuning

**Parameter Location**: `config.yaml` -> `tx_fuzz.tx_per_second`

```yaml
tx_fuzz:
  tx_per_second: 10  # Modify this value
```

**Recommended Settings**:
- **Test Environment**: 5-20 TPS
- **Stress Testing**: 50-100 TPS
- **Extreme Testing**: 100+ TPS

**Notes**:
- High TPS may cause node overload
- Recommend starting with low TPS and gradually increasing
- Monitor node response time and success rate

### 2. Test Duration

**Parameter Location**: `config.yaml` -> `tx_fuzz.fuzz_duration_sec`

```yaml
tx_fuzz:
  fuzz_duration_sec: 60  # 60 seconds, adjust as needed
```

**Recommended Settings**:
- **Quick Test**: 30-60 seconds
- **Standard Test**: 300-600 seconds (5-10 minutes)
- **Long Test**: 3600 seconds above (1 hour+))

### 3. Gas Parameter Optimization

```yaml
tx_fuzz:
  max_gas_price: 20000000000  # 20 Gwei
  max_gas_limit: 8000000      # 8M gas
```

**Gas Price Recommendations**:
- **Testnet**: 1-20 Gwei
- **Mainnet Simulation**: 20-100 Gwei
- **High Priority**: 100+ Gwei

### 4. Load Pattern Selection

```yaml
tx_fuzz:
  load_pattern_type: "ramp"  # Recommended to use gradual increase mode
```

**Pattern Description**:
- **constant**: Fixed TPS, suitable for stability testing
- **ramp**: Gradually increase from low TPS to target TPS, suitable for stress testing
- **spike**: Burst high TPS, suitable for peak testing
- **wave**: Periodic changes, suitable for long-term stability testing

## Advanced Configuration

### 1. Multi-node Load Balancing

Automatically configured load distribution in code:

```go
LoadDistribution: map[string]float64{
    "http://172.16.0.11:8545": 0.2,  // 20%
    "http://172.16.0.12:8545": 0.2,  // 20%
    "http://172.16.0.13:8545": 0.2,  // 20%
    "http://172.16.0.14:8545": 0.2,  // 20%
    "http://172.16.0.15:8545": 0.2,  // 20%
}
```

### 2. Mutation Testing Configuration

```go
fuzzConfig := &fuzzer.TxFuzzConfig{
    UseMutation:     true,   // Enable mutation
    MutationRatio:   0.3,    // 30% of transactions use mutation
    EnableTracking:  true,   // Enable transaction tracking
    ConfirmBlocks:   3,      // Wait for 3 confirmation blocks
}
```

### 3. System Monitoring

```go
EnableMetrics:   true,                    // Enable system metrics
MetricsInterval: 10 * time.Second,        // Metrics collection interval
```

## Output File Description

The following files will be generated after running:

1. **output/tx_fuzz_results.json** - Detailed transaction records and statistics
2. **output/success_tx_hashes.txt** - List of successful transaction hashes
3. **output/failed_tx_hashes.txt** - List of failed transaction hashes

## Real-time Monitoring

Real-time statistics will be displayed during execution:

```
--- Stats (Runtime: 30s) ---
Total Sent: 150 | Mined: 145 | Failed: 3 | Pending: 2
Mutation Used: 45 | Random Used: 105
Success Rate: 96.7% | Mutation Rate: 30.0%
```

## Common Issues and Solutions

### 1. Connection Failure

**Issue**: `connection refused` error
**Solution**: Check if RPC endpoints are accessible, confirm nodes are running

### 2. Insufficient Gas

**Issue**: `insufficient funds for gas` error
**Solution**: 
- Lower `max_gas_price` or `max_gas_limit`
- Ensure accounts have sufficient ETH balance

### 3. Low TPS

**Issue**: Actual TPS is much lower than configured value
**Solution**:
- Check network latency
- Lower `max_retries` and `retry_delay`
- Increase concurrent connections

### 4. Memory Usage

**Issue**: Program occupies memory
**Solution**:
- Lower `fuzz_duration_sec`
- Disable `EnableTracking`
- Reduce `tx_per_second`

## Performance Optimization

### 1. Network Optimization
- Use local or low latency RPC nodes
- Enable multi-node load balancing
- Reasonably set retry parameters

### 2. Resource Optimization
- Adjust TPS according to system resources
- Monitor CPU and memory usage
- Appropriate adjustment of concurrent connections

### 3. Test Strategy
- Start from small-scale testing
- Gradually increase the load
- Record and analyze test results

## Example Configuration

### Lightweight Test Configuration
```yaml
tx_fuzz:
  tx_per_second: 5
  fuzz_duration_sec: 30
  max_gas_price: 10000000000  # 10 Gwei
  load_pattern_type: "constant"
```

### Stress Test Configuration
```yaml
tx_fuzz:
  tx_per_second: 50
  fuzz_duration_sec: 300
  max_gas_price: 50000000000  # 50 Gwei
  load_pattern_type: "ramp"
```

### Extreme Test Configuration
```yaml
tx_fuzz:
  tx_per_second: 100
  fuzz_duration_sec: 600
  max_gas_price: 100000000000  # 100 Gwei
  load_pattern_type: "spike"
```

## Summary

D2PFuzz provides rich configuration options and advanced features. Through reasonable configuration, it can meet the testing needs of different scenarios. It is recommended to start with basic configuration and gradually optimize parameters based on test results to achieve the best testing results.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Version

Current version: v0.3

Tip: For fully tested versions of the past, see branches archive-v0.1 and v0.2