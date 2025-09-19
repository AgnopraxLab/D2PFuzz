# D2PFuzz Transaction Fuzzing Usage Guide

## Overview

D2PFuzz is an Ethereum transaction fuzzing tool that supports advanced features such as multi-node load balancing, failover, and load pattern control. This guide provides detailed instructions on how to use and configure the tool.

## Quick Start

### 1. Basic Execution

```bash
# Run in the project root directory
cd /D2PFuzz
./tx_fuzz_example
```

### 2. Specify Configuration File

```bash
# Use custom configuration file
./tx_fuzz_example /path/to/your/config.yaml
```

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