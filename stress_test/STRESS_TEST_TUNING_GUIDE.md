# D2PFuzz Parameter Tuning Detailed Guide

## Core Parameter Analysis

### 1. TPS (Transactions Per Second) - tx_per_second

**Location**: `config.yaml` -> `tx_fuzz.tx_per_second`

**Influencing Factors**:
- Network latency
- Node processing capability
- Gas price settings
- Account balance

**Tuning Strategy**:

#### Low TPS Scenario (1-10 TPS)
```yaml
tx_per_second: 5
max_retries: 2
retry_delay: 2s
```
- **Use Case**: Functional testing, stability verification
- **Advantages**: Low resource consumption, high success rate
- **Note**: May not discover high concurrency issues

#### Medium TPS Scenario (10-50 TPS)
```yaml
tx_per_second: 25
max_retries: 3
retry_delay: 1s
```
- **Use Case**: Regular performance testing
- **Advantages**: Balance performance and stability
- **Note**: Need to monitor node response time

#### High TPS Scenario (50-100+ TPS)
```yaml
tx_per_second: 100
max_retries: 5
retry_delay: 500ms
```
- **Use Case**: Stress testing, limit testing
- **Advantages**: Discover performance bottlenecks
- **Note**: May cause a large number of failed transactions

### 2. Gas Parameter Optimization

#### Gas Price (max_gas_price)
```yaml
# Test Network - Low Gas Price
max_gas_price: 1000000000   # 1 Gwei

# Standard Setting - Medium Gas Price
max_gas_price: 20000000000  # 20 Gwei

# High Priority - High Gas Price
max_gas_price: 100000000000 # 100 Gwei
```

**Tuning Recommendations**:
- Gas price too low: Transactions may be pending for a long time
- Gas price too high: Consumes too much ETH, but transactions confirm quickly
- Recommend dynamic adjustment based on network congestion

#### Gas Limit (max_gas_limit)
```yaml
# Simple transfer
max_gas_limit: 21000

# Standard transaction
max_gas_limit: 6000000

# Complex contract interaction
max_gas_limit: 10000000
```

### 3. Load Pattern Selection

#### Constant (Constant Mode)
```yaml
load_pattern_type: "constant"
```
- **Characteristics**: Fixed TPS, stable load
- **Use Case**: Stability testing, benchmark testing
- **Configuration**: Simple, no additional parameters needed

#### Ramp (Gradual Increase Mode) - Recommended
```yaml
load_pattern_type: "ramp"
```
- **Characteristics**: Gradually increase from low TPS to target TPS
- **Use Case**: Stress testing, performance boundary detection
- **Advantages**: Can discover performance inflection points

#### Spike (Burst Mode)
```yaml
load_pattern_type: "spike"
```
- **Characteristics**: Suddenly increase to high TPS, then fall back
- **Use Case**: Peak load testing
- **Note**: May cause a large number of failed transactions

#### Wave (Wave Mode)
```yaml
load_pattern_type: "wave"
```
- **Characteristics**: Periodically changing TPS
- **Use Case**: Long term stability testing
- **Advantages**: Simulate real traffic mode

### 4. Retry and Error Handling

#### Conservative Setting (High Stability)
```yaml
max_retries: 2
retry_delay: 3s
circuit_breaker: true
failure_threshold: 3
```

#### Standard Setting (Balanced)
```yaml
max_retries: 3
retry_delay: 1s
circuit_breaker: true
failure_threshold: 5
```

#### Aggressive Setting (High Performance)
```yaml
max_retries: 5
retry_delay: 500ms
circuit_breaker: true
failure_threshold: 10
```

### 5. Test Duration

#### Quick Validation (30-60 seconds)
```yaml
fuzz_duration_sec: 60
```
- **Use Case**: Function validation, quick test
- **Advantages**: Quick feedback
- **Restrictions**: May miss long-term problems

#### Standard Test (5-10 minutes)
```yaml
fuzz_duration_sec: 300
```
- **Use Case**: Performance test, stability testing
- **Advantages**: Sufficient test time
- **Balance**: Time and coverage

#### Long Term Test (30 minutes or more)
```yaml
fuzz_duration_sec: 1800
```
- **Use Case**: Stress testing, durability testing
- **Advantages**: Discover long-term problems
- **Note**: Resource consumption is large

## Performance Tuning Practical

### Scenario 1: Function Validation Testing
**Target**: Validate basic functionality, ensure transactions can be sent and confirmed

```yaml
tx_fuzz:
  tx_per_second: 3
  fuzz_duration_sec: 30
  max_gas_price: 10000000000
  max_gas_limit: 6000000
  load_pattern_type: "constant"
  max_retries: 2
  retry_delay: 2s
```

**Expected Results**: Success rate > 95%

### Scenario 2: Performance Benchmark Testing
**Target**: Establish performance benchmark, understand system's normal processing ability

```yaml
tx_fuzz:
  tx_per_second: 20
  fuzz_duration_sec: 180
  max_gas_price: 20000000000
  max_gas_limit: 8000000
  load_pattern_type: "ramp"
  max_retries: 3
  retry_delay: 1s
```

**Expected Results**: Success rate > 90%, average latency < 5 seconds

### Scenario 3: Stress Limit Testing
**Target**: Find system performance limit, recognize bottlenecks

```yaml
tx_fuzz:
  tx_per_second: 100
  fuzz_duration_sec: 600
  max_gas_price: 50000000000
  max_gas_limit: 10000000
  load_pattern_type: "ramp"
  max_retries: 5
  retry_delay: 500ms
```

**Expected Results**: Find TPS limit, recognize failure mode

### Scenario 4: Stability Testing
**Target**: Validate long-term running stability

```yaml
tx_fuzz:
  tx_per_second: 15
  fuzz_duration_sec: 3600
  max_gas_price: 25000000000
  max_gas_limit: 8000000
  load_pattern_type: "wave"
  max_retries: 3
  retry_delay: 1s
```

**Expected Results**: Long term stable running, no memory leak

## Monitoring and Analysis

### Key Indicators

1. **Success rate** (Success Rate)
   - Target: > 90%
   - Below 90% need adjustment

2. **Average TPS** (Average TPS)
   - Should be close to configured value
   - Significantly below configured value indicates bottleneck

3. **Transaction latency** (Transaction Latency)
   - Normal: < 5 seconds
   - Warning: 5-15 seconds
   - Abnormal: > 15 seconds

4. **Mutation rate** (Mutation Rate)
   - Default: 30%
   - Adjustable range: 10%-50%

### Performance Problem Diagnosis

#### Problem 1: TPS far below configured value
**Possible Reason**:
- Network latency too high
- Node processing capability too low
- Gas price too low

**Solution**:
- Reduce retry delay
- Increase concurrent connections
- Increase Gas price

#### Problem 2: Success rate too low
**Possible Reason**:
- TPS set too high
- Gas parameter not suitable
- Account balance too low

**Solution**:
- Reduce TPS
- Adjust Gas parameter
- Check account balance

#### Problem 3: Memory usage too high
**Possible Reason**:
- Transaction tracking enabled
- Test time too long
- TPS too high

**Solution**:
- Disable transaction tracking
- Shorten test time
- Reduce TPS

## Best Practice

### 1. Progressive Tuning
- Start from low parameter
- Gradually increase load
- Record each test results

### 2. Environment Adaptation
- Test network: conservative parameter
- Local network: can be aggressive
- Production environment: cautious testing

### 3. Resource Monitoring
- Monitor CPU usage
- Monitor memory usage
- Monitor network bandwidth

### 4. Result Analysis
- Save test results
- Compare different configurations
- Establish performance baseline

## Common Configuration Templates

### Development Testing Template
```yaml
tx_per_second: 5
fuzz_duration_sec: 60
max_gas_price: 10000000000
load_pattern_type: "constant"
max_retries: 2
```

### Integration Testing Template
```yaml
tx_per_second: 15
fuzz_duration_sec: 300
max_gas_price: 20000000000
load_pattern_type: "ramp"
max_retries: 3
```

### Stress Testing Template
```yaml
tx_per_second: 50
fuzz_duration_sec: 600
max_gas_price: 50000000000
load_pattern_type: "ramp"
max_retries: 5
```

Through reasonable parameter tuning, can maximize D2PFuzz's test effect, find system's performance bottlenecks and stability problems.