# D2PFuzz Stress Test Suite

This directory contains configuration files, scripts, and documentation specifically for stress testing.

## Directory Structure

```
stress_test/
├── README.md                      # This document
├── run_stress_test.sh            # Dedicated stress test execution script
├── stress_test_config.yaml       # Standard stress test configuration
├── STRESS_TEST_TUNING_GUIDE.md   # Stress test tuning guide
├── tx_fuzz_example.go            # Stress test example program
└── [Dynamically generated config files]  # Test configurations generated at runtime
```

## Quick Start

### 1. Run Stress Test Script
```bash
# Interactive mode
./stress_test/run_stress_test.sh

# Command line mode
./stress_test/run_stress_test.sh standard    # Standard stress test
./stress_test/run_stress_test.sh extreme     # Extreme stress test
./stress_test/run_stress_test.sh endurance   # Endurance stress test
./stress_test/run_stress_test.sh ramp        # Gradual stress test
```

### 2. Use Configuration File Directly
```bash
# Use standard stress test configuration
./tx_fuzz_example stress_test/stress_test_config.yaml
```

## Test Scenarios

### Standard Stress Test
- **TPS**: 100
- **Duration**: 5 minutes
- **Expected Transactions**: ~30,000 transactions
- **Use Case**: Regular stress testing

### Extreme Stress Test
- **TPS**: 200
- **Duration**: 10 minutes
- **Expected Transactions**: ~120,000 transactions
- **Use Case**: System limit testing

### Endurance Stress Test
- **TPS**: 50
- **Duration**: 30 minutes
- **Expected Transactions**: ~90,000 transactions
- **Use Case**: Long term stability testing

### Gradual Stress Test
- **TPS**: 10 → 100 (Gradual increase)
- **Duration**: 15 minutes
- **Load Mode**: Gradual
- **Use Case**: Performance bottleneck analysis

## System Requirements

### Minimum Requirements
- **CPU**: 4 cores
- **Memory**: 8GB
- **Disk**: 10GB available space
- **Network**: Stable network connection

### Recommended Configuration
- **CPU**: 8 cores or more
- **Memory**: 16GB or more
- **Disk**: SSD, 20GB available space
- **Network**: High speed stable connection

## Security Considerations

⚠️ **Important Warning**:
1. Stress Testing will produce large amounts of network traffic and system load
2. Please run stress tests in a dedicated testing environment to avoid affecting production system
3. Make sure you have enough system resources and network bandwidth
4. Suggest backing up important data before running

## Monitoring and Analysis

### Real-time Monitoring
- Script will show real-time TPS, success rate, etc. statistics
- Can view detailed running status through log files

### Result Analysis
- Test results will be exported to JSON file
- Can use analysis scripts for performance analysis
- See `STRESS_TEST_TUNING_GUIDE.md` for detailed analysis method

## Troubleshooting

### Common Problems
1. **Memory Insufficient**: Reduce TPS or reduce concurrent numbers
2. **Network Timeout**: Check network connection, increase retry count
3. **Gas Insufficient**: Adjust gas_limit and gas_price parameters
4. **Connection Failed**: Check RPC endpoint configuration

### Performance Optimization
- Adjust the system resources according to the resource
- Optimize network configuration
- Adjust the retry strategy
- Refer to tuning guide for detailed configuration

## Related Documents

- [Stress Test Tuning Guide](./STRESS_TEST_TUNING_GUIDE.md)
- [Main Usage Guide](../README.md)
- [Basic Test Configuration](../test/basic_test_config.yaml)

## Technical Support

If you encounter problems, please:
1. View log files
2. Check system resources usage
3. Reference Troubleshooting Guide
4. View related documents