# D2PFuzz

D2PFuzz is a fuzzer tool for analyze the Ethernet DevP2P protocol. It is able to generate data corresponding to various sub-protocols including discv4 (e.g., Ping, Pong, etc.), discv5, rlpx, and eth according to the specification of Ethernet network communication protocols. and constructs data sequences according to the chain state and time, and adds mutation functions to them to detect the security of Ethernet network communication protocols.

## Project Structure

```
D2PFuzz/
├── analysis/           # Result analysis
├── cmd/                # Command-line tools directory
├── config/             # Configuration related modules
├── devp2p/             # P2P network protocol modules
├── examples/           # Run tx-fuzz alone
├── fuzzer/             # Fuzzing core modules
├── logs/               # Log files directory
├── monitor/            # Monitoring modules
├── mutation/           # Mutation Strategy
├── output/             # Reports storage directory
├── templates/          # Template config files directory
├── test/               # Test cases directory
├── utils/              # Utility functions modules
├── config.yaml         # Main configuration file
└── main.go             # Program entry point
```

## Quick Start

### Requirements

- Go 1.19+
- Linux/macOS/Windows
- Ethereum node (for transaction fuzzing)

### Installation and Running

```bash
# Clone the project
git clone https://github.com/AgnopraxLab/D2PFuzz.git
cd D2PFuzz

# Install dependencies
go mod tidy

# Run the program
go run main.go

# Run test
go run test/real_connection/main.go
```

## TX-Fuzz Integration

D2PFuzz integrates the [tx-fuzz](https://github.com/MariusVanDerWijden/tx-fuzz) library to provide Ethereum transaction fuzzing functionality. It supports random generation of multiple transaction types, configurable gas parameters and transaction frequency, and provides real-time monitoring.

### Usage

```
cd cmd/livefuzzer
```

Run an execution layer client such as [Geth][1] locally in a standalone bash window.
Tx-fuzz sends transactions to port `8545` by default.
```
geth --http --http.port 8545
```

Or you can create your private testnet by using [ethereum-package][https://github.com/ethpandaops/ethereum-package].

if you use ethereum-package to create your private testnet, you can use the following command to start tx-fuzz:

```
./livefuzzer spam --seed 1234 --sk 04b9f63ecf84210c5366c66d68fa1f5da1fa4f634fad6dfc86178e4d79ff9e59 -rpc http://172.16.0.11:8545
```
Which means tx-fuzz will send transactions to the private testnet node `http://172.16.0.11:8545` with the private key `04b9f63ecf84210c5366c66d68fa1f5da1fa4f634fad6dfc86178e4d79ff9e59`.

### Configuration

Edit the `config.yaml` file to configure test parameters:

```yaml
# Configure your test parameters in config.yaml
```

## 📚 Documentation Navigation

### Core Documentation
- **[Usage Guide](USAGE_GUIDE.md)** - Detailed configuration and usage instructions
- **[Stress Test Suite](stress_test/README.md)** - Professional stress testing tools and configurations

### Professional Tools Documentation
- **[Scripts Usage Guide](scripts/SCRIPTS_USAGE_GUIDE.md)** - Network deployment, transaction query and other script tools
- **[P2P Test Data Generation](devp2p/getchain/README_testdata_generation.md)** - Ethereum P2P protocol test data generation guide

### Tuning Guides
- **[Stress Test Tuning](stress_test/STRESS_TEST_TUNING_GUIDE.md)** - Detailed parameter tuning and performance optimization guide

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Version

Current version: v0.3

Tip: For fully tested versions of the past, see branches archive-v0.1 and v0.2