# D2PFuzz

D2PFuzz is a fuzzer tool for analyze the Ethernet DevP2P protocol. It is able to generate data corresponding to various sub-protocols including discv4 (e.g., Ping, Pong, etc.), discv5, rlpx, and eth according to the specification of Ethernet network communication protocols. and constructs data sequences according to the chain state and time, and adds mutation functions to them to detect the security of Ethernet network communication protocols.

## Project Structure

```
D2PFuzz/
├── analysis/           # Result analysis
├── cmd/                # Command-line tools directory
├── config/             # Configuration related modules
├── fuzzer/             # Fuzzing core modules
├── logs/               # Log files directory
├── monitor/            # Monitoring modules
├── mutation/           # Mutation Strategy
├── outputs/            # Reports storage directory
├── p2p/                # P2P network protocol modules
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

### Configuration

Edit the `config.yaml` file to configure test parameters:

```yaml
# Configure your test parameters in config.yaml
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Version

Current version: v0.3

Tip: For fully tested versions of the past, see branches archive-v0.1 and v0.2