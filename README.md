# D2PFuzz

D2PFuzz is a distributed P2P network fuzzing tool for testing and analyzing the security and stability of P2P network protocols.

## Project Structure

```
D2PFuzz/
├── .gitignore          # Git ignore file configuration
├── LICENSE             # Project license
├── README.md           # Project documentation
├── config.yaml         # Main configuration file
├── go.mod              # Go module dependency management
├── main.go             # Program entry point
├── cmd/                # Command-line tools directory
├── config/             # Configuration related modules
├── fuzzer/             # Fuzzing core modules
├── monitor/            # Monitoring modules
├── output/             # Output files directory
├── p2p/                # P2P network protocol modules
├── report/             # Report generation modules
├── reports/            # Test reports storage directory
├── templates/          # Template files directory
└── utils/              # Utility functions modules
```

## Features

- 🔍 **Distributed Fuzzing**: Support multi-node collaborative P2P network testing
- 📊 **Real-time Monitoring**: Provide real-time monitoring and status feedback during testing
- 📋 **Detailed Reports**: Generate detailed test reports and analysis results
- ⚙️ **Flexible Configuration**: Support various configuration options and custom test scenarios
- 🚀 **High Performance**: Optimized concurrent processing and resource management

## Quick Start

### Requirements

- Go 1.19+
- Linux/macOS/Windows

### Installation and Running

```bash
# Clone the project
git clone https://github.com/zhouCode/D2PFuzz.git
cd D2PFuzz

# Install dependencies
go mod tidy

# Run the program
go run main.go
```

### Configuration

Edit the `config.yaml` file to configure test parameters:

```yaml
# Configure your test parameters in config.yaml
```

## Contributing

Welcome to submit Issues and Pull Requests to help improve this project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Version

Current version: v0.3