# D2PFuzz Manual Testing Tool

A standalone command-line tool for manual testing of Ethereum P2P nodes.

## Features

- ✅ Single node testing
- ✅ Multi-node testing
- ✅ Soft limit testing
- ✅ GetPooledTransactions testing
- ✅ Interactive mode
- ✅ Configuration-driven
- ✅ Modular architecture

## Quick Start

### 1. Build

```bash
cd cmd/manual
go build -o manual
```

### 2. Configure

Edit `config.yaml` in this directory:

```yaml
test:
  mode: "single"              # Test mode
  single_node_index: 4        # Which node to test
  single_node_batch_size: 1   # Number of transactions
```

### 3. Run

```bash
# Use default config (./config.yaml)
./manual

# Use custom config
./manual -config /path/to/config.yaml

# Override test mode from command line
./manual -mode multi

# List all available test modes
./manual --list

# Show version
./manual --version
```

## Configuration

The `config.yaml` file is **independent** from the root project's `config.yaml`. This allows:

- ✅ Different settings for manual testing vs. automated fuzzing
- ✅ No conflicts with main project configuration
- ✅ Clean separation of concerns
- ✅ Easy to maintain and version control

### Key Configuration Sections

#### P2P Configuration
```yaml
p2p:
  jwt_secret: "..."           # JWT secret for engine API
  node_names: [...]           # Display names for nodes
  bootstrap_nodes: [...]      # Enode addresses
```

#### Test Configuration
```yaml
test:
  mode: "single"                           # Test mode
  single_node_index: 4                     # Node index (0-4)
  single_node_nonce: 1                     # Starting nonce
  single_node_batch_size: 1                # Transactions to send
  multi_node_batch_size: 20                # Transactions per node (multi mode)
  multi_node_nonces: [0, 0, 0, 0, 0]      # Initial nonces per node
```

## Available Test Modes

Run `./manual --list` to see all modes:

- `single` - Single node testing
- `multi` - Multi-node testing
- `test-soft-limit` - Test all clients' soft limit
- `test-soft-limit-single` - Test single client soft limit
- `test-soft-limit-report` - Generate soft limit report
- `GetPooledTxs` - Test GetPooledTransactions
- `oneTransaction` - Send single transaction
- `largeTransactions` - Send large batch
- `interactive` - Interactive selection

## Examples

### Single Node Test
```bash
./manual -mode single -config config.yaml
```

### Multi-Node Test
```bash
./manual -mode multi
```

### Custom Config Path
```bash
./manual -config /path/to/my-config.yaml -mode single
```

## Architecture

This tool uses the refactored modular architecture:

```
D2PFuzz/
├── cmd/manual/           # This tool (standalone)
│   ├── main.go          # Entry point (72 lines)
│   ├── config.yaml      # Independent config
│   └── README.md        # This file
├── ethclient/           # Unified client management
├── account/             # Account management
├── transaction/         # Transaction building
├── testing/             # Test runners
└── utils/               # Utilities
```

## Benefits of Standalone Config

1. **Isolation**: Manual testing config doesn't affect fuzzer config
2. **Simplicity**: Only includes relevant settings for manual tests
3. **Flexibility**: Easy to maintain multiple config profiles
4. **Portability**: Self-contained tool with its own config

## Output

Transaction hashes are saved to the file specified in `paths.tx_hashes` (default: `./txhashes.txt`)

## Version

Current version: `2.0.0-refactored`

Check with: `./manual --version`

