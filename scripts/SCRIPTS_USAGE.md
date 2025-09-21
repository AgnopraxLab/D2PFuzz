# SCRIPTS_USAGE

This document explains the usage of all scripts under this directory.

## Network Deployment Scripts

### Local test environment deployment script

```bash
./run_ethereum_network.sh -c <your_ethereumpackage_config.yaml>
```
This script is used to deploy a local test environment for Ethereum nodes.
**Special note:** This script needs to be placed in the root directory of the [ethereum-package](https://github.com/ethpandaops/ethereum-package) repository to run and you can use the configuration file which can launch 5 different execution clients and includes a visualization page.

**Options:**
- `-c, --config FILE`: Specify YAML configuration file (default: config.yaml)
- `-h, --help`: Show help message

**Example configuration:**
```yaml
participants:
  - el_type: geth
    cl_type: lighthouse
  - el_type: nethermind
    cl_type: lighthouse
  - el_type: reth
    cl_type: lighthouse
  - el_type: erigon
    cl_type: lighthouse
  - el_type: besu
    cl_type: lighthouse
additional_services:
  - dora
ethereum_genesis_generator_params:
  image: ethpandaops/ethereum-genesis-generator:5.0.5
```

## Transaction Query Scripts

### Transaction Query Tool

```bash
./query_tx.sh <tx_hash1> [tx_hash2] [tx_hash3] ...
./query_tx.sh -f <filename>
```

This script queries the status of Ethereum transactions across multiple client nodes. It supports querying individual transaction hashes or reading multiple hashes from a file.

**Options:**
- `-f <filename>`: Read transaction hashes from file
- `-h, --help`: Show help message

**Transaction Status Categories:**
- ✓ Confirmed - Transaction successfully mined and confirmed
- ⏳ Pending - Transaction in mempool, ready for mining
- ⏸️ Queued - Transaction in mempool, waiting for conditions
- ✗ Failed - Transaction mined but execution failed
- ❌ Not Found - Transaction hash not found

**Examples:**
```bash
./query_tx.sh 0x1234567890abcdef...
./query_tx.sh -f sample_tx_hashes.txt
```

### Transaction Tracing Tool

```bash
./trace_tx.sh [options] <transaction_hash>
```

This script provides detailed tracing of Ethereum transactions using various tracer types across different client nodes.

**Options:**
- `-t, --tracer <type>`: Tracer type (default: callTracer)
  - Available: callTracer, prestateTracer, 4byteTracer, opcodeLogger
- `-n, --node <node>`: Specify node type (default: geth)
  - Available: geth, nethermind, reth, erigon, besu
- `-e, --endpoint <URL>`: Custom RPC endpoint
- `-o, --output <file>`: Output results to file
- `-p, --pretty`: Pretty print JSON output
- `-h, --help`: Show help message

**Tracer Types:**
- `callTracer`: Trace all contract calls (recommended)
- `prestateTracer`: Trace state changes
- `4byteTracer`: Trace function call statistics
- `opcodeLogger`: Detailed opcode logs

**Examples:**
```bash
./trace_tx.sh 0x1234...
./trace_tx.sh -t prestateTracer 0x1234...
./trace_tx.sh -n reth -t callTracer 0x1234...
./trace_tx.sh -o trace_result.json 0x1234...
```

### Transaction Detail Query Tool

```bash
./tx_detail_query.sh [options]
```

This script provides detailed transaction information and analysis capabilities.

**Examples:**
```bash
./tx_detail_query.sh
```

## Network Monitoring Scripts

### Network Status Query Tool

```bash
./network_status.sh [options]
```

This script queries the status of Ethereum network nodes, including gas prices, fee history, peer count, and synchronization status.

**Options:**
- `-n, --node <node>`: Specify node type (default: geth)
  - Available: geth, nethermind, reth, erigon, besu
- `-e, --endpoint <URL>`: Custom RPC endpoint
- `-a, --all`: Query status of all nodes
- `-o, --output <file>`: Output results to file
- `-j, --json`: Output in JSON format
- `-h, --help`: Show help message

**Query Information:**
- eth_gasPrice: Current gas price
- eth_feeHistory: Fee history
- eth_maxPriorityFeePerGas: Maximum priority fee
- net_peerCount: Number of connected peers
- eth_syncing: Synchronization status

**Examples:**
```bash
./network_status.sh                    # Query default geth node
./network_status.sh -n reth            # Query reth node
./network_status.sh -a                 # Query all nodes
./network_status.sh -j -o status.json  # JSON output to file
```

### Mempool Query Tool

```bash
./query_mempool.sh [options]
```

This script queries pending transactions in the Ethereum network mempool across different client nodes.

**Examples:**
```bash
./query_mempool.sh
```

### Filtered Mempool Query Tool

```bash
./query_mempool_filtered.sh [options]
```

This script provides filtered queries of mempool transactions with specific criteria.

**Examples:**
```bash
./query_mempool_filtered.sh
```

## Account and Analysis Scripts

### Account Transaction Query Tool

```bash
./query_account_transactions.sh [options]
```

This script queries transaction history for specific Ethereum accounts.

**Examples:**
```bash
./query_account_transactions.sh
```

### Prefunded Account Nonce Checker

```bash
./check_prefunded_nonces.sh
```

This script checks the nonce values and balances of prefunded accounts in the test network. It queries 21 predefined accounts and displays their current nonce values and balances.

**Output Format:**
- Account Address
- Nonce (Decimal and Hex)
- Balance (Wei)

**Examples:**
```bash
./check_prefunded_nonces.sh
```

### Gas Pricing Analysis Tool

```bash
./analyze_gas_pricing.sh [options]
```

This script analyzes gas pricing strategies and transaction requirements across different Ethereum clients.

**Examples:**
```bash
./analyze_gas_pricing.sh
```

## Configuration Scripts

### RPC Configuration

```bash
source ./rpc_config.sh
```

This is a configuration file that contains RPC endpoint configurations used by multiple scripts for querying different Ethereum client nodes. It provides:

- RPC endpoint list for all client nodes
- Node type to RPC endpoint mapping
- Helper functions for endpoint management

**Node Endpoints:**
- Geth: http://172.16.0.11:8545
- Nethermind: http://172.16.0.12:8545
- Reth: http://172.16.0.13:8545
- Erigon: http://172.16.0.14:8545
- Besu: http://172.16.0.15:8545

This file is sourced by other scripts to maintain consistent RPC endpoint configuration across the entire toolkit.

## Usage Notes

1. **Prerequisites**: Ensure that the Ethereum network is running and accessible via the configured RPC endpoints.

2. **Dependencies**: Most scripts require `curl`, `jq`, and `bash`. Some scripts may require additional tools like `bc` for calculations.

3. **Network Configuration**: The scripts are configured to work with a local Ethereum test network with 5 different client implementations.

4. **File Permissions**: Make sure all scripts have execute permissions:
   ```bash
   chmod +x *.sh
   ```

5. **Help Information**: All scripts support `--help` or `-h` option to display detailed usage information.

For more detailed information about each script, run the script with the `--help` option.

