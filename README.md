# D2PFuzz

Fuzz the Ethereum networking stack—end to end.
**D2PFuzz** generates and mutates DevP2P traffic (discv4/5, RLPx, `eth/*`) and drives tx-level fuzzing to surface client-specific mempool, networking, and consensus-edge bugs across Geth, Nethermind, Erigon, Besu, Reth, etc.

---

## Highlights

* **Protocol fuzzing**: craft/sequence valid & mutated packets for discv4, discv5, RLPx, and `eth` sub-protocols.
* **Transaction fuzzing**: sustained, patterned load with optional mutation and multi-RPC load balancing.
* **Reproducible**: deterministic seeds and captured outputs for one-tx counterexamples.
* **Operable**: simple YAML config, scripts to spin up a local multi-client devnet, real-time stats and JSON reports.

---

## Project Layout

```
D2PFuzz/
├── account/            # Account management
├── blob/               # Blob transaction component
├── cmd/                # Command-line tools directory
│   ├── livefuzzer/     # Transaction fuzzer tool
│   └── manual/         # Manual testing tool
├── config/             # Configuration modules
├── devp2p/             # P2P network protocol modules
├── ethclient/          # Unified client management
├── fuzzer/             # Fuzzing core modules
├── logs/               # Log files directory
├── mutation/           # Mutation strategies
├── output/             # Reports storage directory
├── poc/                # Proof of Concept implementations
├── rpc/                # Local rpc component
├── scripts/            # Helper scripts
├── stress_test/        # Stress testing directory
├── templates/          # Template config files
├── testing/            # Test runner framework
├── transaction/        # Transaction building
├── utils/              # Utility functions
├── config.yaml         # Main configuration file
├── constants.go        # Global constants
├── main.go             # Program entry point
└── README.md           # Usage of the repository
```

---

## Prerequisites

* Go 1.21+
* Docker & Docker Compose (for local multi-client testnet)
* Git

---

## Install

```bash
git clone https://github.com/AgnopraxLab/D2PFuzz.git
cd D2PFuzz
go mod tidy
```

---

## Spin up a Local Ethereum Testnet (multi-client)

We use [`ethpandaops/ethereum-package`](https://github.com/ethpandaops/ethereum-package).

```bash
./scripts/run_ethereum_network.sh -c <your_ethereumpackage_config.yaml>
# Produces scripts/output.txt with enodes and RPC URLs
```

Grab enodes/RPCs from `scripts/output.txt` and fill your YAML (see `templates/`).

---

## Quick Start

### 1) Manual protocol test (DevP2P / eth sub-protocols)

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

### 2) Stress test

```bash
cd stress_test
./run_stress_test.sh
```

### POC (Proof of Concept) Testing

Specialized testing tools for specific scenarios.

#### Maximum Nonce Testing

Test extreme nonce values (`math.MaxUint64`) to verify how Ethereum clients handle boundary conditions.

**Quick Start:**
```bash
cd poc/maxNonce
# Edit maxNonce.go to configure your node parameters
go run maxNonce.go
```

**Expected Result:** Transaction should be `QUEUED` (waiting for conditions) due to extreme nonce value.

### tx-fuzz
```bash
cd cmd
./livefuzzer spam --seed <seed> --sk <hex_private_key> -rpc <rpc_url>
```

* `--seed` any int (use fixed for reproducibility)
* `--sk` account private key (fund it on your devnet)
* `-rpc` target RPC (repeat flag to load balance across many)

More flags mirror [tx-fuzz](https://github.com/MariusVanDerWijden/tx-fuzz/blob/master/README.md).

---

## Configuration (YAML)

### `tx_fuzz` block

```yaml
tx_fuzz:
  enabled: true
  chain_id: 3151908
  tx_per_second: 10
  fuzz_duration_sec: 60
  seed: 0                 # 0 = random
  use_accounts: true

  # gas
  max_gas_price: 20000000000   # 20 gwei
  max_gas_limit: 8000000

  # multi-node
  rpc_endpoints:
    - "http://172.16.0.11:8545"
    - "http://172.16.0.12:8545"

  # retries
  max_retries: 3
  retry_delay: 1s
  circuit_breaker: true
  failure_threshold: 5

  # load shape: constant | ramp | spike | wave
  load_pattern_type: "ramp"
```

### Mutation & tracking (Go-side toggles)

```go
fuzzConfig := &fuzzer.TxFuzzConfig{
  UseMutation:    true,
  MutationRatio:  0.3,   // 30% mutated
  EnableTracking: true,  // track mined/failed/pending
  ConfirmBlocks:  3,
}
```

### Metrics (Go-side)

```go
EnableMetrics:   true
MetricsInterval: 10 * time.Second
```

---

## Tuning Cheatsheet

* **TPS** (`tx_per_second`)

  * Devnet sanity: 5–20
  * Stress: 50–100
  * Extreme: 100+
* **Duration** (`fuzz_duration_sec`)

  * Quick: 30–60s
  * Standard: 300–600s
  * Long: ≥3600s
* **Load shape**

  * `constant`: stability
  * `ramp`: progressive stress (recommended)
  * `spike`: peak/burst
  * `wave`: long-run stability

**Tips**: ramp up gradually, monitor latency/success, distribute load across multiple RPCs.

---

## Outputs

Generated under `output/`:

* `tx_fuzz_results.json` — per-tx records, timing, outcomes, mutation flags
* `success_tx_hashes.txt` — mined tx hashes
* `failed_tx_hashes.txt` — failures for triage

Real-time console sample:

```
--- Stats (Runtime: 30s) ---
Total Sent: 150 | Mined: 145 | Failed: 3 | Pending: 2
Mutation Used: 45 | Random Used: 105
Success Rate: 96.7% | Mutation Rate: 30.0%
```

---

## Troubleshooting

* **`connection refused`**

  * Confirm RPC is reachable; node is up; firewall rules allow access.
* **`insufficient funds for gas`**

  * Fund the sender; lower `max_gas_price`/`max_gas_limit`.
* **Low observed TPS**

  * Check network latency; reduce `max_retries`/`retry_delay`; add RPCs and increase concurrency.
* **High memory**

  * Shorten `fuzz_duration_sec`; disable tracking; lower TPS.

---

## Example Presets

**Lightweight**

```yaml
tx_fuzz:
  tx_per_second: 5
  fuzz_duration_sec: 30
  max_gas_price: 10000000000
  load_pattern_type: "constant"
```

**Stress**

```yaml
tx_fuzz:
  tx_per_second: 50
  fuzz_duration_sec: 300
  max_gas_price: 50000000000
  load_pattern_type: "ramp"
```

**Extreme**

```yaml
tx_fuzz:
  tx_per_second: 100
  fuzz_duration_sec: 600
  max_gas_price: 100000000000
  load_pattern_type: "spike"
```

---

## Notes on Scope

* **Protocol fuzzing** targets discv4/5 discovery, RLPx handshakes/frames, and `eth/*` messages (Ping/Pong/NewBlock/Txs, etc.), including mutated sequences and time/chain-state-aware flows.
* **Tx-fuzz** complements network fuzzing by stressing mempool rules (nonce gaps, gas pricing, batch shapes) and surfacing divergent behaviors across clients.

---

## License

MIT. See [LICENSE](LICENSE).

## Version

Current: **v0.3**
Older, fully tested snapshots: `archive-v0.1`, `archive-v0.2`.

---

