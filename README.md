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
├── cmd/             # CLI + tx-fuzz entrypoints
├── config/          # Config structs & loaders
├── devp2p/          # DevP2P stack (discv4/5, RLPx, eth)
├── fuzzer/          # Fuzzing core
├── logs/            # Runtime logs
├── manual/          # Manual protocol test runner
├── mutation/        # Mutation strategies
├── output/          # Reports & artifacts
├── scripts/         # Devnet + helpers
├── stress_test/     # Stress test harness
├── templates/       # Config templates
├── utils/           # Utilities
├── config.yaml      # Example config
└── main.go          # Program entry
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

```bash
cd manual
go run main.go
# reads manual/config.yaml and sends predefined sequences
```

### 2) Stress test

```bash
cd stress_test
./run_stress_test.sh
```

### 3) Transaction fuzzing

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

