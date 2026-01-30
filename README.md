# AASI: Agent Anchored Semantic Index

[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This repository contains the official reference implementation and reproduction scripts for the paper:

**"AASI: The Agent Anchored Semantic Index - Empirical Analysis of Discovery Layer Vulnerabilities in the Agentic Web"**

AASI is a decentralized discovery protocol designed to secure the "Patchwork AGI" ecosystem against AI-driven Sybil attacks. It introduces a **Two-Stage Defense Mechanism** combining high-visibility vector retrieval with cryptographically anchored identity trust.

---

##  Repository Structure

This repository is organized as a Rust workspace:

- **`crates/`**: The core protocol implementation.
  - `aasi-core`: The discovery node (Rust + Qdrant + Sled).
  - `aasi-client`: Cryptography SDK (Ed25519 signing, Argon2 PoW).
  - `aasi-proto`: gRPC service definitions.
- **`experiments/reproduction/`**: The trace-driven simulation harness used in the paper (formerly `aasi-experiment`).
- **`tools/`**: Python scripts for dataset generation and result plotting.
- **`infra/`**: Docker Compose configuration for the Qdrant vector database.

---

##  Quick Start (Reproducing Results)

We provide a "Golden Path" script to reproduce the paper's key findings (Sybil@10 reduction from 95% to 0%) in a single command.

### Prerequisites
- **Rust** (stable)
- **Docker** (with Compose)
- **Python 3.8+** (with `pip`)
### Environment Note
This codebase and the reproduction scripts were developed and tested on **macOS (Apple Silicon, M-series)**. 
While the core Rust crates are cross-platform, Linux users running the simulation harness may need to verify Docker network bridge configurations (specifically host-container communication via `127.0.0.1`).

### Steps

1. **Install Python Dependencies:**
   ```bash
   pip install -r tools/requirements.txt
   ```

2. **Run Full Reproduction:**
   This script will:
   - Start the vector database (Docker).
   - Generate the SciFact dataset.
   - Run **Baseline** (Collapse), **Treatment 1** (Visibility), and **Treatment 2** (Defense) simulations.
   - Generate the final comparison plot in `results/plots/`.
   
   ```bash
   ./scripts/reproduce_paper_results.sh
   ```

   *(Note: The full simulation takes approx. 3-4 hours on a modern workstation due to the 1,000-agent interaction graph simulation. For a quick smoke test, edit the script to reduce `--rounds` to 5.)*

3. **View Results:**
   - **Metrics Summary:** `results/empirical_defense_summary.md` (Auto-generated)
   - **Plot:** `results/plots/defense_impact_comparison.png`

---

##  Additional Experiments

### Sybil Population Scaling Analysis (Table 2)

To reproduce the **Robustness to Population Scaling** experiment (Table 2 in the paper), which validates that visibility expansion alone is insufficient regardless of the attacker population size:

```bash
./scripts/run_sybil_scaling_experiment.sh
```

This script will:
- Generate datasets with $N_{sybil} \in \{50, 100, 200, 500\}$ agents.
- Run experiments with fixed $K=100$ retrieval window and $\beta=0.3$ trust weight.
- Output results to `results/scaling_n_sybil/`.

**Expected Runtime:** ~2-3 hours (5 rounds per configuration).

**Key Finding:** Even with $K=2N$ oversampling (50 Sybils vs 100 window), Sybils achieve 100% dominance, confirming that the Defense Inequality ($\beta \Delta T > \alpha \Delta S$) is necessary.

**Note:** The $N=500$ configuration may experience occasional timeouts due to vector search load (this is documented in the paper as a known scalability limitation of in-memory vector stores).

---

##  Manual Usage

### Start Infrastructure
```bash
docker compose -f infra/docker-compose.yml up -d
```

### Run the Core Node
```bash
cargo run -p aasi-core
```

### Register an Agent (CLI)
```bash
cargo run -p aasi-cli -- register --did "did:web:example.com" --capability "Rust Developer"
```

---

## 📜 License

This project is licensed under the AGPL v3 License - see the [LICENSE](LICENSE) file for details.
