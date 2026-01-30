# AASI Infra (Localhost)

This directory contains small, reproducible infrastructure pieces for the AASI experiment environment:

- **Qdrant** (vector DB) on `localhost:6334` (gRPC) / `localhost:6333` (REST)
- **Anvil** (local EVM) on `localhost:8545` with a fixed `block_time=2s`
- **Local DID document hosting** (for `did:web:127.0.0.1%3A8000:*`)

## Start / Stop

From `aasi/`:

- Start: `docker compose -f infra/docker-compose.yml up -d`
- Stop + wipe volumes (clean rerun): `docker compose -f infra/docker-compose.yml down -v`

## DID Documents (Local)

Serve DID documents (used by Identity registration and feedback signature verification):

- `./scripts/serve_did.sh`
- Verify: `curl http://127.0.0.1:8000/elite/0001/did.json`

The experiment harness may generate per-run DID documents under a run-specific directory; `serve_did.sh` supports overriding the served root.

## Local EVM (Blockchain Baseline)

Default (compose): `anvil` is started automatically with `--block-time 2` on `localhost:8545`.

Manual alternative (no compose):

- Install Foundry: `https://book.getfoundry.sh/getting-started/installation`
- Run: `anvil --block-time 2 --port 8545`

Benchmarking note:

- We compare **write/update visibility latency** (submit → mined → confirmed), not read latency.
- Report a **range** across confirmations (e.g., `1 block`, `3 conf`, `6 conf`) and record chain params in `run_config.json`.
