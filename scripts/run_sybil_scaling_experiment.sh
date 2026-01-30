#!/bin/bash
set -e

# AASI Sybil Scaling Experiment
# This script tests the "Visibility Defense" (Treatment 1) against varying Sybil population sizes.
# Goal: Demonstrate that Visibility (K=100) only works when N_Sybil < K, and fails when N_Sybil >= K.

echo "========================================================"
echo "   AASI Scaling Analysis: Sybil Population vs Visibility"
echo "========================================================"

# Check dependencies
if ! command -v docker &> /dev/null;
    then
    echo "Error: docker is not installed."
    exit 1
fi

if ! command -v cargo &> /dev/null;
    then
    echo "Error: rust/cargo is not installed."
    exit 1
fi

# 1. Generate Datasets
# We keep Elite=100, Honest=700 fixed, and vary Sybil count.
echo "[1/2] Generating Datasets for N_Sybil = {50, 100, 200, 500}..."

for N in 50 100 200 500;
    do
    DATASET_PATH="datasets/sybil_${N}"
    if [ ! -f "$DATASET_PATH/dataset_meta.json" ];
        then
        echo "  Generating N=${N}..."
        # n_agents = 800 (honest+elite) + N
        TOTAL_AGENTS=$((800 + N))
        python3 tools/download_dataset.py \
            --out "$DATASET_PATH" \
            --n-sybil $N \
            --n-elite 100 \
            --n-honest 700 \
            --n-agents $TOTAL_AGENTS \
            --seed 42 > /dev/null
    else
        echo "  Dataset N=${N} exists (metadata found). Skipping."
    fi
done

# 2. Run Experiments (Treatment 1 Config)
# Config: K=100 (Visibility), Beta=0.3 (Low Trust)
# Hypothesis:
#   N=50  (< K): Sybil@10 should be low (Defense works?)
#   N=100 (= K): Sybil@10 should be high (Saturation point)
#   N=200 (> K): Sybil@10 = 100% (Failure)
#   N=500 (>> K): Sybil@10 = 100% (Failure)

export AASI_SEARCH_OVERSAMPLING=100
export AASI_RANK_BETA=0.3

echo "[2/2] Running Experiments (K=100, Beta=0.3)..."

for N in 50 100 200 500;
    do
    echo "--------------------------------------------------------"
    echo "  Running Scenario: N_Sybil = ${N} (vs K=100)"
    echo "--------------------------------------------------------"
    
    RESULTS_DIR="results/scaling_n_sybil/N_${N}"
    
    # We run 5 rounds to quickly see the convergence trend
    cargo run -p aasi-experiment -- run-all \
        --dataset "datasets/sybil_${N}" \
        --rounds 5 \
        --results-dir "$RESULTS_DIR" \
        --reset --start-server
        
    echo "  > Done. Results in $RESULTS_DIR"
done

echo "========================================================