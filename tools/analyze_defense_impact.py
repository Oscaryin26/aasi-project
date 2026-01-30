
import json
import matplotlib.pyplot as plt
import os
import pandas as pd

def load_sybil_metric(run_dir):
    metrics_path = os.path.join(run_dir, "metrics.json")
    if not os.path.exists(metrics_path):
        print(f"Warning: {metrics_path} not found.")
        return None
    
    with open(metrics_path, "r") as f:
        data = json.load(f)
    
    # Extract Sybil@10 for 'full' method over rounds
    rounds = []
    scores = []
    for r in data["rounds"]:
        rounds.append(r["round"])
        scores.append(r["sybil_at_10"]["full"])
        
    return rounds, scores

def analyze_defense_impact():
    # Define the three experimental conditions
    runs = {
        "Baseline (Collapsed)": "results/fix_high_noise_03",
        "Treatment 1 (Visibility Fix)": "results/fix_visibility_01/1766521678",
        "Treatment 2 (Defense Fix)": "results/defense_01/1766546347"
    }
    
    plt.figure(figsize=(10, 6))
    
    final_values = {}

    for label, path in runs.items():
        if not os.path.exists(path):
            print(f"Skipping {label}: Path not found ({path})")
            continue
            
        rounds, scores = load_sybil_metric(path)
        if rounds:
            plt.plot(rounds, scores, label=label, linewidth=2, marker='o', markevery=5)
            final_values[label] = scores[-1]
            print(f"{label}: Final Sybil@10 = {scores[-1]:.3f}")

    plt.title("Impact of Two-Stage Defense on Sybil Dominance")
    plt.xlabel("Round")
    plt.ylabel("Sybil@10 (Proportion of Top-10 Results)")
    plt.ylim(-0.05, 1.05)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend()
    
    output_path = "results/plots/defense_impact_comparison.png"
    os.makedirs("results/plots", exist_ok=True)
    plt.savefig(output_path)
    print(f"\nPlot saved to {output_path}")

if __name__ == "__main__":
    analyze_defense_impact()
