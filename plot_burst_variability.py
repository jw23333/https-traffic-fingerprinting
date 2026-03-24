#!/usr/bin/env python3
"""
Plot burst pair variability comparison between apple.com and chickenpox.
Shows why apple.com is unsuitable for fingerprinting (high variance)
while chickenpox is stable (low variance).
"""

import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# Paths to burst pair CSVs
apple_pairs_dir = Path("experiments/unstable_case/pairs/apple")
chickenpox_pairs_dir = Path("dataset_pairs/chickenpox")

def load_pair_counts(pairs_dir):
    """Load burst pair counts for each visit."""
    visits = sorted(pairs_dir.glob("*.csv"))
    pair_counts = []
    visit_numbers = []
    
    for i, csv in enumerate(visits, 1):
        try:
            df = pd.read_csv(csv)
            pair_counts.append(len(df))
            visit_numbers.append(i)
        except Exception as e:
            print(f"Warning: Could not read {csv.name}: {e}")
    
    return visit_numbers, pair_counts

# Load data
print("[*] Loading apple.com burst data...")
apple_visits, apple_counts = load_pair_counts(apple_pairs_dir)

print("[*] Loading chickenpox burst data...")
chicken_visits, chicken_counts = load_pair_counts(chickenpox_pairs_dir)

if not apple_counts or not chicken_counts:
    print("ERROR: Could not load data from one or both directories")
    exit(1)

# Calculate statistics
apple_mean = np.mean(apple_counts)
apple_min = min(apple_counts)
apple_max = max(apple_counts)
apple_var_ratio = apple_max / apple_min if apple_min > 0 else float('inf')

chicken_mean = np.mean(chicken_counts)
chicken_min = min(chicken_counts)
chicken_max = max(chicken_counts)
chicken_var_ratio = chicken_max / chicken_min if chicken_min > 0 else float('inf')

print(f"\n[+] Apple.com Statistics:")
print(f"    Min: {apple_min}, Max: {apple_max}, Mean: {apple_mean:.1f}")
print(f"    Variance Ratio: {apple_var_ratio:.1f}x")

print(f"\n[+] Chickenpox Statistics:")
print(f"    Min: {chicken_min}, Max: {chicken_max}, Mean: {chicken_mean:.1f}")
print(f"    Variance Ratio: {chicken_var_ratio:.1f}x")

# Create side-by-side plots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Apple.com
ax1.plot(apple_visits, apple_counts, 'o-', color='red', alpha=0.7, linewidth=2, markersize=6)
ax1.axhline(y=apple_mean, color='red', linestyle='--', linewidth=2, label=f'Mean: {apple_mean:.0f}')
ax1.fill_between(apple_visits, apple_min, apple_max, alpha=0.1, color='red')
ax1.set_xlabel('Visit Number', fontsize=11)
ax1.set_ylabel('Burst Pair Count', fontsize=11)
ax1.set_title(f'Apple.com: Unstable Traffic\n(Variance Ratio: {apple_var_ratio:.1f}x)', fontsize=12, fontweight='bold')
ax1.legend(fontsize=10)
ax1.grid(alpha=0.3)
ax1.set_ylim(0, max(apple_counts) * 1.1)

# Plot 2: Chickenpox
ax2.plot(chicken_visits, chicken_counts, 'o-', color='green', alpha=0.7, linewidth=2, markersize=6)
ax2.axhline(y=chicken_mean, color='green', linestyle='--', linewidth=2, label=f'Mean: {chicken_mean:.0f}')
ax2.fill_between(chicken_visits, chicken_min, chicken_max, alpha=0.1, color='green')
ax2.set_xlabel('Visit Number', fontsize=11)
ax2.set_ylabel('Burst Pair Count', fontsize=11)
ax2.set_title(f'Chickenpox: Stable Traffic\n(Variance Ratio: {chicken_var_ratio:.1f}x)', fontsize=12, fontweight='bold')
ax2.legend(fontsize=10)
ax2.grid(alpha=0.3)
ax2.set_ylim(0, max(apple_counts) * 1.1)  # Same y-axis scale for comparison

plt.suptitle('Burst Pair Variability: Unstable vs. Stable Sites', fontsize=14, fontweight='bold', y=1.00)
plt.tight_layout()
plt.savefig('burst_pair_variability_comparison.png', dpi=300, bbox_inches='tight')
print(f"\n[+] Plot saved to burst_pair_variability_comparison.png")
plt.close()

print("\n[✓] Done!")
