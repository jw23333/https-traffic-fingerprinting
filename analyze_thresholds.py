#!/usr/bin/env python3
"""
Analyze burst pair data to recommend thresholds for "small" vs "big" classification.
Helps design n-gram sequential features.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from glob import glob

def analyze_byte_distributions():
    """Analyze out_bytes and in_bytes across all sites to recommend thresholds."""
    
    all_out_bytes = []
    all_in_bytes = []
    
    pairs_dir = Path("dataset_pairs")
    
    for site_dir in pairs_dir.iterdir():
        if not site_dir.is_dir():
            continue
        
        for pairs_file in site_dir.glob("*_pairs.csv"):
            df = pd.read_csv(pairs_file)
            all_out_bytes.extend(df['out_bytes'].tolist())
            all_in_bytes.extend(df['in_bytes'].tolist())
    
    out_arr = np.array(all_out_bytes)
    in_arr = np.array(all_in_bytes)
    
    print("=" * 80)
    print("OUTBOUND BURST SIZES (bytes)")
    print("=" * 80)
    print(f"Count:      {len(out_arr):,}")
    print(f"Mean:       {np.mean(out_arr):.1f}")
    print(f"Median:     {np.median(out_arr):.1f}")
    print(f"Std:        {np.std(out_arr):.1f}")
    print(f"Min:        {np.min(out_arr):.1f}")
    print(f"Max:        {np.max(out_arr):.1f}")
    print()
    print("Percentiles:")
    for p in [10, 25, 50, 75, 90, 95]:
        print(f"  {p}th:      {np.percentile(out_arr, p):.1f}")
    
    print()
    print("=" * 80)
    print("INBOUND BURST SIZES (bytes)")
    print("=" * 80)
    print(f"Count:      {len(in_arr):,}")
    print(f"Mean:       {np.mean(in_arr):.1f}")
    print(f"Median:     {np.median(in_arr):.1f}")
    print(f"Std:        {np.std(in_arr):.1f}")
    print(f"Min:        {np.min(in_arr):.1f}")
    print(f"Max:        {np.max(in_arr):.1f}")
    print()
    print("Percentiles:")
    for p in [10, 25, 50, 75, 90, 95]:
        print(f"  {p}th:      {np.percentile(in_arr, p):.1f}")
    
    print()
    print("=" * 80)
    print("RECOMMENDED THRESHOLDS")
    print("=" * 80)
    print()
    print("STRATEGY 1: Median-based (balanced split)")
    print(f"  out_bytes: small ≤ {np.median(out_arr):.0f}, large > {np.median(out_arr):.0f}")
    print(f"  in_bytes:  small ≤ {np.median(in_arr):.0f}, large > {np.median(in_arr):.0f}")
    print()
    print("STRATEGY 2: 3-tier (small / medium / large)")
    print(f"  out_bytes: small ≤ {np.percentile(out_arr, 33):.0f}, medium ≤ {np.percentile(out_arr, 67):.0f}, large > {np.percentile(out_arr, 67):.0f}")
    print(f"  in_bytes:  small ≤ {np.percentile(in_arr, 33):.0f}, medium ≤ {np.percentile(in_arr, 67):.0f}, large > {np.percentile(in_arr, 67):.0f}")
    print()
    print("STRATEGY 3: Fixed thresholds (domain knowledge)")
    print(f"  Tiny ≤ 100, Small ≤ 1000, Medium ≤ 10000, Large > 10000")
    print()
    print("RECOMMENDATION:")
    print("  Start with median-based (Strategy 1) for binary small/large.")
    print("  Your burst pairs ALREADY have sequential order, so you can extract")
    print("  n-grams directly without changing the pcap→pairs pipeline!")
    print()

if __name__ == "__main__":
    analyze_byte_distributions()
