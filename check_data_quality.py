#!/usr/bin/env python3
"""
check_data_quality.py

Analyze data quality of collected pcap files in dataset_raw.
Checks traffic variance, feature consistency, and site distinctiveness.

Usage:
    python check_data_quality.py

This helps evaluate whether sites are good candidates for classification:
- Low variance (< 3x) = stable, predictable traffic
- High variance (> 5x) = unstable, hard to classify
- Similar feature distributions between sites = will confuse each other
"""

import sys
from pathlib import Path
from typing import Dict, List
import pandas as pd
import numpy as np

from process_pcap import process_pcap, get_pairs_from_pcap
from process_dataset_pairs import summary_features


def analyze_site_variance(site_dir: Path, site_name: str) -> Dict:
    """Analyze variance in traffic patterns for a single site."""
    pcap_files = sorted(site_dir.glob("*.pcap"))
    
    if not pcap_files:
        return None
    
    pair_counts = []
    feature_values = []
    
    for pcap_path in pcap_files:
        try:
            # Get pairs without writing to disk
            pairs = get_pairs_from_pcap(
                pcap_path=str(pcap_path),
                iface="en1",
                gap_ms=50.0
            )
            
            if not pairs:
                continue
                
            # Convert to DataFrame and extract features
            df = pd.DataFrame(pairs)
            feats = summary_features(df)
            
            pair_counts.append(len(pairs))
            feature_values.append(feats)
            
        except Exception as e:
            print(f"  [!] Error processing {pcap_path.name}: {e}", file=sys.stderr)
            continue
    
    if not pair_counts:
        return None
    
    # Compute pair count statistics
    min_pairs = min(pair_counts)
    max_pairs = max(pair_counts)
    avg_pairs = np.mean(pair_counts)
    std_pairs = np.std(pair_counts)
    ratio = max_pairs / min_pairs if min_pairs > 0 else 0
    
    # Assess variance level
    if ratio < 3.0:
        assessment = "EXCELLENT"
    elif ratio < 4.0:
        assessment = "GOOD"
    elif ratio < 5.0:
        assessment = "OK"
    else:
        assessment = "HIGH"
    
    # Compute feature variance (coefficient of variation)
    feature_cv = {}
    if feature_values:
        feat_df = pd.DataFrame(feature_values)
        for col in feat_df.columns:
            mean_val = feat_df[col].mean()
            std_val = feat_df[col].std()
            cv = (std_val / mean_val * 100) if mean_val > 0 else 0
            feature_cv[col] = cv
    
    return {
        'site': site_name,
        'visits': len(pair_counts),
        'min_pairs': min_pairs,
        'max_pairs': max_pairs,
        'avg_pairs': avg_pairs,
        'std_pairs': std_pairs,
        'ratio': ratio,
        'assessment': assessment,
        'feature_cv': feature_cv,
        'feature_values': feature_values
    }


def print_variance_report(stats: List[Dict]):
    """Print formatted variance report for all sites."""
    print("\n" + "=" * 90)
    print("TRAFFIC VARIANCE ANALYSIS")
    print("=" * 90)
    print(f"{'Site':<20} {'Visits':>7} {'Min':>6} {'Max':>6} {'Avg':>8} {'Std':>8} {'Ratio':>7} {'Quality':<10}")
    print("-" * 90)
    
    for s in sorted(stats, key=lambda x: x['ratio']):
        print(f"{s['site']:<20} {s['visits']:>7} {s['min_pairs']:>6} {s['max_pairs']:>6} "
              f"{s['avg_pairs']:>8.1f} {s['std_pairs']:>8.1f} {s['ratio']:>6.1f}x {s['assessment']:<10}")
    
    print("\nVariance Assessment:")
    print("  EXCELLENT (< 3.0x) - Very stable, ideal for classification")
    print("  GOOD      (< 4.0x) - Stable, should work well")
    print("  OK        (< 5.0x) - Acceptable, may have some confusion")
    print("  HIGH      (≥ 5.0x) - Unstable, likely to cause misclassifications")


def print_feature_variance(stats: List[Dict]):
    """Print feature-level variance for each site."""
    print("\n" + "=" * 90)
    print("FEATURE COEFFICIENT OF VARIATION (CV%) - Lower is more stable")
    print("=" * 90)
    
    # Get all feature names
    if not stats or not stats[0]['feature_cv']:
        print("No feature data available")
        return
    
    feature_names = list(stats[0]['feature_cv'].keys())
    
    print(f"{'Site':<20}", end="")
    for feat in feature_names[:6]:  # Show top 6 most important features
        print(f"{feat[:10]:>12}", end="")
    print()
    print("-" * 90)
    
    for s in sorted(stats, key=lambda x: x['site']):
        print(f"{s['site']:<20}", end="")
        for feat in feature_names[:6]:
            cv = s['feature_cv'].get(feat, 0)
            print(f"{cv:>11.1f}%", end="")
        print()
    
    print("\nNote: CV% = (std / mean) × 100. Lower values indicate more consistent features.")


def compare_sites(stats: List[Dict]):
    """Compare feature distributions between sites to find overlaps."""
    print("\n" + "=" * 90)
    print("SITE DISTINCTIVENESS - Feature overlap analysis")
    print("=" * 90)
    
    if len(stats) < 2:
        print("Need at least 2 sites for comparison")
        return
    
    # For each pair of sites, compute how much their features overlap
    from itertools import combinations
    
    print(f"{'Site A':<20} {'Site B':<20} {'Overlap Score':>15} {'Assessment':<15}")
    print("-" * 90)
    
    for site_a, site_b in combinations(stats, 2):
        if not site_a['feature_values'] or not site_b['feature_values']:
            continue
        
        # Compute overlap based on mean pair count proximity
        mean_a = site_a['avg_pairs']
        mean_b = site_b['avg_pairs']
        
        # Overlap score: how similar the average pair counts are
        # Lower score = more distinct, Higher score = more overlap
        overlap = 1.0 - abs(mean_a - mean_b) / max(mean_a, mean_b)
        
        if overlap > 0.8:
            assessment = "HIGH OVERLAP"
        elif overlap > 0.6:
            assessment = "MODERATE"
        else:
            assessment = "DISTINCT"
        
        print(f"{site_a['site']:<20} {site_b['site']:<20} {overlap:>14.2f}  {assessment:<15}")
    
    print("\nOverlap Score: 1.0 = identical avg traffic, 0.0 = completely different")
    print("HIGH OVERLAP (> 0.8) - Sites likely to confuse each other")
    print("MODERATE     (> 0.6) - Some confusion possible")
    print("DISTINCT     (≤ 0.6) - Sites should be distinguishable")


def main():
    dataset_dir = Path("dataset_raw")
    
    if not dataset_dir.exists():
        print(f"Error: {dataset_dir} not found")
        sys.exit(1)
    
    print("Analyzing data quality from dataset_raw...")
    print("This may take a minute for large datasets...\n")
    
    stats = []
    
    # Analyze each site
    for site_dir in sorted(dataset_dir.iterdir()):
        if not site_dir.is_dir():
            continue
        
        site_name = site_dir.name
        print(f"Processing {site_name}...", end=" ", flush=True)
        
        result = analyze_site_variance(site_dir, site_name)
        if result:
            stats.append(result)
            print(f"✓ ({result['visits']} visits, {result['ratio']:.1f}x variance)")
        else:
            print("✗ (no valid data)")
    
    if not stats:
        print("\nNo valid data found in dataset_raw")
        sys.exit(1)
    
    # Print reports
    print_variance_report(stats)
    print_feature_variance(stats)
    compare_sites(stats)
    
    # Summary recommendations
    print("\n" + "=" * 90)
    print("RECOMMENDATIONS")
    print("=" * 90)
    
    excellent = [s for s in stats if s['assessment'] == 'EXCELLENT']
    good = [s for s in stats if s['assessment'] == 'GOOD']
    ok = [s for s in stats if s['assessment'] == 'OK']
    high = [s for s in stats if s['assessment'] == 'HIGH']
    
    print(f"\nSites by quality:")
    print(f"  EXCELLENT: {len(excellent)} sites - {', '.join(s['site'] for s in excellent) if excellent else 'None'}")
    print(f"  GOOD:      {len(good)} sites - {', '.join(s['site'] for s in good) if good else 'None'}")
    print(f"  OK:        {len(ok)} sites - {', '.join(s['site'] for s in ok) if ok else 'None'}")
    print(f"  HIGH:      {len(high)} sites - {', '.join(s['site'] for s in high) if high else 'None'}")
    
    if high:
        print(f"\n⚠️  Consider removing high-variance sites: {', '.join(s['site'] for s in high)}")
    
    if excellent or good:
        best = excellent + good
        print(f"\n✓  Recommended sites for training: {', '.join(s['site'] for s in best)}")
    
    print()


if __name__ == '__main__':
    main()
