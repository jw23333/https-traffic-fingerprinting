#!/usr/bin/env python3
"""
process_dataset_pairs.py

Build a training dataset from `pairs_metadata.csv`, extract features from each
`*_pairs.csv` file, train a Random Forest classifier, and save the trained
model and label encoder.

Usage (quick):
  python3 process_dataset_pairs.py --meta pairs_metadata.csv --out-model rf_model.joblib

Dependencies:
  pip install pandas scikit-learn joblib

Feature modes:
  summary  - fixed-size summary statistics per pairs CSV (default)
  firstk   - include flattened first-K pairs in addition to summary stats

The script prints classification metrics and saves the model and label encoder.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import math
import sys

import numpy as np

try:
    import pandas as pd
except Exception as e:
    print("Missing dependency: pandas. Install with: pip install pandas")
    raise

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
except Exception:
    print("Missing dependency: scikit-learn. Install with: pip install scikit-learn")
    raise

try:
    import joblib
except Exception:
    print("Missing dependency: joblib. Install with: pip install joblib")
    raise


def read_pairs_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Pairs CSV not found: {path}")
    df = pd.read_csv(path)
    return df


# --- N-GRAM FEATURE EXTRACTION ---
# Thresholds determined from analyze_thresholds.py (median-based split)
OUT_SMALL_THRESHOLD = 11450
IN_SMALL_THRESHOLD = 167


def extract_ngram_features(df: pd.DataFrame) -> dict:
    """Extract sequential n-gram features from burst pairs.
    
    Features are position-independent (counts/ratios), allowing Random Forest
    to learn traffic flow patterns even when resource loading order varies.
    """
    if df.empty:
        return _empty_ngram_features()
    
    # Classify each burst pair as small/large for out and in
    out_classes = ['S' if row['out_bytes'] <= OUT_SMALL_THRESHOLD else 'L' 
                   for _, row in df.iterrows()]
    in_classes = ['S' if row['in_bytes'] <= IN_SMALL_THRESHOLD else 'L' 
                  for _, row in df.iterrows()]
    
    features = {}
    
    # --- OUTBOUND BIGRAMS (consecutive burst size transitions) ---
    features['bigram_out_S_to_S'] = sum(1 for i in range(len(out_classes)-1) 
                                         if out_classes[i] == 'S' and out_classes[i+1] == 'S')
    features['bigram_out_S_to_L'] = sum(1 for i in range(len(out_classes)-1) 
                                         if out_classes[i] == 'S' and out_classes[i+1] == 'L')
    features['bigram_out_L_to_S'] = sum(1 for i in range(len(out_classes)-1) 
                                         if out_classes[i] == 'L' and out_classes[i+1] == 'S')
    features['bigram_out_L_to_L'] = sum(1 for i in range(len(out_classes)-1) 
                                         if out_classes[i] == 'L' and out_classes[i+1] == 'L')
    
    # --- INBOUND BIGRAMS ---
    features['bigram_in_S_to_S'] = sum(1 for i in range(len(in_classes)-1) 
                                        if in_classes[i] == 'S' and in_classes[i+1] == 'S')
    features['bigram_in_S_to_L'] = sum(1 for i in range(len(in_classes)-1) 
                                        if in_classes[i] == 'S' and in_classes[i+1] == 'L')
    features['bigram_in_L_to_S'] = sum(1 for i in range(len(in_classes)-1) 
                                        if in_classes[i] == 'L' and in_classes[i+1] == 'S')
    features['bigram_in_L_to_L'] = sum(1 for i in range(len(in_classes)-1) 
                                        if in_classes[i] == 'L' and in_classes[i+1] == 'L')
    
    # --- BURST TYPE COUNTS (how many small-out/large-in pairs, etc.) ---
    features['count_out_small'] = out_classes.count('S')
    features['count_out_large'] = out_classes.count('L')
    features['count_in_small'] = in_classes.count('S')
    features['count_in_large'] = in_classes.count('L')
    
    # --- RATIOS (normalize by total pairs for scale invariance) ---
    total_pairs = len(df)
    features['ratio_out_small'] = features['count_out_small'] / total_pairs if total_pairs > 0 else 0
    features['ratio_out_large'] = features['count_out_large'] / total_pairs if total_pairs > 0 else 0
    features['ratio_in_small'] = features['count_in_small'] / total_pairs if total_pairs > 0 else 0
    features['ratio_in_large'] = features['count_in_large'] / total_pairs if total_pairs > 0 else 0
    
    # --- TRIGRAMS (3-consecutive outbound burst patterns) ---
    features['trigram_out_S_S_S'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['S', 'S', 'S'])
    features['trigram_out_S_S_L'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['S', 'S', 'L'])
    features['trigram_out_S_L_S'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['S', 'L', 'S'])
    features['trigram_out_S_L_L'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['S', 'L', 'L'])
    features['trigram_out_L_S_S'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['L', 'S', 'S'])
    features['trigram_out_L_S_L'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['L', 'S', 'L'])
    features['trigram_out_L_L_S'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['L', 'L', 'S'])
    features['trigram_out_L_L_L'] = sum(1 for i in range(len(out_classes)-2) 
                                         if out_classes[i:i+3] == ['L', 'L', 'L'])
    
    return features


def _empty_ngram_features() -> dict:
    """Return zero-filled n-gram features for empty captures."""
    features = {}
    # Bigrams
    for direction in ['out', 'in']:
        for a in ['S', 'L']:
            for b in ['S', 'L']:
                features[f"bigram_{direction}_{a}_to_{b}"] = 0
    # Counts
    for direction in ['out', 'in']:
        features[f'count_{direction}_small'] = 0
        features[f'count_{direction}_large'] = 0
    # Ratios
    for direction in ['out', 'in']:
        features[f'ratio_{direction}_small'] = 0
        features[f'ratio_{direction}_large'] = 0
    # Trigrams (outbound only to keep feature count manageable)
    for pattern in ['S_S_S', 'S_S_L', 'S_L_S', 'S_L_L', 'L_S_S', 'L_S_L', 'L_L_S', 'L_L_L']:
        features[f'trigram_out_{pattern}'] = 0
    return features


def summary_features(df: pd.DataFrame) -> dict:
    """Extract aggregate statistics + sequential n-gram features from burst pairs.
    
    Returns a dict combining:
    - 12 original aggregate features (totals, means, stds, ratio)
    - 28 n-gram features (bigrams, trigrams, counts, ratios)
    Total: 40 features
    """
    # safe conversions
    if df.empty:
        base_feats = {
            'total_pairs': 0,
            'total_out_bytes': 0,
            'total_in_bytes': 0,
            'mean_out_bytes': 0,
            'mean_in_bytes': 0,
            'std_out_bytes': 0,
            'std_in_bytes': 0,
            'mean_out_pkts': 0,
            'mean_in_pkts': 0,
            'mean_out_dur': 0,
            'mean_in_dur': 0,
            'ratio_out_in_bytes': 0,
        }
        base_feats.update(_empty_ngram_features())
        return base_feats

    out_bytes = df['out_bytes'].to_numpy(dtype=float)
    in_bytes = df['in_bytes'].to_numpy(dtype=float)
    out_pkts = df['out_pkts'].to_numpy(dtype=float)
    in_pkts = df['in_pkts'].to_numpy(dtype=float)
    out_dur = (df['out_end'] - df['out_start']).to_numpy(dtype=float)
    in_dur = (df['in_end'] - df['in_start']).to_numpy(dtype=float)

    total_out = out_bytes.sum()
    total_in = in_bytes.sum()

    base_feats = {
        'total_pairs': len(df),
        'total_out_bytes': float(total_out),
        'total_in_bytes': float(total_in),
        'mean_out_bytes': float(np.mean(out_bytes)) if out_bytes.size else 0.0,
        'mean_in_bytes': float(np.mean(in_bytes)) if in_bytes.size else 0.0,
        'std_out_bytes': float(np.std(out_bytes)) if out_bytes.size else 0.0,
        'std_in_bytes': float(np.std(in_bytes)) if in_bytes.size else 0.0,
        'mean_out_pkts': float(np.mean(out_pkts)) if out_pkts.size else 0.0,
        'mean_in_pkts': float(np.mean(in_pkts)) if in_pkts.size else 0.0,
        'mean_out_dur': float(np.mean(out_dur)) if out_dur.size else 0.0,
        'mean_in_dur': float(np.mean(in_dur)) if in_dur.size else 0.0,
        'ratio_out_in_bytes': float(total_out / total_in) if total_in > 0 else float(total_out),
    }
    
    # Add n-gram features
    base_feats.update(extract_ngram_features(df))
    
    return base_feats


def first_k_features(df: pd.DataFrame, k: int) -> dict:
    # flatten first K pairs into features; pad with zeros
    cols = ['out_bytes', 'in_bytes', 'out_pkts', 'in_pkts', 'out_start', 'out_end', 'in_start', 'in_end']
    features = {}
    for i in range(k):
        if i < len(df):
            row = df.iloc[i]
            for c in cols:
                features[f'{c}_{i+1}'] = float(row.get(c, 0.0) if not pd.isna(row.get(c, 0.0)) else 0.0)
        else:
            for c in cols:
                features[f'{c}_{i+1}'] = 0.0
    return features


def build_dataset_from_metadata(meta_csv: Path, feature_mode: str = 'summary', k: int = 50):
    meta = pd.read_csv(meta_csv)
    X_rows = []
    labels = []
    file_paths = []

    for idx, row in meta.iterrows():
        label = str(row['label'])
        pairs_path = Path(row['pairs_csv'])
        # Make relative paths absolute if needed
        if not pairs_path.exists():
            # try relative to project
            pairs_path = (Path.cwd() / pairs_path).resolve()

        try:
            df = read_pairs_csv(pairs_path)
        except FileNotFoundError:
            print(f"[!] Skipping missing pairs CSV: {pairs_path}")
            continue

        feats = {}
        feats.update(summary_features(df))
        if feature_mode == 'firstk':
            feats.update(first_k_features(df, k))

        X_rows.append(feats)
        labels.append(label)
        file_paths.append(str(pairs_path))

    X = pd.DataFrame(X_rows)
    # if firstk, make sure columns are ordered consistently
    X = X.fillna(0.0)
    return X, pd.Series(labels), file_paths


def train_and_evaluate(X: pd.DataFrame, y: pd.Series, test_size: float, out_model: Path, random_state: int = 42):
    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, stratify=y_enc, random_state=random_state
    )

    clf = RandomForestClassifier(n_estimators=200, random_state=random_state, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model + encoder + feature names
    out_model = Path(out_model)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({'model': clf, 'label_encoder': le, 'feature_names': list(X.columns)}, out_model)
    print(f"Saved model bundle to: {out_model}")


def parse_args():
    p = argparse.ArgumentParser(description='Build dataset from pairs metadata and train RF')
    p.add_argument('--meta', default='pairs_metadata.csv', help='CSV with columns: label,pcap,pairs_csv')
    p.add_argument('--feature-mode', choices=['summary', 'firstk'], default='summary')
    p.add_argument('--k', type=int, default=50, help='K for firstk features')
    p.add_argument('--test-size', type=float, default=0.2)
    p.add_argument('--out-model', default='rf_model.joblib')
    return p.parse_args()


def main():
    args = parse_args()
    meta_csv = Path(args.meta)
    if not meta_csv.exists():
        print(f"Metadata file not found: {meta_csv}")
        sys.exit(1)

    print(f"Building dataset from metadata: {meta_csv}")
    X, y, files = build_dataset_from_metadata(meta_csv, feature_mode=args.feature_mode, k=args.k)

    print(f"Samples: {len(X)}, Features: {len(X.columns)}")
    print(X.columns.tolist())

    # Optional: simple log1p transform for skewed features
    X_proc = X.replace([np.inf, -np.inf], 0).fillna(0)
    numeric_cols = X_proc.select_dtypes(include=[np.number]).columns
    X_proc[numeric_cols] = np.log1p(X_proc[numeric_cols])

    train_and_evaluate(X_proc, y, test_size=args.test_size, out_model=args.out_model)


if __name__ == '__main__':
    main()