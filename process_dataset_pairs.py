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


def summary_features(df: pd.DataFrame) -> dict:
    # safe conversions
    if df.empty:
        return {
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

    out_bytes = df['out_bytes'].to_numpy(dtype=float)
    in_bytes = df['in_bytes'].to_numpy(dtype=float)
    out_pkts = df['out_pkts'].to_numpy(dtype=float)
    in_pkts = df['in_pkts'].to_numpy(dtype=float)
    out_dur = (df['out_end'] - df['out_start']).to_numpy(dtype=float)
    in_dur = (df['in_end'] - df['in_start']).to_numpy(dtype=float)

    total_out = out_bytes.sum()
    total_in = in_bytes.sum()

    return {
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