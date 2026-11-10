#!/usr/bin/env python3
"""Compare RF feature removals on one shared, stratified offline split.

Run from the project directory:
    python3 run_rf_ablation.py --out-dir results/rf_feature_removal_20261025

Reads existing pair CSVs without modifying them. Saves selected research outputs
in --out-dir and separate model bundles under models/<output directory name>/.
An existing output directory is never overwritten. No GUI acceptance rule is used.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

import joblib
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from process_dataset_pairs import extract_ngram_features, summary_features


PAIR_COLUMNS = ('out_bytes', 'in_bytes', 'out_pkts', 'in_pkts',
                'out_start', 'out_end', 'in_start', 'in_end')
SIZE_FEATURES = (
    'total_out_bytes', 'total_in_bytes', 'mean_out_bytes', 'mean_in_bytes',
    'std_out_bytes', 'std_in_bytes', 'ratio_out_in_bytes',
    *extract_ngram_features(pd.DataFrame()).keys(),
)
REMOVALS = {
    'baseline': (),
    'without_size': SIZE_FEATURES,
    'without_duration': ('mean_out_dur', 'mean_in_dur'),
    'without_packet_count': ('mean_out_pkts', 'mean_in_pkts'),
}
TITLES = {
    'baseline': 'All features', 'without_size': 'Without byte-size features',
    'without_duration': 'Without duration features',
    'without_packet_count': 'Without packets-per-burst counts',
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_visits(metadata_path: Path) -> tuple[pd.DataFrame, list[pd.DataFrame]]:
    """Preserve metadata row order and fail rather than silently skipping visits."""
    metadata = pd.read_csv(metadata_path, dtype=str, keep_default_na=False)
    required = {'label', 'pcap', 'pairs_csv'}
    if not required.issubset(metadata.columns):
        raise ValueError('Metadata must contain label, pcap and pairs_csv columns.')
    if metadata.empty or (metadata[list(required)] == '').any().any():
        raise ValueError('Metadata must contain visits with nonempty labels and paths.')
    frames, records, seen = [], [], set()
    for sample_id, row in metadata.iterrows():
        path = Path(row['pairs_csv']).expanduser()
        if not path.is_absolute() and not path.is_file():
            path = metadata_path.parent / path
        path = path.resolve()
        if path in seen:
            raise ValueError(f'Duplicate pair CSV would leak a visit across the split: {path}')
        seen.add(path)
        content_hash = sha256(path)
        frame = pd.read_csv(path)
        if frame.empty or not set(PAIR_COLUMNS).issubset(frame.columns):
            raise ValueError(f'Empty or incompatible pair CSV: {path}')
        numeric = frame[list(PAIR_COLUMNS)].apply(pd.to_numeric, errors='raise')
        if not np.isfinite(numeric.to_numpy()).all() or (numeric < 0).any().any():
            raise ValueError(f'Nonfinite or negative pair values: {path}')
        if ((numeric.out_end < numeric.out_start).any()
                or (numeric.in_end < numeric.in_start).any()):
            raise ValueError(f'Burst ends before it starts: {path}')
        frames.append(numeric)
        records.append({'sample_id': int(sample_id), 'label': row['label'],
                        'pcap': row['pcap'], 'pairs_csv': row['pairs_csv'],
                        'resolved_pairs_csv': str(path), 'pairs_sha256': content_hash,
                        'burst_pairs': len(frame)})
    return pd.DataFrame(records), frames


def fit_byte_thresholds(frames: list[pd.DataFrame], train_indices) -> dict:
    """Pool only training visits, matching the existing median threshold rule."""
    return {name: float(np.median(np.concatenate([
        frames[index][name].to_numpy(dtype=float) for index in train_indices])))
        for name in ('out_bytes', 'in_bytes')}


def feature_table(frames: list[pd.DataFrame], thresholds: dict) -> pd.DataFrame:
    return pd.DataFrame([summary_features(
        frame, out_small_threshold=thresholds['out_bytes'],
        in_small_threshold=thresholds['in_bytes']) for frame in frames])


def select_features(features: pd.DataFrame, variant: str) -> pd.DataFrame:
    """Explicit removal lists are also saved in the results and model bundles."""
    return features.drop(columns=list(REMOVALS[variant]))


def resolve_split(visits: pd.DataFrame, y, test_size: float, seed: int,
                  split_path: Path | None = None):
    """Use a predeclared holdout when supplied, including a shared fitting order."""
    if split_path is None:
        return train_test_split(np.arange(len(visits)), test_size=test_size,
                                stratify=y, random_state=seed)
    assignments = pd.read_csv(split_path)
    if (len(assignments) != len(visits) or
            assignments.sample_id.tolist() != visits.sample_id.tolist() or
            assignments.label.tolist() != visits.label.tolist() or
            assignments.pcap.tolist() != visits.pcap.tolist() or
            set(assignments.split) != {'train', 'test'}):
        raise ValueError('Predeclared split must match every metadata visit in row order.')
    train = assignments.index[assignments.split == 'train'].to_numpy()
    test = assignments.index[assignments.split == 'test'].to_numpy()
    # Deterministic fitting order is shared by the engineered and packet RFs.
    train = np.random.default_rng(seed).permutation(train)
    if (set(visits.iloc[train].label) != set(visits.label) or
            set(visits.iloc[test].label) != set(visits.label)):
        raise ValueError('Every label must occur in both training and test sets.')
    return train, test


def save_confusion_figures(results: dict, labels: list[str], output: Path) -> None:
    side = max(12, len(labels) * .8 + 10)
    figure = Figure(figsize=(side, side), layout='constrained')
    FigureCanvasAgg(figure)
    axes = figure.subplots(2, 2)
    maximum = max(max(row) for result in results.values() for row in result['confusion_matrix'])
    for axis, (variant, result) in zip(axes.flat, results.items()):
        matrix = np.array(result['confusion_matrix'])
        axis.imshow(matrix, cmap='Blues', vmin=0, vmax=maximum)
        axis.set_xticks(range(len(labels)), labels, rotation=60, ha='right', fontsize=8)
        axis.set_yticks(range(len(labels)), labels, fontsize=8)
        axis.set_xlabel('Predicted page')
        axis.set_ylabel('True page')
        axis.set_title(f'{TITLES[variant]}\n{result["correct"]}/{result["test_visits"]} correct '
                       f'({result["accuracy"]:.1%})')
        for (row, column), count in np.ndenumerate(matrix):
            axis.text(column, row, str(count), ha='center', va='center',
                      color='white' if count > maximum / 2 else 'black', fontsize=8)
    figure.suptitle('RF feature removal — same held-out visits for every model', fontsize=15)
    figure.savefig(output / 'confusion_matrices.png', dpi=180)
    figure.savefig(output / 'confusion_matrices.svg')


def run_experiment(metadata_path: Path, output: Path, model_dir: Path, *,
                   test_size: float = .2, seed: int = 42, trees: int = 200,
                   split_path: Path | None = None) -> dict:
    if output.exists() or model_dir.exists():
        raise FileExistsError('Choose new results and model directories; existing runs are preserved.')
    if not 0 < test_size < 1 or trees < 1:
        raise ValueError('test_size must be between 0 and 1, and trees must be positive.')
    metadata_path = metadata_path.resolve()
    metadata_hash = sha256(metadata_path)
    visits, frames = load_visits(metadata_path)
    encoder = LabelEncoder().fit(visits.label)
    y = encoder.transform(visits.label)
    indices = np.arange(len(visits))
    train, test = resolve_split(visits, y, test_size, seed, split_path)
    thresholds = fit_byte_thresholds(frames, train)
    features = feature_table(frames, thresholds)
    labels = [str(label) for label in encoder.classes_]
    visits['split'] = ['train' if index in set(train) else 'test' for index in indices]
    visits['fit_order'] = visits.index.map({int(index): order for order, index in enumerate(train)})
    output.mkdir(parents=True)
    model_dir.mkdir(parents=True)
    visits.to_csv(output / 'split.csv', index=False)
    predictions, results = [], {}
    for variant in REMOVALS:
        selected = select_features(features, variant)
        X = np.log1p(selected.replace([np.inf, -np.inf], 0).fillna(0))
        model = RandomForestClassifier(n_estimators=trees, random_state=seed, n_jobs=-1)
        started = time.perf_counter()
        model.fit(X.iloc[train], y[train])
        fit_seconds = time.perf_counter() - started
        predicted = model.predict(X.iloc[test])
        probabilities = model.predict_proba(X.iloc[test])
        model_path = model_dir / f'{variant}.joblib'
        joblib.dump({
            'model': model, 'label_encoder': encoder, 'feature_names': list(selected.columns),
            'burst_size_thresholds': thresholds, 'feature_variant': variant,
            'removed_features': list(REMOVALS[variant]), 'preprocessing': 'log1p',
            'metadata_sha256': metadata_hash, 'split_sha256': sha256(output / 'split.csv'),
        }, model_path)
        correct = int(np.count_nonzero(predicted == y[test]))
        results[variant] = {
            'features': len(selected.columns), 'retained_features': list(selected.columns),
            'removed_features': list(REMOVALS[variant]),
            'train_visits': len(train), 'test_visits': len(test), 'correct': correct,
            'accuracy': float(accuracy_score(y[test], predicted)),
            'macro_f1': float(f1_score(y[test], predicted, labels=range(len(labels)),
                                       average='macro', zero_division=0)),
            'training_accuracy': float(model.score(X.iloc[train], y[train])),
            'fit_seconds': fit_seconds,
            'confusion_matrix': confusion_matrix(y[test], predicted, labels=range(len(labels))).tolist(),
            'per_class': classification_report(y[test], predicted, labels=range(len(labels)),
                                               target_names=labels, output_dict=True, zero_division=0),
            'model_path': str(model_path), 'model_sha256': sha256(model_path),
        }
        for position, index in enumerate(test):
            predictions.append({
                'variant': variant, 'sample_id': int(index), 'true_label': labels[y[index]],
                'predicted_label': labels[predicted[position]],
                'confidence': float(probabilities[position].max()),
                'correct': bool(predicted[position] == y[index]),
                **{f'probability_{labels[value]}': float(probabilities[position, column])
                   for column, value in enumerate(model.classes_)},
            })
        print(f'{variant:24} {len(selected.columns):2} features  '
              f'{correct}/{len(test)} correct  accuracy={results[variant]["accuracy"]:.4f}  '
              f'macro-F1={results[variant]["macro_f1"]:.4f}', flush=True)
    baseline = results['baseline']['accuracy']
    summary = []
    for variant, result in results.items():
        result['accuracy_change_pp'] = 100 * (result['accuracy'] - baseline)
        summary.append({'variant': variant, **{key: result[key] for key in (
            'features', 'train_visits', 'test_visits', 'correct', 'accuracy',
            'accuracy_change_pp', 'macro_f1', 'training_accuracy', 'fit_seconds')}})
    # Confirm that the run did not modify its metadata or processed input traces.
    if sha256(metadata_path) != metadata_hash or any(
            sha256(Path(row.resolved_pairs_csv)) != row.pairs_sha256
            for row in visits.itertuples()):
        raise RuntimeError('An input file changed during the experiment; do not use these results.')
    payload = {
        'experiment': 'RF grouped feature removal, offline held-out evaluation',
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'metadata': str(metadata_path), 'metadata_sha256': metadata_hash,
        'split_sha256': sha256(output / 'split.csv'), 'visits': len(visits),
        'class_counts': dict(Counter(visits.label)),
        'training_class_counts': dict(Counter(visits.iloc[train].label)),
        'test_class_counts': dict(Counter(visits.iloc[test].label)),
        'class_order': labels, 'random_state': seed, 'test_size': len(test) / len(visits),
        'predeclared_split': str(split_path) if split_path else None,
        'predeclared_split_sha256': sha256(split_path) if split_path else None,
        'rf_parameters': model.get_params(), 'preprocessing': 'log1p',
        'threshold_fit': 'Medians pooled over burst pairs from training visits only',
        'burst_size_thresholds': thresholds, 'acceptance_threshold_applied': False,
        'input_files_unchanged': True,
        'versions': {'python': platform.python_version(), 'numpy': np.__version__,
                     'pandas': pd.__version__, 'scikit_learn': sklearn.__version__,
                     'joblib': joblib.__version__},
        'source_sha256': {name: sha256(Path(__file__).parent / name) for name in (
            'run_rf_ablation.py', 'process_dataset_pairs.py')},
        'variants': results,
        'limitations': [
            'One split and one RF seed; small differences are descriptive, not significance claims.',
            'Without duration retains timing-dependent burst boundaries.',
            'Without packet count removes two mean packet-count features; other volume correlates remain.',
            'Without size also removes size-derived order patterns; groups are not independent.',
            'RF max_features remains sqrt; the number considered per split varies with feature count.',
            'Held-out visits come from the same collection; no fresh GUI or unknown-page evaluation.',
        ],
    }
    (output / 'results.json').write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n')
    pd.DataFrame(summary).to_csv(output / 'summary.csv', index=False)
    pd.DataFrame(predictions).to_csv(output / 'predictions.csv', index=False)
    save_confusion_figures(results, labels, output)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--meta', type=Path, default=Path('pairs_metadata.csv'))
    parser.add_argument('--out-dir', type=Path, default=Path('results/rf_feature_removal'))
    parser.add_argument('--model-dir', type=Path)
    parser.add_argument('--test-size', type=float, default=.2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--split', type=Path, help='Predeclared assignments in metadata row order')
    args = parser.parse_args()
    model_dir = args.model_dir or Path('models') / args.out_dir.name
    run_experiment(args.meta, args.out_dir, model_dir, test_size=args.test_size,
                   seed=args.seed, split_path=args.split)


if __name__ == '__main__':
    main()
