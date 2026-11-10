#!/usr/bin/env python3
"""Train RF on CNN's exact signed-packet inputs and save the A/B/C comparison.

python3 train_packet_rf.py --out-dir results/rf_signed_packets_20261025 \
    --model-dir models/rf_signed_packets_20261025
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

from cnn_model import CNNPredictor, encode_sequences
from packet_rf_model import packet_matrix
from packet_sequences import file_hash, load_cache


def matrix_hash(values: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(values).tobytes()).hexdigest()


def save_comparison_figures(comparison: list[dict], labels: list[str], output: Path):
    side = max(5.4, len(labels) * .6 + 3)
    figure = Figure(figsize=(side * len(comparison), side), layout='constrained')
    FigureCanvasAgg(figure)
    axes = figure.subplots(1, len(comparison))
    maximum = max(max(row) for result in comparison for row in result['confusion_matrix'])
    for axis, result in zip(axes, comparison):
        matrix = np.array(result['confusion_matrix'])
        axis.imshow(matrix, cmap='Blues', vmin=0, vmax=maximum)
        axis.set_xticks(range(len(labels)), labels, rotation=60, ha='right', fontsize=8)
        axis.set_yticks(range(len(labels)), labels, fontsize=8)
        axis.set(xlabel='Predicted page', ylabel='True page',
                 title=f'{result["configuration"]}: {result["title"]}\n'
                       f'{result["correct"]}/{result["test_visits"]} correct ({result["accuracy"]:.1%})')
        for (row, column), count in np.ndenumerate(matrix):
            axis.text(column, row, str(count), ha='center', va='center',
                      color='white' if count > maximum / 2 else 'black', fontsize=8)
    figure.suptitle(f'Same {comparison[1]["train_visits"]} training and '
                   f'{comparison[1]["test_visits"]} test visits; B/C share packet values', fontsize=15)
    figure.savefig(output / 'comparison_confusion_matrices.png', dpi=180)
    figure.savefig(output / 'comparison_confusion_matrices.svg')


def run_training(cnn_results_path: Path, rf_results_path: Path, output: Path,
                 model_dir: Path) -> dict:
    if output.exists() or model_dir.exists():
        raise FileExistsError('Choose new output and model directories; completed runs are preserved.')
    cnn_record = json.loads(cnn_results_path.read_text())
    rf_record = json.loads(rf_results_path.read_text())
    cnn = CNNPredictor(cnn_record['model_path'])
    if file_hash(Path(cnn_record['model_path'])) != cnn_record['model_sha256']:
        raise ValueError('CNN checkpoint no longer matches its recorded experiment.')
    cache_path = Path(cnn_record['packet_cache'])
    if file_hash(cache_path) != cnn_record['packet_cache_sha256']:
        raise ValueError('Packet cache no longer matches the CNN experiment.')
    sequences, records, cache_metadata = load_cache(cache_path)
    if (cache_metadata['source_split_sha256'] != cnn_record['outer_split_sha256'] or
            cache_metadata['source_split_sha256'] != rf_record['split_sha256']):
        raise ValueError('RF, CNN and packet cache do not share an outer split.')
    if cnn.preprocessing != cnn_record['preprocessing']:
        raise ValueError('Saved CNN and recorded preprocessing differ.')
    encoder = LabelEncoder().fit(records.label)
    labels = [str(value) for value in encoder.classes_]
    if labels != cnn.labels or labels != rf_record['class_order']:
        raise ValueError('Model class orders differ.')
    y = encoder.transform(records.label)
    # Reconstruct the original RF's fitting order as well as its visit membership,
    # so fixed-seed bootstrap indices refer to the same visits in A and B.
    if 'fit_order' in records:
        train = records[records.split == 'train'].sort_values('fit_order').index.to_numpy()
        if sorted(records.loc[train, 'fit_order'].tolist()) != list(range(len(train))):
            raise ValueError('Saved RF fitting order is incomplete or duplicated.')
        test = records.index[records.split == 'test'].to_numpy()
    else:
        train, test = train_test_split(np.arange(len(records)), test_size=rf_record['test_size'],
                                       stratify=y, random_state=rf_record['random_state'])
    if (set(train) != set(records.index[records.split == 'train']) or
            set(test) != set(records.index[records.split == 'test'])):
        raise ValueError('Reconstructed RF split does not match the saved visits.')
    cnn_predictions = pd.read_csv(cnn_results_path.parent / 'predictions.csv')
    if set(test) != set(cnn_predictions.sample_id):
        raise ValueError('CNN test predictions do not use the same held-out visits.')
    values = packet_matrix(sequences, cnn.preprocessing)
    cnn_values, _ = encode_sequences(sequences, cnn.preprocessing)
    if not np.array_equal(values, cnn_values.numpy()[:, 0, :]):
        raise RuntimeError('RF packet values differ from CNN packet values.')
    input_hash = matrix_hash(values)
    model = RandomForestClassifier(**rf_record['rf_parameters'])
    started = time.perf_counter()
    model.fit(values[train], y[train])
    fit_seconds = time.perf_counter() - started
    predicted = model.predict(values[test])
    probabilities = model.predict_proba(values[test])
    output.mkdir(parents=True)
    model_dir.mkdir(parents=True)
    model_path = model_dir / 'model.joblib'
    joblib.dump({'model_type': 'signed_packet_rf', 'model': model, 'label_encoder': encoder,
                 'preprocessing': cnn.preprocessing, 'feature_names': [
                     f'packet_{index + 1}' for index in range(values.shape[1])],
                 'packet_matrix_sha256': input_hash,
                 'packet_cache_sha256': cnn_record['packet_cache_sha256'],
                 'outer_split_sha256': rf_record['split_sha256'],
                 'score_type': 'mean_tree_probability'}, model_path)
    records['fit_order'] = records.index.map({int(index): order for order, index in enumerate(train)})
    records['used_packets'] = [min(len(sequence), values.shape[1]) for sequence in sequences]
    records['input_row_sha256'] = [matrix_hash(row) for row in values]
    records.to_csv(output / 'split.csv', index=False)
    predictions = []
    for position, index in enumerate(test):
        predictions.append({'sample_id': int(index), 'true_label': labels[y[index]],
                            'predicted_label': labels[predicted[position]],
                            'confidence': float(probabilities[position].max()),
                            'correct': bool(y[index] == predicted[position]),
                            **{f'probability_{labels[value]}': float(probabilities[position, column])
                               for column, value in enumerate(model.classes_)}})
    prediction_table = pd.DataFrame(predictions)
    prediction_table.to_csv(output / 'predictions.csv', index=False)
    result = {
        'experiment': 'RF versus CNN on identical signed-packet inputs',
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'configuration': 'B', 'class_order': labels,
        'train_visits': len(train), 'test_visits': len(test),
        'training_class_counts': dict(Counter(records.iloc[train].label)),
        'test_class_counts': dict(Counter(records.iloc[test].label)),
        'correct': int(np.count_nonzero(predicted == y[test])),
        'accuracy': float(accuracy_score(y[test], predicted)),
        'macro_f1': float(f1_score(y[test], predicted, average='macro', zero_division=0)),
        'training_accuracy': float(model.score(values[train], y[train])),
        'confusion_matrix': confusion_matrix(y[test], predicted, labels=range(len(labels))).tolist(),
        'per_class': classification_report(y[test], predicted, labels=range(len(labels)),
                                           target_names=labels, output_dict=True, zero_division=0),
        'fit_seconds': fit_seconds, 'rf_parameters': model.get_params(),
        'preprocessing': cnn.preprocessing, 'input_features': values.shape[1],
        'input_dtype': str(values.dtype), 'packet_matrix_sha256': input_hash,
        'cnn_input_values_identical': True, 'extra_features': [], 'log1p_applied': False,
        'packet_cache': str(cache_path), 'packet_cache_sha256': file_hash(cache_path),
        'outer_split_sha256': rf_record['split_sha256'],
        'cnn_reference': str(cnn_results_path), 'cnn_reference_sha256': file_hash(cnn_results_path),
        'rf_reference': str(rf_results_path), 'rf_reference_sha256': file_hash(rf_results_path),
        'model_path': str(model_path), 'model_sha256': file_hash(model_path),
        'score_type': 'mean_tree_probability', 'acceptance_threshold_applied': False,
        'versions': {'python': platform.python_version(), 'numpy': np.__version__,
                     'pandas': pd.__version__, 'sklearn': sklearn.__version__, 'joblib': joblib.__version__},
        'source_sha256': {name: file_hash(Path(__file__).parent / name) for name in (
            'train_packet_rf.py', 'packet_rf_model.py', 'cnn_model.py', 'packet_sequences.py')},
        'limitations': [
            'Single fixed split and seed; no statistical significance or universal model ranking.',
            'RF uses flattened packet positions; CNN uses convolutions and masks padding.',
            'A/B fix RF settings including sqrt max_features, whose candidate count depends on input width.',
            'CNN used internal validation for epoch selection; RF parameters remain fixed.',
            'No fresh GUI captures, unknown-page rejection or acceptance-threshold tuning.',
        ],
    }
    paired = prediction_table.set_index('sample_id').join(
        cnn_predictions.set_index('sample_id')[['predicted_label', 'correct']], rsuffix='_cnn')
    result['paired_with_cnn'] = {
        'both_correct': int((paired.correct & paired.correct_cnn).sum()),
        'rf_only_correct': int((paired.correct & ~paired.correct_cnn).sum()),
        'cnn_only_correct': int((~paired.correct & paired.correct_cnn).sum()),
        'both_incorrect': int((~paired.correct & ~paired.correct_cnn).sum()),
        'different_top_labels': int((paired.predicted_label != paired.predicted_label_cnn).sum()),
    }
    comparison = [
        {'configuration': 'A', 'title': 'RF: engineered features', **rf_record['variants']['baseline']},
        {'configuration': 'B', 'title': 'RF: signed packet sizes', **result},
        {'configuration': 'C', 'title': 'CNN: signed packet sizes', **{
            key: cnn_record[key] for key in ('correct', 'accuracy', 'macro_f1', 'confusion_matrix',
                                           'test_visits')}},
    ]
    result['comparison'] = [{key: row[key] for key in (
        'configuration', 'title', 'correct', 'accuracy', 'macro_f1', 'confusion_matrix')}
        for row in comparison]
    (output / 'results.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    pd.DataFrame([{key: row[key] for key in ('configuration', 'title', 'correct', 'accuracy', 'macro_f1')}
                  for row in comparison]).to_csv(output / 'comparison.csv', index=False)
    save_comparison_figures(comparison, labels, output)
    print(f'RF packet sequence: {result["correct"]}/{len(test)} correct; '
          f'accuracy={result["accuracy"]:.4f}; macro-F1={result["macro_f1"]:.4f}; '
          f'fit={fit_seconds:.3f}s', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cnn-results', type=Path,
                        default=Path('results/cnn_signed_packets_20261025/results.json'))
    parser.add_argument('--rf-results', type=Path,
                        default=Path('results/rf_feature_removal_20261025/results.json'))
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--model-dir', type=Path, required=True)
    args = parser.parse_args()
    run_training(args.cnn_results, args.rf_results, args.out_dir, args.model_dir)
