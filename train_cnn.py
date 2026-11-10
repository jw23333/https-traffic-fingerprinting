#!/usr/bin/env python3
"""Select a packet CNN on development data, refit, then evaluate the held-out visits.

python3 train_cnn.py --cache models/cnn_signed_packets_20261025/packet_sequences.npz \
    --out-dir results/cnn_signed_packets_20261025 --model-dir models/cnn_signed_packets_20261025
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import random
import time

from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, log_loss
from sklearn.model_selection import train_test_split
import torch
from torch import nn

from cnn_model import ARCHITECTURE, PacketCNN, encode_sequences, fit_preprocessing
from packet_sequences import file_hash, load_cache


def seed_everything(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


def split_development(records: pd.DataFrame, seed: int, validation_per_class: int):
    development = records.index[records.split == 'train'].to_numpy()
    test = records.index[records.split == 'test'].to_numpy()
    classes = sorted(records.label.unique())
    fit, validation = train_test_split(
        development, test_size=len(classes) * validation_per_class,
        stratify=records.iloc[development].label, random_state=seed)
    if set(fit) & set(validation) or set(development) & set(test):
        raise ValueError('Overlapping split assignments.')
    return fit, validation, development, test


def evaluate(model, values, lengths, labels, indices, batch_size=16):
    model.eval()
    indices = torch.tensor(indices, dtype=torch.long)
    logits = []
    with torch.inference_mode():
        for start in range(0, len(indices), batch_size):
            batch = indices[start:start + batch_size]
            logits.append(model(values[batch], lengths[batch]))
    logits = torch.cat(logits)
    loss = float(nn.functional.cross_entropy(logits, labels[indices]))
    probabilities = logits.softmax(dim=1).numpy()
    predicted = probabilities.argmax(axis=1)
    return {'loss': loss, 'accuracy': float(np.mean(predicted == labels[indices].numpy())),
            'probabilities': probabilities, 'predicted': predicted}


def train_epoch(model, optimizer, values, lengths, labels, indices, batch_size, generator):
    model.train()
    order = torch.tensor(indices)[torch.randperm(len(indices), generator=generator)]
    loss_sum, correct = 0., 0
    for start in range(0, len(order), batch_size):
        batch = order[start:start + batch_size]
        optimizer.zero_grad(set_to_none=True)
        logits = model(values[batch], lengths[batch])
        loss = nn.functional.cross_entropy(logits, labels[batch])
        if not torch.isfinite(loss):
            raise RuntimeError('Training loss became nonfinite.')
        loss.backward()
        optimizer.step()
        loss_sum += float(loss.detach()) * len(batch)
        correct += int((logits.detach().argmax(1) == labels[batch]).sum())
    return loss_sum / len(indices), correct / len(indices)


def checkpoint(model, labels, preprocessing, training):
    return {'format_version': 1, 'model_type': 'signed_packet_cnn',
            'architecture': dict(ARCHITECTURE), 'labels': labels,
            'preprocessing': preprocessing, 'training': training,
            'state_dict': model.state_dict(), 'score_type': 'uncalibrated_softmax'}


def save_figures(history: pd.DataFrame, matrix: np.ndarray, labels: list[str], output: Path):
    figure = Figure(figsize=(11, 4), layout='constrained')
    FigureCanvasAgg(figure)
    axes = figure.subplots(1, 2)
    for phase, title in [('fit', 'Training'), ('validation', 'Validation')]:
        key = 'train' if phase == 'fit' else phase
        axes[0].plot(history.epoch, history[f'{key}_loss'], label=title)
        axes[1].plot(history.epoch, history[f'{key}_accuracy'], label=title)
    axes[0].set(xlabel='Epoch', ylabel='Cross-entropy loss', title='Development model selection')
    axes[1].set(xlabel='Epoch', ylabel='Accuracy', ylim=(0, 1.03), title='Development accuracy')
    for axis in axes:
        axis.legend()
        axis.grid(alpha=.2)
    for suffix in ('png', 'svg'):
        figure.savefig(output / f'learning_curves.{suffix}', dpi=180)
    side = max(7, len(labels) * .55 + 3)
    figure = Figure(figsize=(side, side), layout='constrained')
    FigureCanvasAgg(figure)
    axis = figure.subplots()
    maximum = int(matrix.max())
    axis.imshow(matrix, cmap='Blues', vmin=0, vmax=max(1, maximum))
    axis.set_xticks(range(len(labels)), labels, rotation=60, ha='right', fontsize=8)
    axis.set_yticks(range(len(labels)), labels, fontsize=8)
    axis.set(xlabel='Predicted page', ylabel='True page', title='CNN: final model on held-out visits')
    for (row, column), count in np.ndenumerate(matrix):
        axis.text(column, row, str(count), ha='center', va='center',
                  color='white' if count > maximum / 2 else 'black', fontsize=8)
    for suffix in ('png', 'svg'):
        figure.savefig(output / f'confusion_matrix.{suffix}', dpi=180)


def run_training(cache_path: Path, output: Path, model_dir: Path, *, seed: int = 42,
                 validation_per_class: int = 11, max_epochs: int = 100,
                 patience: int = 10, batch_size: int = 16, threads: int = 4,
                 preprocessing_reference: Path | None = None) -> dict:
    if output.exists() or (model_dir / 'final.pt').exists() or (model_dir / 'selection_best.pt').exists():
        raise FileExistsError('Choose fresh output/model paths; completed runs are never overwritten.')
    if min(validation_per_class, max_epochs, patience, batch_size, threads) < 1:
        raise ValueError('Training settings must be positive.')
    torch.set_num_threads(threads)
    seed_everything(seed)
    sequences, records, cache_metadata = load_cache(cache_path)
    fit, validation, development, test = split_development(records, seed, validation_per_class)
    labels = sorted(str(label) for label in records.label.unique())
    y = torch.tensor([labels.index(label) for label in records.label], dtype=torch.long)
    preprocessing_source = None
    preprocessing_fit_visits = len(fit)
    if preprocessing_reference is None:
        preprocessing = fit_preprocessing(sequences, fit)
    else:
        reference = json.loads(preprocessing_reference.read_text())
        if file_hash(Path(reference['model_path'])) != reference['model_sha256']:
            raise ValueError('Preprocessing reference model has changed.')
        original = pd.read_csv(reference['outer_split'])
        previous_paths = {str(Path(path).resolve()) for path in original.pcap}
        if previous_paths & {str(Path(path).resolve()) for path in records.iloc[test].pcap}:
            raise ValueError('Frozen preprocessing reference overlaps the new test visits.')
        preprocessing = reference['preprocessing']
        preprocessing_fit_visits = reference['preprocessing_fit_visits']
        preprocessing_source = {'results': str(preprocessing_reference),
                                'sha256': file_hash(preprocessing_reference),
                                'policy': 'Frozen before expanded-data holdout selection'}
    values, lengths = encode_sequences(sequences, preprocessing)
    print(f'Development selection: {len(fit)} fit / {len(validation)} validation; '
          f'final refit: {len(development)}; held out: {len(test)}', flush=True)
    print(f'Input length: {preprocessing["sequence_length"]}; size scale: '
          f'{preprocessing["size_scale"]}; CPU threads: {threads}', flush=True)
    records['selection_split'] = ['fit' if index in set(fit) else
                                  'validation' if index in set(validation) else 'test'
                                  for index in records.index]
    records['used_packets'] = lengths.numpy()
    records['truncated_packets'] = records.packet_count - records.used_packets
    output.mkdir(parents=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    records.to_csv(output / 'split.csv', index=False)
    history, best_loss, best_epoch, stale = [], float('inf'), 0, 0
    training_config = {'seed': seed, 'batch_size': batch_size, 'optimizer': 'Adam',
                       'learning_rate': .001, 'weight_decay': .0001,
                       'max_epochs': max_epochs, 'patience': patience, 'min_delta': .0001,
                       'device': 'cpu', 'threads': threads, 'deterministic_algorithms': True}
    model = PacketCNN(len(labels), **ARCHITECTURE)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001, weight_decay=.0001)
    generator = torch.Generator().manual_seed(seed)
    started = time.perf_counter()
    for epoch in range(1, max_epochs + 1):
        loss, accuracy = train_epoch(model, optimizer, values, lengths, y, fit, batch_size, generator)
        valid = evaluate(model, values, lengths, y, validation, batch_size)
        history.append({'epoch': epoch, 'train_loss': loss, 'train_accuracy': accuracy,
                        'validation_loss': valid['loss'], 'validation_accuracy': valid['accuracy']})
        if valid['loss'] < best_loss - .0001:
            best_loss, best_epoch, stale = valid['loss'], epoch, 0
            torch.save(checkpoint(model, labels, preprocessing,
                                  {**training_config, 'phase': 'selection', 'fit_visits': len(fit),
                                   'epoch': epoch, 'validation_loss': best_loss}),
                       model_dir / 'selection_best.pt')
        else:
            stale += 1
        if epoch == 1 or epoch % 5 == 0 or stale >= patience:
            print(f'Select epoch {epoch:3}: train loss={loss:.4f}, '
                  f'validation loss={valid["loss"]:.4f}, accuracy={valid["accuracy"]:.1%}', flush=True)
        if stale >= patience:
            break
    selection_seconds = time.perf_counter() - started
    pd.DataFrame(history).to_csv(output / 'selection_history.csv', index=False)
    # The held-out test set has not been evaluated. Freeze the selected epoch and
    # preprocessing, then refit from the same initial seed on all development visits.
    seed_everything(seed)
    model = PacketCNN(len(labels), **ARCHITECTURE)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001, weight_decay=.0001)
    generator = torch.Generator().manual_seed(seed)
    refit_history = []
    print(f'Validation selected {best_epoch} epochs. Refitting on all {len(development)} visits.', flush=True)
    started = time.perf_counter()
    for epoch in range(1, best_epoch + 1):
        loss, accuracy = train_epoch(model, optimizer, values, lengths, y, development,
                                     batch_size, generator)
        refit_history.append({'epoch': epoch, 'train_loss': loss, 'train_accuracy': accuracy})
        if epoch == 1 or epoch % 10 == 0 or epoch == best_epoch:
            print(f'Refit epoch {epoch:3}: train loss={loss:.4f}, accuracy={accuracy:.1%}', flush=True)
    refit_seconds = time.perf_counter() - started
    pd.DataFrame(refit_history).to_csv(output / 'refit_history.csv', index=False)
    final_path = model_dir / 'final.pt'
    torch.save(checkpoint(model, labels, preprocessing,
                          {**training_config, 'phase': 'final_refit', 'fit_visits': len(development),
                           'epochs': best_epoch, 'packet_cache_sha256': file_hash(cache_path),
                           'outer_split_sha256': cache_metadata['source_split_sha256']}), final_path)
    # Only the final refit model is evaluated on the original held-out test visits.
    testing = evaluate(model, values, lengths, y, test, batch_size)
    training = evaluate(model, values, lengths, y, development, batch_size)
    predicted, probabilities = testing['predicted'], testing['probabilities']
    expected = y[test].numpy()
    matrix = confusion_matrix(expected, predicted, labels=range(len(labels)))
    predictions = []
    for position, index in enumerate(test):
        predictions.append({'sample_id': int(records.iloc[index].sample_id),
                            'true_label': labels[expected[position]],
                            'predicted_label': labels[predicted[position]],
                            'confidence': float(probabilities[position].max()),
                            'correct': bool(expected[position] == predicted[position]),
                            **{f'probability_{label}': float(probabilities[position, column])
                               for column, label in enumerate(labels)}})
    pd.DataFrame(predictions).to_csv(output / 'predictions.csv', index=False)
    class_report = classification_report(expected, predicted, labels=range(len(labels)),
                                         target_names=labels, output_dict=True, zero_division=0)
    best_row = history[best_epoch - 1]
    payload = {
        'experiment': 'Compact CNN on signed packet-size sequences',
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'class_order': labels, 'class_counts': dict(Counter(records.label)),
        'fit_class_counts': dict(Counter(records.iloc[fit].label)),
        'validation_class_counts': dict(Counter(records.iloc[validation].label)),
        'test_class_counts': dict(Counter(records.iloc[test].label)),
        'selection_fit_visits': len(fit), 'validation_visits': len(validation),
        'final_fit_visits': len(development), 'test_visits': len(test),
        'outer_split': cache_metadata['source_split'],
        'outer_split_sha256': cache_metadata['source_split_sha256'],
        'packet_cache': str(cache_path), 'packet_cache_sha256': file_hash(cache_path),
        'preprocessing': preprocessing, 'preprocessing_fit_visits': preprocessing_fit_visits,
        'preprocessing_reference': preprocessing_source,
        'architecture': dict(ARCHITECTURE),
        'parameter_count': sum(parameter.numel() for parameter in model.parameters()),
        'training': training_config, 'selection_epochs_run': len(history),
        'selected_epochs': best_epoch, 'selected_validation_loss': best_loss,
        'selected_validation_accuracy': best_row['validation_accuracy'],
        'selection_seconds': selection_seconds, 'refit_seconds': refit_seconds,
        'selection_optimizer_updates': len(history) * int(np.ceil(len(fit) / batch_size)),
        'refit_optimizer_updates': best_epoch * int(np.ceil(len(development) / batch_size)),
        'correct': int(np.count_nonzero(expected == predicted)),
        'accuracy': float(accuracy_score(expected, predicted)),
        'macro_f1': float(f1_score(expected, predicted, average='macro', zero_division=0)),
        'test_cross_entropy': testing['loss'],
        'test_log_loss': float(log_loss(expected, probabilities, labels=range(len(labels)))),
        'final_training_accuracy': training['accuracy'],
        'confusion_matrix': matrix.tolist(), 'per_class': class_report,
        'model_path': str(final_path), 'model_sha256': file_hash(final_path),
        'selection_checkpoint': str(model_dir / 'selection_best.pt'),
        'score_type': 'uncalibrated_softmax', 'acceptance_threshold_applied': False,
        'truncation': {phase: {
            'visits': len(subset),
            'truncated_visits': int((subset.truncated_packets > 0).sum()),
            'packets_removed': int(subset.truncated_packets.sum()),
            'packet_count_min': int(subset.packet_count.min()),
            'packet_count_max': int(subset.packet_count.max()),
        } for phase, subset in records.groupby('selection_split')},
        'versions': {'python': platform.python_version(), 'torch': str(torch.__version__),
                     'numpy': np.__version__, 'pandas': pd.__version__, 'sklearn': sklearn.__version__},
        'source_sha256': {name: file_hash(Path(__file__).parent / name) for name in
                          ('train_cnn.py', 'cnn_model.py', 'packet_sequences.py', 'process_pcap.py')},
        'limitations': [
            'One split and seed; test visits are shared with RF, not a GUI evaluation.',
            'RF engineered inputs and CNN packet sequences differ; this compares complete approaches.',
            'Softmax scores are uncalibrated and not numerically interchangeable with RF scores.',
            'Packet filtering and compact architecture adapt prior work; this is not a full DF reproduction.',
            'No fresh GUI capture or unknown-page rejection evaluation in this training experiment.',
        ],
    }
    (output / 'results.json').write_text(json.dumps(payload, indent=2, allow_nan=False) + '\n')
    pd.DataFrame([{key: payload[key] for key in ('correct', 'test_visits', 'accuracy', 'macro_f1',
                                                'selected_epochs', 'selection_seconds', 'refit_seconds')}]
                 ).to_csv(output / 'summary.csv', index=False)
    save_figures(pd.DataFrame(history), matrix, labels, output)
    print(f'Final test: {payload["correct"]}/{len(test)} correct, '
          f'accuracy={payload["accuracy"]:.4f}, macro-F1={payload["macro_f1"]:.4f}', flush=True)
    return payload


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--model-dir', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--max-epochs', type=int, default=100)
    parser.add_argument('--patience', type=int, default=10)
    parser.add_argument('--threads', type=int, default=4)
    parser.add_argument('--validation-per-class', type=int, default=11)
    parser.add_argument('--preprocessing-reference', type=Path,
                        help='Prior CNN results JSON whose input length/scale remain fixed')
    args = parser.parse_args()
    run_training(args.cache, args.out_dir, args.model_dir, seed=args.seed,
                 max_epochs=args.max_epochs, patience=args.patience, threads=args.threads,
                 validation_per_class=args.validation_per_class,
                 preprocessing_reference=args.preprocessing_reference)
