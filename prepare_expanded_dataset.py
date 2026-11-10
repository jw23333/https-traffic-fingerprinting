#!/usr/bin/env python3
"""Prepare expanded captures without overwriting the original research inputs.

Infer capture-time client addresses per PCAP. Reserve test visits only from the
new captures, since the original benchmark has already informed model choices.
The output directory holds processed training inputs, not collection diaries.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
from pathlib import Path

import numpy as np
import pandas as pd

from collect_dataset import SITES, sanitize_name
from packet_sequences import file_hash, infer_client_ips, signed_sequence
from process_pcap import build_capture_data, run_tshark_fields, write_pairs_csv
from run_rf_ablation import PAIR_COLUMNS


LABELS = tuple(sanitize_name(url) for url in SITES)


def declare_holdout(records: pd.DataFrame, previous_pcaps: set[str],
                    test_per_class: int, seed: int) -> pd.DataFrame:
    """Freeze balanced new-only test membership before looking at model results."""
    if test_per_class < 1:
        raise ValueError('At least one test visit per page is required.')
    result = records.copy()
    result['sample_id'] = np.arange(len(result))
    result['collection_group'] = ['original' if str(Path(path).resolve()) in previous_pcaps
                                  else 'additional' for path in result.pcap]
    result['split'] = 'train'
    rng = np.random.default_rng(seed)
    for label in sorted(result.label.unique()):
        candidates = result.index[(result.label == label) &
                                   (result.collection_group == 'additional')].to_numpy()
        if len(candidates) <= test_per_class:
            raise ValueError(f'Not enough additional training/test visits for {label}.')
        result.loc[rng.choice(candidates, size=test_per_class, replace=False), 'split'] = 'test'
    return result


def reconstruct_visit(record: dict, *, include_sequence: bool = False):
    path = Path(record['pcap'])
    rows = run_tshark_fields(str(path), include_ports=True)
    capture = build_capture_data(rows, infer_client_ips(rows))
    sequence = signed_sequence(capture.packets)
    if not capture.pairs or not np.any(sequence > 0) or not np.any(sequence < 0):
        raise ValueError(f'Capture lacks bidirectional burst-pair traffic: {path}')
    original_pairs = record.get('original_pairs')
    if original_pairs:
        expected = pd.read_csv(original_pairs)
        actual = pd.DataFrame(capture.pairs)
        if len(actual) != len(expected) or not np.allclose(
                actual[list(PAIR_COLUMNS)], expected[list(PAIR_COLUMNS)], rtol=0, atol=1e-9):
            raise ValueError(f'Historical direction/pairs changed: {path}')
    out = Path(record['pairs_csv'])
    out.parent.mkdir(parents=True, exist_ok=True)
    write_pairs_csv(capture.pairs, out)
    details = {key: record[key] for key in ('label', 'pcap', 'pairs_csv')} | {
        'pcap_sha256': file_hash(path), 'packet_count': len(sequence),
        'pairs_sha256': file_hash(out), 'outgoing_packets': int(np.count_nonzero(sequence > 0)),
        'incoming_packets': int(np.count_nonzero(sequence < 0)),
        'burst_pairs': len(capture.pairs), 'original_pairs_verified': bool(original_pairs)}
    return (details, sequence) if include_sequence else details


def prepare(raw_dir: Path, previous_metadata: Path | None, output: Path, *,
            visits_per_class: int = 200, test_per_class: int = 40,
            seed: int = 42, workers: int = 4, labels=None):
    if output.exists():
        raise FileExistsError(f'Choose a new input directory: {output}')
    labels = LABELS if labels is None else tuple(labels)
    if not labels or len(set(labels)) != len(labels) or not set(labels).issubset(LABELS):
        raise ValueError('Choose distinct labels from the configured monitored pages.')
    previous_paths = {}
    if previous_metadata is not None:
        previous = pd.read_csv(previous_metadata)
        previous_paths = {str(Path(row.pcap).resolve()): str(Path(row.pairs_csv).resolve())
                          for row in previous.itertuples()}
    records = []
    for label in labels:
        files = sorted((raw_dir / label).glob('*.pcap'))
        if len(files) != visits_per_class:
            raise ValueError(f'{label}: expected exactly {visits_per_class}, found {len(files)}.')
        for path in files:
            resolved = str(path.resolve())
            records.append({'label': label, 'pcap': resolved,
                            'pairs_csv': str((output / 'pairs' / label /
                                              (path.stem + '_pairs.csv')).resolve()),
                            'original_pairs': previous_paths.get(resolved)})
    if not set(previous_paths).issubset({record['pcap'] for record in records}):
        raise ValueError('Expanded collection must retain every original visit.')
    # Save the predeclared split before processing/training, with stable row IDs.
    assignments = declare_holdout(pd.DataFrame(records)[['label', 'pcap', 'pairs_csv']],
                                  set(previous_paths), test_per_class, seed)
    output.mkdir(parents=True)
    assignments.to_csv(output / 'assignments.csv', index=False)
    checked, sequences = [], []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for record, sequence in executor.map(partial(reconstruct_visit, include_sequence=True), records):
            checked.append(record)
            sequences.append(sequence)
            if len(checked) % 200 == 0 or len(checked) == len(records):
                print(f'Prepared {len(checked)}/{len(records)} captures', flush=True)
    manifest = pd.DataFrame(checked)
    if manifest.pcap_sha256.duplicated().any():
        raise ValueError('Duplicate raw capture content: resolve before using this dataset.')
    manifest[['label', 'pcap', 'pairs_csv']].to_csv(output / 'metadata.csv', index=False)
    manifest.to_csv(output / 'inputs.csv', index=False)
    offsets = np.r_[0, np.cumsum([len(sequence) for sequence in sequences])]
    np.savez_compressed(output / 'extracted_sequences.npz', values=np.concatenate(sequences),
                        offsets=offsets, records_json=json.dumps(checked))
    (output / 'preparation.json').write_text(json.dumps({
        'labels': list(labels),
        'visits_per_class': visits_per_class, 'test_per_class': test_per_class, 'seed': seed,
        'test_policy': ('Balanced holdout from a fully fresh collection' if previous_metadata is None else
                        'Sample only additional captures; all original visits enter development'),
        'previous_metadata': str(previous_metadata.resolve()) if previous_metadata else None,
        'previous_metadata_sha256': file_hash(previous_metadata) if previous_metadata else None,
        'historical_pairs_verified': int(manifest.original_pairs_verified.sum()),
        'source_sha256': {name: file_hash(Path(__file__).parent / name) for name in
                          ('prepare_expanded_dataset.py', 'packet_sequences.py', 'process_pcap.py')},
    }, indent=2) + '\n')
    print(assignments.groupby(['label', 'collection_group', 'split']).size().to_string(), flush=True)
    return assignments


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', type=Path, required=True)
    parser.add_argument('--previous-metadata', type=Path, default=Path('pairs_metadata.csv'))
    parser.add_argument('--fresh', action='store_true', help='Fresh collection with no previous metadata dependency')
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--visits-per-class', type=int, default=200)
    parser.add_argument('--test-per-class', type=int, default=40)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--labels', nargs='+', choices=LABELS,
                        help='Explicit subset for reproducing earlier runs; defaults to all configured pages')
    args = parser.parse_args()
    prepare(args.raw_dir, None if args.fresh else args.previous_metadata, args.out_dir,
            visits_per_class=args.visits_per_class, test_per_class=args.test_per_class,
            seed=args.seed, workers=args.workers, labels=args.labels)
