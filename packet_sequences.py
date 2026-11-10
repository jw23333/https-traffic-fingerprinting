"""Reconstruct signed packet sequences from saved captures, without live IP lookup."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from process_pcap import build_capture_data, run_tshark_fields


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def infer_client_ips(rows: list[dict]) -> set[str]:
    """Infer non-443 endpoints, then require every packet to cross that boundary.

    The collection contains client connections to port-443 servers. Fail on
    ambiguous endpoints rather than guessing using today's interface addresses.
    """
    clients, servers = set(), set()
    endpoints = []
    for row in rows:
        source = row.get('ip.src') or row.get('ipv6.src') or ''
        target = row.get('ip.dst') or row.get('ipv6.dst') or ''
        sport = row.get('tcp.srcport') or row.get('udp.srcport') or ''
        dport = row.get('tcp.dstport') or row.get('udp.dstport') or ''
        if not source or not target:
            raise ValueError('Packet lacks IP endpoints; supply a compatible capture.')
        if dport == '443' and sport != '443':
            clients.add(source)
            servers.add(target)
        elif sport == '443' and dport != '443':
            clients.add(target)
            servers.add(source)
        endpoints.append((source, target))
    if not clients or clients & servers:
        raise ValueError('Cannot unambiguously infer the capture-time client addresses.')
    if any((source in clients) == (target in clients) for source, target in endpoints):
        raise ValueError('Not every packet crosses the inferred client/server boundary.')
    return clients


def signed_sequence(packets: list[dict]) -> np.ndarray:
    """Use the inspector's ordered, direction-labelled packets for model input."""
    ordered = sorted(packets, key=lambda row: float(row['frame.time_relative']))
    values = np.array([float(row['signed_len']) for row in ordered], dtype=np.float32)
    if not len(values) or not np.isfinite(values).all() or np.any(values == 0):
        raise ValueError('A sequence must contain finite, nonzero signed packet lengths.')
    return values


def read_visit(record: dict) -> tuple[np.ndarray, dict]:
    path = Path(record['pcap']).resolve()
    rows = run_tshark_fields(str(path), include_ports=True)
    clients = infer_client_ips(rows)
    capture = build_capture_data(rows, clients)
    sequence = signed_sequence(capture.packets)
    expected = pd.read_csv(record['resolved_pairs_csv'])
    columns = ['out_bytes', 'in_bytes', 'out_pkts', 'in_pkts',
               'out_start', 'out_end', 'in_start', 'in_end']
    actual = pd.DataFrame(capture.pairs)
    if len(actual) != len(expected) or not np.allclose(
            actual[columns].to_numpy(dtype=float), expected[columns].to_numpy(dtype=float),
            rtol=0, atol=1e-9):
        raise ValueError(f'Reconstructed direction/bursts differ from the RF data: {path.name}')
    if file_hash(Path(record['resolved_pairs_csv'])) != record['pairs_sha256']:
        raise ValueError(f'Pair CSV changed since the recorded RF split: {path.name}')
    return sequence, {
        **record, 'resolved_pcap': str(path), 'pcap_sha256': file_hash(path),
        'packet_count': len(sequence), 'outgoing_packets': int(np.count_nonzero(sequence > 0)),
        'incoming_packets': int(np.count_nonzero(sequence < 0)),
        'reconstructed_pairs_match': True,
    }


def build_cache(split_path: Path, cache_path: Path, workers: int = 4,
                prepared_cache: Path | None = None) -> dict:
    if cache_path.exists():
        raise FileExistsError(f'Packet cache already exists: {cache_path}')
    split = pd.read_csv(split_path)
    if split.sample_id.tolist() != list(range(len(split))):
        raise ValueError('Expected the original RF split in metadata row order.')
    if set(split.split) != {'train', 'test'} or split.pcap.duplicated().any():
        raise ValueError('Invalid or duplicated visits in the RF split.')
    sequences, records = [], []
    if prepared_cache is None:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for sequence, record in executor.map(read_visit, split.to_dict('records')):
                sequences.append(sequence)
                records.append(record)
                if len(records) % 200 == 0 or len(records) == len(split):
                    print(f'Extracted packet sequences: {len(records)}/{len(split)}', flush=True)
    else:
        with np.load(prepared_cache, allow_pickle=False) as cache:
            values, offsets = cache['values'], cache['offsets']
            prepared = json.loads(str(cache['records_json']))
        if len(prepared) != len(split) or len(offsets) != len(split) + 1:
            raise ValueError('Prepared extraction does not match the RF visit count.')
        for start, end, source, record in zip(offsets[:-1], offsets[1:], prepared, split.to_dict('records')):
            if (source['pcap'] != record['pcap'] or source['label'] != record['label'] or
                    source['pairs_sha256'] != record['pairs_sha256'] or
                    source['pairs_csv'] != record['resolved_pairs_csv']):
                raise ValueError('Prepared extraction differs from the RF inputs or row order.')
            sequences.append(values[start:end].copy())
            records.append({**source, **record, 'resolved_pcap': str(Path(record['pcap']).resolve()),
                            'reconstructed_pairs_match': True})
    payload = {'source_split': str(split_path), 'source_split_sha256': file_hash(split_path),
               'representation': 'signed captured frame.len, outgoing positive; TCP/UDP port 443',
               'packet_filter': 'All existing port-443 packets retained, including acknowledgements',
               'source_sha256': {name: file_hash(Path(__file__).parent / name)
                                 for name in ('packet_sequences.py', 'process_pcap.py')}}
    if prepared_cache is not None:
        payload['prepared_extraction'] = str(prepared_cache)
        payload['prepared_extraction_sha256'] = file_hash(prepared_cache)
    offsets = np.r_[0, np.cumsum([len(sequence) for sequence in sequences])]
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache_path, values=np.concatenate(sequences), offsets=offsets,
                        records_json=json.dumps(records), metadata_json=json.dumps(payload))
    print(f'Saved packet sequences to {cache_path}', flush=True)
    return payload


def load_cache(path: Path, *, verify_files: bool = True):
    with np.load(path, allow_pickle=False) as cache:
        values, offsets = cache['values'], cache['offsets']
        records = pd.DataFrame(json.loads(str(cache['records_json'])))
        metadata = json.loads(str(cache['metadata_json']))
    sequences = [values[start:end].copy() for start, end in zip(offsets[:-1], offsets[1:])]
    if len(sequences) != len(records):
        raise ValueError('Cache records and sequences disagree.')
    if verify_files:
        if file_hash(Path(metadata['source_split'])) != metadata['source_split_sha256']:
            raise ValueError('The recorded RF split has changed.')
        for record in records.itertuples():
            if (file_hash(Path(record.resolved_pcap)) != record.pcap_sha256 or
                    file_hash(Path(record.resolved_pairs_csv)) != record.pairs_sha256):
                raise ValueError(f'Input file changed: sample {record.sample_id}')
    return sequences, records, metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', type=Path,
                        default=Path('results/rf_feature_removal_20261025/split.csv'))
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--prepared-cache', type=Path,
                        help='Reuse packet extraction from prepare_expanded_dataset without rereading PCAPs')
    args = parser.parse_args()
    build_cache(args.split, args.cache, args.workers, args.prepared_cache)
