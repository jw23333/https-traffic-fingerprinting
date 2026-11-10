#!/usr/bin/env python3
"""Collect a fresh, resumable set of 3,000 NHS visits without per-visit logs.

Run from the project directory:
    python3 collect_fresh_dataset.py --interface en1

Use the same command after Ctrl+C to resume. Add --dry-run to preview without
creating folders, opening Safari or recording. No command here deletes data.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from collect_dataset import (CAPTURE_SECONDS, DEFAULT_INTERFACE, DELAY_BETWEEN_VISITS,
                             PRELOAD_SETTLE_SECONDS, SITES)
from extend_dataset import extend_collection


DEFAULT_RAW_DIR = Path(__file__).resolve().parent / 'dataset_raw' / 'nhs_15pages_fresh_20261029'


def collect(raw_dir: Path = DEFAULT_RAW_DIR, *, interface: str = DEFAULT_INTERFACE,
            target: int = 200, batch_size: int = 20, seed: int = 42,
            dry_run: bool = False):
    settings = {
        'format_version': 1, 'sites': list(SITES), 'target_visits_per_page': target,
        'visits_per_batch': batch_size, 'random_seed': seed, 'interface': interface,
        'capture_seconds': CAPTURE_SECONDS, 'preload_settle_seconds': PRELOAD_SETTLE_SECONDS,
        'delay_between_visits': DELAY_BETWEEN_VISITS,
        'method': 'Private Safari Option+Command+R',
        'schedule': 'Shuffle page order each round; complete one batch per page',
    }
    extend_collection(raw_dir, target, interface=interface, dry_run=dry_run,
                      sites=SITES, create=True, batch_size=batch_size, seed=seed,
                      collection_settings=settings)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--interface', default=DEFAULT_INTERFACE)
    parser.add_argument('--out-dir', type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument('--visits-per-site', type=int, default=200)
    parser.add_argument('--batch-size', type=int, default=20)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        collect(args.out_dir, interface=args.interface, target=args.visits_per_site,
                batch_size=args.batch_size, seed=args.seed, dry_run=args.dry_run)
    except KeyboardInterrupt:
        print('\nStopped. Completed captures are kept; rerun the same command to resume.')
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Error: {error}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
