#!/usr/bin/env python3
"""Add captures until every configured page reaches a target total.

Preview:
    python3 extend_dataset.py --raw-dir dataset_raw/collection_20261016_force_reload \
        --target-visits 200 --dry-run
Collect (rerun the same command to resume):
    python3 extend_dataset.py --raw-dir dataset_raw/collection_20261016_force_reload \
        --target-visits 200 --interface en1

Uses the existing Private Safari/capture-ready/force-reload procedure. Existing
captures are read only; completed new captures stay in the same page folders.
This command does not process pairs, change model splits or train models.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import json
from pathlib import Path
import random
import re
import subprocess
import time

from collect_dataset import (DEFAULT_INTERFACE, DELAY_BETWEEN_VISITS, MAX_VISIT_ATTEMPTS,
                             SITES, SafariSession, capture_visit, sanitize_name)


def valid_capture(path: Path) -> bool:
    """Use the collector's readable/nonempty check, without modifying the file."""
    if path.stat().st_size <= 24:
        return False
    try:
        result = subprocess.run(
            ['tshark', '-r', str(path), '-c', '1', '-T', 'fields', '-e', 'frame.number'],
            check=True, capture_output=True, text=True, timeout=15)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return bool(result.stdout.strip())


def validate_location(raw_dir: Path, sites, *, allow_empty: bool = False) -> None:
    if allow_empty and not raw_dir.exists():
        return
    if not raw_dir.is_dir():
        raise FileNotFoundError(f'Existing collection folder not found: {raw_dir}')
    if allow_empty and all(path.name in {'.collection.lock', 'collection_config.json', '.DS_Store'}
                           for path in raw_dir.iterdir()):
        return
    if not any((raw_dir / sanitize_name(url)).is_dir() for url in sites):
        raise ValueError('Choose an existing collection containing configured page folders '
                         '(such as chickenpox/), rather than their parent dataset_raw/.')


def collection_plan(raw_dir: Path, target: int, sites=None, *, allow_empty: bool = False) -> list[dict]:
    if target < 1:
        raise ValueError('Target visits must be positive.')
    sites = SITES if sites is None else sites
    validate_location(raw_dir, sites, allow_empty=allow_empty)
    plan = []
    for url in sites:
        page = sanitize_name(url)
        directory = raw_dir / page
        files = sorted(directory.glob('*.pcap'))
        with ThreadPoolExecutor(max_workers=4) as executor:
            validity = list(executor.map(valid_capture, files))
        valid = [path for path, good in zip(files, validity) if good]
        invalid = [path for path, good in zip(files, validity) if not good]
        numbered = [int(match.group(1)) for path in files
                    if (match := re.match(re.escape(page) + r'_(\d+)(?:_|$)', path.stem))]
        # Include invalid files when reserving numbers, so even their names are
        # not reused. capture_visit also uses timestamped filenames.
        next_visit = max([len(files), *numbered], default=0) + 1
        plan.append({'url': url, 'page': page, 'directory': directory,
                     'valid': valid, 'invalid': invalid, 'next_visit': next_visit,
                     'needed': max(0, target - len(valid))})
    return plan


def print_plan(plan: list[dict], target: int) -> None:
    page_width = max(14, *(len(page['page']) for page in plan))
    print(f'\nTarget: {target} total readable, nonempty captures per page')
    print(f'{"Page":{page_width}} {"Existing":>9} {"To add":>9}')
    for page in plan:
        print(f'{page["page"]:{page_width}} {len(page["valid"]):9} {page["needed"]:9}')
        for path in page['invalid']:
            print(f'  Not counted (empty/unreadable; left untouched): {path.name}')
    print(f'Total new captures needed: {sum(page["needed"] for page in plan)}', flush=True)


@contextmanager
def collection_lock(raw_dir: Path):
    # flock is released by the OS even after a process crash. The small hidden
    # lock file is operational state, not a collection report or research note.
    with (raw_dir / '.collection.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another extension run is already using this collection.') from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def check_collection_settings(raw_dir: Path, settings: dict, *, write: bool = False) -> None:
    """One small configuration file prevents mixing protocols when resuming."""
    path = raw_dir / 'collection_config.json'
    if path.exists():
        if json.loads(path.read_text()) != settings:
            raise ValueError('Collection settings differ from this folder. Restore its settings or use a new folder.')
    else:
        if any(raw_dir.rglob('*.pcap')):
            raise ValueError('Fresh collection cannot adopt existing PCAPs without its configuration file.')
        if write:
            with path.open('x') as handle:
                json.dump(settings, handle, indent=2)
                handle.write('\n')


def scheduled_visits(plan: list[dict], target: int, batch_size: int | None, seed: int):
    """Interleave page batches; completed visit counts make the schedule resumable."""
    if batch_size is not None and batch_size < 1:
        raise ValueError('Visits per batch must be positive.')
    counts = [len(page['valid']) for page in plan]
    next_visits = [page['next_visit'] for page in plan]
    step = target if batch_size is None else batch_size
    rng = random.Random(seed)
    for start in range(0, target, step):
        goal = min(start + step, target)
        order = list(range(len(plan)))
        if batch_size is not None:
            rng.shuffle(order)
        if not any(count < goal for count in counts):
            continue
        if batch_size is not None:
            print(f'\nRound {start // step + 1}: up to {goal}/{target} visits per page', flush=True)
        for index in order:
            while counts[index] < goal:
                yield index, next_visits[index]
                counts[index] += 1
                next_visits[index] += 1


def extend_collection(raw_dir: Path, target: int = 200, *, interface: str = DEFAULT_INTERFACE,
                      dry_run: bool = False, sites=None, create: bool = False,
                      batch_size: int | None = None, seed: int = 42,
                      collection_settings: dict | None = None) -> None:
    """Count completed files on every run; an interrupted batch can be resumed."""
    raw_dir = raw_dir.expanduser().resolve()
    sites = SITES if sites is None else sites
    if target < 1:
        raise ValueError('Target visits must be positive.')
    if batch_size is not None and batch_size < 1:
        raise ValueError('Visits per batch must be positive.')
    validate_location(raw_dir, sites, allow_empty=create)
    if collection_settings is not None:
        check_collection_settings(raw_dir, collection_settings)
    if dry_run:
        print_plan(collection_plan(raw_dir, target, sites, allow_empty=create), target)
        print('Dry run complete. Safari and live recording were not started.')
        return
    if create:
        raw_dir.mkdir(parents=True, exist_ok=True)
    # Check the location before opening the lock file or creating page folders.
    with collection_lock(raw_dir):
        if collection_settings is not None:
            check_collection_settings(raw_dir, collection_settings, write=True)
        plan = collection_plan(raw_dir, target, sites, allow_empty=create)
        print_plan(plan, target)
        if not any(page['needed'] for page in plan):
            print('Target already satisfied; no visits were started.', flush=True)
            return
        session = SafariSession()
        total_saved = 0
        completed = [len(page['valid']) for page in plan]
        known = [{path.resolve() for path in page['directory'].glob('*.pcap')} for page in plan]
        for index, visit in scheduled_visits(plan, target, batch_size, seed):
            page = plan[index]
            for attempt in range(1, MAX_VISIT_ATTEMPTS + 1):
                try:
                    path = capture_visit(page['url'], page['directory'], visit,
                                         interface=interface, session=session)
                except Exception as error:
                    print(f'  Attempt {attempt}/{MAX_VISIT_ATTEMPTS} failed: {error}', flush=True)
                    if attempt == MAX_VISIT_ATTEMPTS:
                        raise RuntimeError(
                            f'Stopped while adding {page["page"]}. Completed captures are kept; '
                            'rerun this command to resume.') from error
                    time.sleep(DELAY_BETWEEN_VISITS)
                else:
                    path = Path(path).resolve()
                    if path in known[index] or path.parent != page['directory'].resolve() or not path.is_file():
                        raise RuntimeError('Collector did not return a new capture in the expected folder.')
                    known[index].add(path)
                    completed[index] += 1
                    total_saved += 1
                    print(f'  {page["page"]}: {completed[index]}/{target} completed; '
                          f'{sum(completed)}/{len(plan) * target} overall', flush=True)
                    break
            time.sleep(DELAY_BETWEEN_VISITS)
        for page, count in zip(plan, completed):
            print(f'{page["page"]}: {count} total captures; target satisfied.', flush=True)
        print(f'\nFinished. Added {total_saved} new captures. Existing files were preserved.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--raw-dir', type=Path, required=True,
                        help='Existing collection root; missing configured page folders are added during collection')
    parser.add_argument('--target-visits', type=int, default=200,
                        help='Total valid captures wanted per page, including existing files (default: 200)')
    parser.add_argument('--interface', default=DEFAULT_INTERFACE)
    parser.add_argument('--dry-run', action='store_true', help='Count and show the additions without visiting pages')
    args = parser.parse_args()
    try:
        extend_collection(args.raw_dir, args.target_visits, interface=args.interface, dry_run=args.dry_run)
    except KeyboardInterrupt:
        print('\nStopped. Completed captures are kept. Rerun the same command to resume.')
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Error: {error}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
