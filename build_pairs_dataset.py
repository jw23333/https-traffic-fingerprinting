#!/usr/bin/env python3
"""
build_pairs_dataset.py

Process raw pcaps under dataset_raw/ into burst-pair CSVs under dataset_pairs/.
Generates a metadata file pairs_metadata.csv with columns: label,pcap,pairs_csv.

Usage:
  python3 build_pairs_dataset.py

Adjust RAW_DATASET / PAIRS_DATASET / INTERFACE as needed.
Or select a separate collection without changing the existing defaults:
  python3 build_pairs_dataset.py --raw-dir dataset_raw/collection_force_reload
"""

from pathlib import Path
import argparse
import csv

from process_pcap import process_pcap

RAW_DATASET = Path("dataset_raw")
PAIRS_DATASET = Path("dataset_pairs")
INTERFACE = "en1"
METADATA_FILE = "pairs_metadata.csv"
BURST_GAP_MS = 50.0

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def build(raw_dataset: Path | None = None, pairs_dataset: Path | None = None,
          interface: str | None = None, metadata_file: Path | None = None):
    raw_dataset = RAW_DATASET if raw_dataset is None else raw_dataset.expanduser()
    pairs_dataset = PAIRS_DATASET if pairs_dataset is None else pairs_dataset.expanduser()
    interface = INTERFACE if interface is None else interface
    metadata_file = Path(METADATA_FILE) if metadata_file is None else metadata_file.expanduser()
    if not raw_dataset.is_dir():
        raise FileNotFoundError(f"Raw dataset folder not found: {raw_dataset}")
    label_files = [(folder, list(folder.glob('*.pcap')))
                   for folder in raw_dataset.iterdir() if folder.is_dir()]
    if not any(files for _, files in label_files):
        raise ValueError(f"No <page>/*.pcap files in {raw_dataset}. "
                         "Use --raw-dir to select the collection folder itself.")
    ensure_dir(pairs_dataset)
    rows = []
    for label_dir, pcaps in label_files:
        if not pcaps:
            continue
        label = label_dir.name
        print(f"[+] Label: {label}")
        out_label_dir = pairs_dataset / label
        ensure_dir(out_label_dir)
        for pcap in pcaps:
            print(f"    [-] pcap: {pcap.name}")
            out_pairs = out_label_dir / (pcap.stem + "_pairs.csv")
            _, pairs_csv = process_pcap(
                pcap_path=str(pcap),
                iface=interface,
                packets_csv=None,
                pairs_csv=str(out_pairs),
                gap_ms=BURST_GAP_MS,
            )
            rows.append({"label": label, "pcap": str(pcap), "pairs_csv": str(pairs_csv)})
    ensure_dir(metadata_file.parent)
    with metadata_file.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label","pcap","pairs_csv"])
        w.writeheader(); w.writerows(rows)
    print(f"[✓] Wrote metadata: {metadata_file} (samples={len(rows)})")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', type=Path)
    parser.add_argument('--pairs-dir', type=Path)
    parser.add_argument('--interface')
    parser.add_argument('--metadata', type=Path)
    args = parser.parse_args()
    build(args.raw_dir, args.pairs_dir, args.interface, args.metadata)

if __name__ == "__main__":
    main()
