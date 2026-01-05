#!/usr/bin/env python3
"""
build_pairs_dataset.py

Process raw pcaps under dataset_raw/ into burst-pair CSVs under dataset_pairs/.
Generates a metadata file pairs_metadata.csv with columns: label,pcap,pairs_csv.

Usage:
  python3 build_pairs_dataset.py

Adjust RAW_DATASET / PAIRS_DATASET / INTERFACE as needed.
"""

from pathlib import Path
import csv

from process_pcap import process_pcap

RAW_DATASET = Path("dataset_raw")
PAIRS_DATASET = Path("dataset_pairs")
INTERFACE = "en1"
METADATA_FILE = "pairs_metadata.csv"
BURST_GAP_MS = 50.0

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def build():
    ensure_dir(PAIRS_DATASET)
    rows = []
    for label_dir in RAW_DATASET.iterdir():
        if not label_dir.is_dir():
            continue
        label = label_dir.name
        print(f"[+] Label: {label}")
        out_label_dir = PAIRS_DATASET / label
        ensure_dir(out_label_dir)
        for pcap in label_dir.glob("*.pcap"):
            print(f"    [-] pcap: {pcap.name}")
            out_pairs = out_label_dir / (pcap.stem + "_pairs.csv")
            _, pairs_csv = process_pcap(
                pcap_path=str(pcap),
                iface=INTERFACE,
                packets_csv=None,
                pairs_csv=str(out_pairs),
                gap_ms=BURST_GAP_MS,
            )
            rows.append({"label": label, "pcap": str(pcap), "pairs_csv": str(pairs_csv)})
    with open(METADATA_FILE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label","pcap","pairs_csv"])
        w.writeheader(); w.writerows(rows)
    print(f"[✓] Wrote metadata: {METADATA_FILE} (samples={len(rows)})")

if __name__ == "__main__":
    build()
