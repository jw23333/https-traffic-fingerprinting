#!/usr/bin/env python3
"""
Collect traffic data from unstable websites to demonstrate poor model performance.

This script reuses collection infrastructure from the main codebase but collects
from websites with highly variable traffic patterns (apple.com, microsoft.com,
amazon.com, nytimes.com). The resulting dataset will show:
- High training accuracy despite poor generalization
- Random GUI predictions at runtime
- High data quality issues (variance ratio, low consistency)
"""

import sys
import time
from pathlib import Path

# Add parent directory to path so we can import main modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from collect_dataset import (
    open_private_and_load,
    reload_from_origin,
    reset_safari,
)
from process_pcap import process_pcap
from capture_safari_all import start_capture

# Configuration
UNSTABLE_WEBSITES = [
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.nytimes.com",
]

VISITS_PER_SITE = 50  # Fewer visits to highlight instability
CAPTURE_SECONDS = 2.5
INTERFACE = "en0"  # MacBook Pro WiFi; use en1 if on a different Mac
START_BEFORE_VISIT = True

EXPERIMENT_DIR = Path(__file__).parent / "unstable_case"
RAW_DIR = EXPERIMENT_DIR / "raw"
PAIRS_DIR = EXPERIMENT_DIR / "pairs"
LOGS_DIR = EXPERIMENT_DIR / "logs"


def sanitize_name(url: str) -> str:
    """Extract site name from URL."""
    name = url.lower()
    for prefix in ("http://", "https://", "www."):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.split("/")[0].replace(".com", "")


def collect_from_unstable_sites():
    """Collect traffic from unstable websites."""
    print("[*] Starting collection from unstable websites...")
    
    for site_url in UNSTABLE_WEBSITES:
        site_name = sanitize_name(site_url)
        print(f"\n[*] Collecting from {site_name}...")
        
        site_raw_dir = RAW_DIR / site_name
        site_raw_dir.mkdir(parents=True, exist_ok=True)
        
        for visit_idx in range(1, VISITS_PER_SITE + 1):
            print(f"  [{visit_idx}/{VISITS_PER_SITE}] Capturing {site_name}...", end=" ", flush=True)
            
            prefix = f"{site_name}_{visit_idx}"
            
            try:
                reset_safari()
                
                if START_BEFORE_VISIT:
                    # Open and navigate
                    open_private_and_load(site_url)
                    reload_from_origin()
                    time.sleep(0.1)
                    
                    # Start capture during navigation
                    _, pcap_path = start_capture(
                        interface=INTERFACE,
                        out_dir=str(site_raw_dir),
                        prefix=prefix,
                        duration=CAPTURE_SECONDS,
                        fixed=True,
                    )
                else:
                    # Navigate first
                    open_private_and_load(site_url)
                    reload_from_origin()
                    time.sleep(0.3)
                    
                    # Then capture
                    _, pcap_path = start_capture(
                        interface=INTERFACE,
                        out_dir=str(site_raw_dir),
                        prefix=prefix,
                        duration=CAPTURE_SECONDS,
                        fixed=True,
                    )
                
                file_size = pcap_path.stat().st_size / 1024
                print(f"✓ ({file_size:.1f} KB)")
                
            except Exception as e:
                print(f"✗ Error: {e}")
                continue
            
            finally:
                time.sleep(0.5)
    
    print("\n[+] Collection complete!")
    return RAW_DIR


def convert_pcaps_to_pairs():
    """Convert all pcap files to burst-pair CSV files."""
    print("\n[*] Converting pcap files to burst-pair CSVs...")
    
    pcap_count = 0
    for site_dir in sorted(RAW_DIR.iterdir()):
        if not site_dir.is_dir():
            continue
        
        site_name = site_dir.name
        pairs_site_dir = PAIRS_DIR / site_name
        pairs_site_dir.mkdir(parents=True, exist_ok=True)
        
        for pcap_file in sorted(site_dir.glob("*.pcap")):
            print(f"  Converting {pcap_file.name}...", end=" ", flush=True)
            
            pairs_file = pairs_site_dir / (pcap_file.stem + "_pairs.csv")
            
            try:
                _, pairs_csv = process_pcap(
                    pcap_path=str(pcap_file),
                    iface=INTERFACE,
                    packets_csv=None,
                    pairs_csv=str(pairs_file),
                    gap_ms=50.0,
                )
                print(f"✓")
                pcap_count += 1
            except Exception as e:
                print(f"✗ {e}")
    
    print(f"[+] Converted {pcap_count} pcap files")
    return PAIRS_DIR


def main():
    print("="*70)
    print("UNSTABLE WEBSITES COLLECTION EXPERIMENT")
    print("="*70)
    print(f"Target websites: {', '.join(UNSTABLE_WEBSITES)}")
    print(f"Visits per site: {VISITS_PER_SITE}")
    print(f"Output directory: {EXPERIMENT_DIR}")
    print("="*70)
    
    # Step 1: Collect
    raw_dir = collect_from_unstable_sites()
    
    # Step 2: Convert
    pairs_dir = convert_pcaps_to_pairs()
    
    print("\n[+] Unstable website data collection complete!")
    print(f"    Raw pcaps: {raw_dir}")
    print(f"    Burst pairs: {pairs_dir}")
    

if __name__ == "__main__":
    main()
