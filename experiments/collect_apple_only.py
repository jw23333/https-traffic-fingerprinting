#!/usr/bin/env python3
"""
Collect 10 additional traffic samples from apple.com only.
Uses the same infrastructure as collect_unstable_websites.py.
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from collect_dataset import (
    open_private_and_load,
    reload_from_origin,
    reset_safari,
)
from process_pcap import process_pcap
from capture_safari_all import start_capture

# Configuration
SITE_URL = "https://www.apple.com"
VISITS = 10  # Collect 10 samples
CAPTURE_SECONDS = 2.5
INTERFACE = "en1"  # Change to en1 if needed

EXPERIMENT_DIR = Path(__file__).parent / "unstable_case"
RAW_DIR = EXPERIMENT_DIR / "raw" / "apple"
PAIRS_DIR = EXPERIMENT_DIR / "pairs" / "apple"

def collect_apple():
    """Collect 10 additional apple.com samples."""
    print("[*] Collecting 10 samples from apple.com...")
    
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PAIRS_DIR.mkdir(parents=True, exist_ok=True)
    
    for visit_idx in range(1, VISITS + 1):
        print(f"  [{visit_idx}/{VISITS}] Capturing apple...", end=" ", flush=True)
        
        prefix = f"apple_{visit_idx}"
        
        try:
            reset_safari()
            
            # Open and navigate
            open_private_and_load(SITE_URL)
            reload_from_origin()
            time.sleep(0.1)
            
            # Start capture during navigation
            _, pcap_path = start_capture(
                interface=INTERFACE,
                out_dir=str(RAW_DIR),
                prefix=prefix,
                duration=CAPTURE_SECONDS,
                fixed=True,
            )
            
            # Process into burst pairs
            process_pcap(
                pcap_path=str(pcap_path),
                iface=INTERFACE,
                packets_csv=None,
                pairs_csv=str(PAIRS_DIR / f"{prefix}_pairs.csv"),
                gap_ms=50.0,
            )
            
            print("✓")
            
        except Exception as e:
            print(f"✗ Error: {e}")
            continue
    
    print("[+] Done collecting 10 apple samples")

if __name__ == "__main__":
    collect_apple()
