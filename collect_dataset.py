#!/usr/bin/env python3
"""
collect_dataset.py

Automate dataset collection by visiting sites in Safari and capturing fixed-duration
pcap traces using the `start_capture(..., fixed=True)` helper in `capture_safari_all.py`.

Behavior:
- Creates a `dataset/` folder inside the project directory.
- For each site in `SITES`, creates a subfolder named after the site.
- Visits the site in Safari, waits a small delay for the browser to begin connections,
  then runs a fixed-duration capture which writes a timestamped pcap into the
  site's subfolder. Repeats `VISITS_PER_SITE` times.

Notes:
- This script uses AppleScript (osascript) to open locations in Safari.
- For full capture of the initial TLS/QUIC handshakes, consider starting the
  capture immediately before navigation. The default below starts the capture
  after navigation + a short delay; change `START_BEFORE_VISIT` to `True` to
  capture from before navigation.

Usage: run from the project directory
    python3 collect_dataset.py

"""

import os
import time
import subprocess
from pathlib import Path
from typing import List

from capture_safari_all import start_capture, DEFAULT_OUT_DIR


# ---------------- Configuration ----------------
# Edit these values as needed. Defaults are reasonable for a first run.
PROJECT_DIR = Path(DEFAULT_OUT_DIR)
DATASET_DIR = PROJECT_DIR / "dataset_raw"

# Sites to visit. Use full URL strings.
# Chosen for diverse, relatively stable traffic patterns.
SITES: List[str] = [
    "https://www.wikipedia.org",      # light, very distinct
    "https://docs.python.org",         # very light docs, distinct
    "https://www.reuters.com",         # medium news (lighter than BBC)
    "https://www.npmjs.com",                # medium package index (distinct from news/docs)
    "https://medium.com",              # medium blog platform
]

VISITS_PER_SITE = 50
CAPTURE_SECONDS = 2.5
# Seconds to wait after opening the site before starting capture (if start_before_visit=False)
DELAY_BEFORE_CAPTURE = 0.3
# Cooldown between visits (give browser a moment, avoids hitting rate limits)
DELAY_BETWEEN_VISITS = 1.0
# If True: start capture before navigating to the URL (recommended to capture initial packets)
START_BEFORE_VISIT = True


def sanitize_name(url: str) -> str:
    """Make a filesystem-friendly name for a site (used for subfolder/prefix)."""
    # remove scheme
    name = url.lower()
    for prefix in ("http://", "https://", "www."):
        if name.startswith(prefix):
            name = name[len(prefix):]
    # replace path and non-alnum with underscore
    name = name.split("/", 1)[0]
    safe = ''.join([c if c.isalnum() else '_' for c in name])
    return safe


def ensure_dataset_dirs():
    DATASET_DIR.mkdir(parents=True, exist_ok=True)


def open_in_safari(url: str) -> None:
    """Open the URL in Safari using AppleScript (osascript)."""
    script = f'tell application "Safari"\nactivate\nopen location "{url}"\nend tell'
    subprocess.run(["osascript", "-e", script], check=True)

def open_private_and_load(url: str) -> None:
    """Open a new Private window and load the URL.

    Uses System Events to send Shift+Command+N to Safari.
    Requires Accessibility permission for "osascript" under System Settings > Privacy & Security > Accessibility.
    """
    # Activate Safari and open a new Private Window
    subprocess.run(["osascript", "-e", 'tell application "Safari" to activate'], check=True)
    subprocess.run(["osascript", "-e", 'tell application "System Events" to keystroke "n" using {shift down, command down}'], check=True)
    # Small delay, then set URL of the front document
    script = f'tell application "Safari"\ntry\nset URL of front document to "{url}"\non error\nopen location "{url}"\nend try\nend tell'
    subprocess.run(["osascript", "-e", script], check=True)

def reload_from_origin() -> None:
    """Force a full reload ignoring caches (Option+Command+R)."""
    subprocess.run(["osascript", "-e", 'tell application "Safari" to activate'], check=True)
    subprocess.run(["osascript", "-e", 'tell application "System Events" to keystroke "r" using {option down, command down}'], check=True)

def reset_safari():
    """Close all Safari windows to remove old tabs and cached connections."""
    script = 'tell application "Safari" to close every window'
    subprocess.run(["osascript", "-e", script], check=True)
    time.sleep(0.2)  # small delay to allow Safari to reset

def capture_visit(site_url: str, site_dir: Path, visit_idx: int) -> None:
    """Perform a single visit and fixed-duration capture for the site."""
    prefix = f"{sanitize_name(site_url)}_{visit_idx}"

    print(f"[+] Visit {visit_idx}: {site_url} -> folder: {site_dir} (prefix: {prefix})")

    try:
        reset_safari()
        if START_BEFORE_VISIT:
            print("    [>] Opening Private window and loading site (fresh)")
            open_private_and_load(site_url)
            # Force reload from origin to bypass any residual caches
            reload_from_origin()
            time.sleep(0.1)

            print("    [>] Starting capture (navigation in progress)")
            _, pcap_path = start_capture(
                interface="en1",
                out_dir=str(site_dir),
                prefix=prefix,
                duration=CAPTURE_SECONDS,
                fixed=True,
            )
            print(f"    [✓] Wrote {pcap_path}")
        else:
            # Navigate first (Private), force reload from origin, then capture
            open_private_and_load(site_url)
            reload_from_origin()
            time.sleep(DELAY_BEFORE_CAPTURE)
            print("    [>] Starting capture (after navigation)")
            _, pcap_path = start_capture(
                interface="en1",
                out_dir=str(site_dir),
                prefix=prefix,
                duration=CAPTURE_SECONDS,
                fixed=True,
            )
            print(f"    [✓] Wrote {pcap_path}")

    except subprocess.CalledProcessError as e:
        print(f"    [!] subprocess error: {e}")
    except Exception as e:
        print(f"    [!] unexpected error: {e}")


def run_collection(sites: List[str] = SITES):
    ensure_dataset_dirs()

    for site in sites:
        site_name = sanitize_name(site)
        site_dir = DATASET_DIR / site_name
        site_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n=== Collecting for site: {site} ({site_dir}) ===")

        for i in range(1, VISITS_PER_SITE + 1):
            capture_visit(site, site_dir, i)
            time.sleep(DELAY_BETWEEN_VISITS)


if __name__ == '__main__':
    print(f"Project dir: {PROJECT_DIR}")
    print(f"Dataset dir: {DATASET_DIR}")
    print(f"Sites: {SITES}")
    run_collection()
