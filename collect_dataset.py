#!/usr/bin/env python3
"""Collect labelled HTTPS traces using Safari's reload-from-origin shortcut.

The batch opens one private window and reuses it. When the target page changes,
it navigates normally and lets that navigation settle. Each visit starts capture,
waits for readiness, and sends Option+Command+R. The recording continues for
CAPTURE_SECONDS from issuing that force reload. Raw port-443 traffic is retained
without website filtering, using the existing packet/burst/feature formats.

Run a complete batch, choosing a fresh output folder to separate older data:
    python3 collect_dataset.py --interface en1 --out-dir dataset_raw/new_collection

Requires tshark, macOS Automation/Accessibility permissions for osascript,
and permission to capture on the selected interface. Existing windows stay open.
"""

import argparse
from datetime import datetime, timezone
from dataclasses import dataclass
import json
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Callable
from urllib.parse import urldefrag

from capture_safari_all import (DEFAULT_INTERFACE, DEFAULT_OUT_DIR,
                                start_capture, stop_capture)


# ---------------- Configuration ----------------
PROJECT_DIR = Path(DEFAULT_OUT_DIR)
DATASET_DIR = PROJECT_DIR / "dataset_raw"
SITES: list[str] = [
    "https://www.nhs.uk/conditions/chickenpox/",
    "https://www.nhs.uk/conditions/measles/",
    "https://www.nhs.uk/conditions/mumps/",
    "https://www.nhs.uk/conditions/rubella/",
    "https://www.nhs.uk/conditions/flu/",
    "https://www.nhs.uk/conditions/common-cold/",
    "https://www.nhs.uk/conditions/whooping-cough/",
    "https://www.nhs.uk/conditions/scarlet-fever/",
    "https://www.nhs.uk/conditions/hand-foot-mouth-disease/",
    "https://www.nhs.uk/conditions/shingles/",
    "https://www.nhs.uk/conditions/impetigo/",
    "https://www.nhs.uk/conditions/tonsillitis/",
    "https://www.nhs.uk/conditions/glandular-fever/",
    "https://www.nhs.uk/conditions/norovirus/",
    "https://www.nhs.uk/conditions/conjunctivitis/",
]
VISITS_PER_SITE = 70
CAPTURE_SECONDS = 2.5
DELAY_BETWEEN_VISITS = 1.0
# Preparation only: keep the first navigation outside the measured force reload.
PRELOAD_SETTLE_SECONDS = 3.0
MAX_VISIT_ATTEMPTS = 3


def run_safari_script(script: str, *args: str) -> str:
    """Keep AppleScript's actual error text instead of only an exit status."""
    try:
        result = subprocess.run(["osascript", "-e", script, *args], check=True,
                                capture_output=True, text=True, timeout=40)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise RuntimeError(f"Safari automation failed: {detail}") from exc
    return result.stdout.strip()


# activate is asynchronous: System Events keystrokes go to the foreground app.
# Wait for that app explicitly, including the first launch from a background app.
SAFARI_FOREGROUND_SCRIPT = '''
on focusSafari()
    tell application "Safari" to activate
    repeat 100 times
        tell application "System Events"
            if exists process "Safari" then
                tell process "Safari"
                    set frontmost to true
                    if frontmost then return
                end tell
            end if
        end tell
        delay 0.1
    end repeat
    error "Safari did not become the foreground application within 10 seconds."
end focusSafari
'''


def sanitize_name(url: str) -> str:
    """Use the condition name, or domain, as the class folder name."""
    name = url.lower()
    for prefix in ("http://", "https://", "www."):
        if name.startswith(prefix):
            name = name[len(prefix):]
    if "/conditions/" in name:
        condition = name.split("/conditions/", 1)[1].rstrip("/")
        if condition:
            # Custom GUI URLs may contain nested paths or query strings. Keep
            # names within one filesystem component; standard class names stay
            # unchanged.
            return ''.join(c if (c.isascii() and c.isalnum()) or c in '-_' else '_'
                           for c in condition)[:80]
    return ''.join(c if c.isascii() and c.isalnum() else '_'
                   for c in name.split('/', 1)[0])[:80]


def reset_safari() -> None:
    """Legacy utility; the dataset collector no longer calls this."""
    run_safari_script('tell application "Safari" to close every window')
    time.sleep(0.2)


def open_private_window() -> int:
    """Wait for Safari focus and a newly created private window's document."""
    script = SAFARI_FOREGROUND_SCRIPT + '''
on run argv
    my focusSafari()
    tell application "Safari" to set previousWindowIDs to id of every window
    tell application "System Events" to keystroke "n" using {shift down, command down}
    repeat 100 times
        tell application "Safari"
            if (count of windows) > 0 then
                if (id of front window) is not in previousWindowIDs then
                    if (count of documents) > 0 then return (id of front window)
                end if
            end if
        end tell
        delay 0.1
    end repeat
    error "Safari did not create a new private window within 10 seconds. Check Automation/Accessibility permissions."
end run
'''
    return int(run_safari_script(script))


def safari_window_exists(window_id: int) -> bool:
    """Check the collector's own window, without touching other windows."""
    script = '''
on run argv
    tell application "Safari" to return exists (window id (item 1 of argv as integer))
end run
'''
    return run_safari_script(script, str(window_id)).lower() == 'true'


def safari_window_url(window_id: int) -> str:
    """Read the owned window's selected tab before a guided GUI visit."""
    script = '''
on run argv
    tell application "Safari" to return URL of current tab of window id (item 1 of argv as integer)
end run
'''
    return run_safari_script(script, str(window_id))


def load_in_safari(url: str, window_id: int | None = None) -> None:
    """Prepare the requested URL before the measured force-reload visit."""
    script = '''
on run argv
    tell application "Safari"
        if (count of argv) > 1 then
            set targetWindow to window id (item 2 of argv as integer)
            set URL of current tab of targetWindow to (item 1 of argv)
        else
            set URL of front document to (item 1 of argv)
        end if
    end tell
end run
'''
    args = (url,) if window_id is None else (url, str(window_id))
    run_safari_script(script, *args)


def open_private_and_load(url: str) -> None:
    """Preserve the original private-window/navigation helper."""
    open_private_window()
    load_in_safari(url)
    time.sleep(PRELOAD_SETTLE_SECONDS)


def reload_from_origin(window_id: int | None = None) -> None:
    """Use the existing Option+Command+R method, after confirming focus."""
    script = SAFARI_FOREGROUND_SCRIPT + '''
on run argv
    my focusSafari()
    tell application "Safari"
        if (count of windows) = 0 then error "No Safari window to force reload."
        if (count of argv) > 0 then
            set targetWindow to window id (item 1 of argv as integer)
            set index of targetWindow to 1
        end if
    end tell
    tell application "System Events" to keystroke "r" using {option down, command down}
end run
'''
    args = () if window_id is None else (str(window_id),)
    run_safari_script(script, *args)


@dataclass
class SafariSession:
    """Reuse one collection window and navigate only when the page changes."""
    window_id: int | None = None
    loaded_url: str | None = None
    # A GUI user may navigate in Safari between visits. Batch collection retains
    # its existing preparation behaviour; guided capture additionally checks this.
    verify_url: bool = False

    def prepare(self, url: str) -> None:
        if self.window_id is None or not safari_window_exists(self.window_id):
            self.window_id = open_private_window()
            self.loaded_url = None
        needs_navigation = self.loaded_url != url
        if not needs_navigation and self.verify_url:
            actual = urldefrag(safari_window_url(self.window_id))[0].rstrip('/')
            needs_navigation = actual != urldefrag(url)[0].rstrip('/')
        if needs_navigation:
            load_in_safari(url, window_id=self.window_id)
            time.sleep(PRELOAD_SETTLE_SECONDS)
            self.loaded_url = url


class CaptureCancelled(RuntimeError):
    """A cancelled guided visit must not be classified as a complete capture."""


def capture_visit(site_url: str, site_dir: Path, visit_idx: int,
                  interface: str = DEFAULT_INTERFACE, *,
                  session: SafariSession | None = None,
                  cancel_event: threading.Event | None = None,
                  progress: Callable[[str], None] | None = None) -> Path:
    """Capture one visit; stop on every exit path and discard failed traces.

    A returned path means capture ran for its intended window and contains at
    least one packet. It does not independently verify the webpage's content.
    """
    if CAPTURE_SECONDS <= 0:
        raise ValueError("CAPTURE_SECONDS must be positive.")
    prefix = f"{sanitize_name(site_url)}_{visit_idx}"
    pcap_path = None
    session = SafariSession() if session is None else session
    stage = 'prepare collection window and page'

    def check_cancelled():
        if cancel_event is not None and cancel_event.is_set():
            raise CaptureCancelled('Visit cancelled; partial recording discarded.')

    def report(message):
        if progress is not None:
            progress(message)

    print(f"[+] Visit {visit_idx}: {site_url}")
    try:
        check_cancelled()
        report('Preparing the page in the Private Safari window…')
        session.prepare(site_url)
        check_cancelled()
        stage = 'start capture'
        report('Starting traffic recording…')
        proc, pcap_path = start_capture(
            interface=interface, out_dir=str(site_dir), prefix=prefix, fixed=False,
        )
        try:
            check_cancelled()
            print("    [>] Capture ready; force reloading with Option+Command+R")
            stage = 'force reload'
            report('Recording is ready; force reloading the page…')
            reload_started = time.monotonic()
            reload_from_origin(window_id=session.window_id)
            check_cancelled()
            remaining = CAPTURE_SECONDS - (time.monotonic() - reload_started)
            if remaining <= 0:
                raise RuntimeError("Safari force-reload command exceeded the capture window.")
            stage = 'record force reload'
            report(f'Recording the {CAPTURE_SECONDS:g}-second force reload…')
            if cancel_event is None:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass  # Expected: capture is still running at the end.
                else:
                    raise RuntimeError(f"Capture ended before being stopped (code {proc.returncode}).")
            else:
                # Keep the same deadline as batch capture, while allowing the
                # GUI to cancel. Always stop the child in the finally block.
                deadline = reload_started + CAPTURE_SECONDS
                while remaining > 0:
                    check_cancelled()
                    try:
                        proc.wait(timeout=min(remaining, 0.1))
                    except subprocess.TimeoutExpired:
                        remaining = deadline - time.monotonic()
                    else:
                        raise RuntimeError(f"Capture ended before being stopped (code {proc.returncode}).")
                check_cancelled()
        finally:
            stop_capture(proc)

        stage = 'validate recording'
        report('Checking the completed recording…')
        if proc.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT):
            raise RuntimeError(f"Capture did not stop cleanly (code {proc.returncode}).")
        # Reject empty or unreadable recordings instead of silently training on them.
        packet = subprocess.run(
            ["tshark", "-r", pcap_path, "-c", "1", "-T", "fields", "-e", "frame.number"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        if not packet.stdout.strip():
            raise RuntimeError("Capture contains no packets.")
        check_cancelled()
        print(f"    [✓] Wrote {pcap_path}")
        return Path(pcap_path)
    except BaseException as exc:
        # A partial trace must not be picked up as a successful training visit.
        if pcap_path is not None:
            Path(pcap_path).unlink(missing_ok=True)
        if isinstance(exc, CaptureCancelled):
            raise
        if isinstance(exc, Exception):
            raise RuntimeError(f"{stage}: {exc}") from exc
        raise


def run_collection(sites: list[str] | None = None, *,
                   dataset_dir: Path = DATASET_DIR,
                   interface: str = DEFAULT_INTERFACE,
                   visits_per_site: int | None = None) -> bool:
    """Run the full batch; retry failed visits and persist the actual errors."""
    sites = SITES if sites is None else sites
    visits = VISITS_PER_SITE if visits_per_site is None else visits_per_site
    if visits < 1:
        raise ValueError('Visits per page must be positive.')
    dataset_dir.mkdir(parents=True, exist_ok=True)
    succeeded = failed = 0
    session = SafariSession()
    log_path = dataset_dir / 'collection_log.jsonl'
    def log_visit(**event):
        event['time_utc'] = datetime.now(timezone.utc).isoformat()
        with log_path.open('a') as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + '\n')
    log_visit(status='batch_started', interface=interface,
              capture_seconds=CAPTURE_SECONDS, method='Option+Command+R',
              preload_settle_seconds=PRELOAD_SETTLE_SECONDS, sites=sites,
              reuse_private_window=True)
    try:
        for site in sites:
            site_dir = dataset_dir / sanitize_name(site)
            site_dir.mkdir(parents=True, exist_ok=True)
            print(f"\n=== {site}: {visits} visits → {site_dir} ===")
            for i in range(1, visits + 1):
                for attempt in range(1, MAX_VISIT_ATTEMPTS + 1):
                    try:
                        path = capture_visit(site, site_dir, i, interface=interface,
                                             session=session)
                    except Exception as exc:
                        log_visit(status='attempt_failed', url=site, visit=i,
                                  attempt=attempt, error=str(exc))
                        print(f"    [!] Attempt {attempt}/{MAX_VISIT_ATTEMPTS} failed: {exc}")
                        if attempt == MAX_VISIT_ATTEMPTS:
                            failed += 1
                        else:
                            time.sleep(DELAY_BETWEEN_VISITS)
                    else:
                        succeeded += 1
                        log_visit(status='saved', url=site, visit=i,
                                  attempt=attempt, pcap=str(path))
                        break
                time.sleep(DELAY_BETWEEN_VISITS)
    finally:
        log_visit(status='batch_finished', saved=succeeded, failed=failed)
        print(f"\nCollection summary: {succeeded} saved, {failed} failed.")
        print(f"Detailed log: {log_path}")
    return failed == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--out-dir", type=Path, default=DATASET_DIR,
                        help="Raw dataset root; use a fresh folder to separate old captures.")
    parser.add_argument('--visits-per-site', type=int, default=VISITS_PER_SITE,
                        help=f'Visits to collect for each configured page (default: {VISITS_PER_SITE})')
    args = parser.parse_args()
    if args.visits_per_site < 1:
        parser.error('--visits-per-site must be positive')
    dataset_dir = args.out_dir.expanduser().resolve()
    print(f"Dataset dir: {dataset_dir}")
    print(f"Interface: {args.interface}; capture window: {CAPTURE_SECONDS}s")
    return 0 if run_collection(dataset_dir=dataset_dir, interface=args.interface,
                               visits_per_site=args.visits_per_site) else 1


if __name__ == '__main__':
    raise SystemExit(main())
