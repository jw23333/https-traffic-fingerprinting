#!/usr/bin/env python3
"""
capture_safari_all.py

Goal
-----
Capture ONLY HTTPS traffic (TCP 443 and UDP 443) on macOS for a fixed
duration and save it to a .pcap file suitable for website fingerprinting
research (packet timing/length/direction; no decryption).

Notes
-----
- You will likely need to run this with elevated privileges to capture on
  network interfaces, e.g. `sudo python3 capture_safari_all.py`.
- Requires tshark to be installed via Homebrew: `brew install wireshark`.
- The code is structured into small functions so you can later build a
  Tkinter GUI with Start/Stop buttons that reuse this backend.

Example capture command (what this script constructs and runs under the hood):
  tshark -i en0 -a duration:<seconds> -w <output>.pcap -f "tcp port 443 or udp port 443"
"""

# Standard library imports
import os                      # for file paths, directories, and environment queries
import shutil                  # to check if tshark is available on PATH
import subprocess              # to run external commands (like tshark)
from datetime import datetime  # to generate timestamped filenames
import signal                  # to send signals when stopping background capture


# ----------------------------- Constants -----------------------------
# Default capture interface (Wi‑Fi on this Mac). You can override via CLI.
DEFAULT_INTERFACE = "en1"  # run `tshark -D` to list interfaces on your system

# Default capture duration in seconds; change with --seconds on CLI.
DEFAULT_SECONDS = 10

# BPF capture filter that selects ONLY HTTPS traffic (TCP + UDP on port 443).
HTTPS_BPF_FILTER = "tcp port 443 or udp port 443"

# Default output directory: the folder where this script lives (your project).
# You can still override with --out-dir if you want a different location.
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = PROJECT_DIR


def ensure_directory(path: str) -> None:
    """Create the output directory if it does not exist.

    Args:
        path: Absolute or user-relative path ("~" supported) to create.
    """
    # Expand a user path like "~/wf_traces" to a full absolute path.
    expanded = os.path.expanduser(path)
    # Create the directory and parents if they are missing; do nothing if exists.
    os.makedirs(expanded, exist_ok=True)


def build_pcap_path(out_dir: str, prefix: str = "safari") -> str:
    """Construct a timestamped .pcap filename inside the output directory.

    Args:
        out_dir: Directory where the pcap should be written.
        prefix: Filename prefix to help identify the capture (default: "safari").
    Returns:
        Absolute path to the pcap file, e.g., /Users/me/wf_traces/safari_20251027T113500Z.pcap
    """
    # Use UTC time for consistent ordering across machines/time zones.
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    # Compose a filename like safari_20251027T113500Z.pcap.
    filename = f"{prefix}_{timestamp}.pcap"
    # Join the directory and filename into an absolute path.
    return os.path.join(os.path.expanduser(out_dir), filename)


def check_tshark_available() -> None:
    """Ensure tshark is installed and available in PATH.

    Raises:
        FileNotFoundError: If tshark cannot be found on PATH.
    """
    # shutil.which returns the absolute path to the executable if found, else None.
    if shutil.which("tshark") is None:
        # Provide a helpful message for macOS users to install via Homebrew.
        raise FileNotFoundError(
            "tshark not found. Install it with: brew install wireshark"
        )


def build_tshark_cmd(interface: str, seconds: int, pcap_path: str, bpf_filter: str = HTTPS_BPF_FILTER) -> list:
    """Build the tshark command that captures only HTTPS traffic for a fixed duration.

    Args:
        interface: The network interface to capture on (e.g., "en0").
        seconds:   How long to capture before automatically stopping.
        pcap_path: Where to write the .pcap file.
        bpf_filter: Berkeley Packet Filter string to select desired traffic.
    Returns:
        A list representing the command and arguments to pass to subprocess.
    """
    # Construct a list of command parts exactly as they would appear in the shell.
    # -i <iface> chooses the interface; -a duration:N stops automatically after N seconds;
    # -w <file> writes raw packets to a pcap file; -f <filter> applies a capture filter.
    return [
        "tshark",
        "-i", interface,
        "-a", f"duration:{seconds}",
        "-w", pcap_path,
        "-f", bpf_filter,
    ]


# ----------------------- Flexible capture API -----------------------
def start_capture(interface: str,
                  out_dir: str,
                  prefix: str = "safari",
                  duration: int | None = None,
                  fixed: bool = False):
    """Start a capture in either fixed-duration or manual (start/stop) mode.

    Behavior
    --------
    - When fixed is True and duration is provided: runs tshark with
      "-a duration:<seconds>" and blocks until completion. Returns (None, pcap_path).
    - When fixed is False: starts a background capture (no auto-stop) using Popen
      and returns (proc, pcap_path) so callers can stop it later via stop_capture().

    Args:
        interface: Network interface to capture on (e.g., "en0").
        out_dir:   Output directory where the .pcap will be written.
        prefix:    Filename prefix for the pcap.
        duration:  Duration in seconds for fixed-duration mode.
        fixed:     If True, block for a fixed duration; else run in background.

    Returns:
        Tuple[proc|None, str]: (subprocess.Popen or None, pcap_path)

    Raises:
        ValueError: If fixed=True but duration is not provided.
        FileNotFoundError / CalledProcessError: bubbled up from tshark checks/runs.
    """
    check_tshark_available()
    ensure_directory(out_dir)
    pcap_path = build_pcap_path(out_dir, prefix=prefix)

    if fixed:
        if duration is None:
            raise ValueError("duration must be provided when fixed=True")
        # Use the existing helper that includes -a duration
        cmd = build_tshark_cmd(interface, duration, pcap_path, HTTPS_BPF_FILTER)
        print(f"[+] Capturing HTTPS (TCP/UDP 443) on interface '{interface}' for {duration} seconds...")
        print(f"[+] Writing to: {pcap_path}")
        print(f"[+] Command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"[✓] Capture complete -> {pcap_path}")
        return None, pcap_path

    # Manual start/stop mode: build a command WITHOUT -a duration
    cmd = [
        "tshark",
        "-i", interface,
        "-w", pcap_path,
        "-f", HTTPS_BPF_FILTER,
    ]
    print(f"[+] Starting background HTTPS capture on '{interface}' (manual stop)...")
    print(f"[+] Writing to: {pcap_path}")
    print(f"[+] Command: {' '.join(cmd)}")

    # Start tshark in its own process group so we can stop it cleanly via os.killpg.
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,  # capture errors so we can report permission issues
        preexec_fn=os.setsid,  # create a new session/process group (POSIX/macOS)
        text=True,
    )

    # If tshark dies immediately (e.g., due to permissions), surface the error now.
    try:
        proc_ret = proc.wait(timeout=0.3)
    except subprocess.TimeoutExpired:
        # Still running; that’s fine.
        return proc, pcap_path

    # If we get here, the process exited too soon — raise with stderr contents.
    stderr_out = proc.stderr.read() if proc.stderr else ""
    raise RuntimeError(f"tshark exited early with code {proc_ret}. Stderr: {stderr_out.strip()}")
    return proc, pcap_path


def stop_capture(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Stop a background capture started by start_capture(..., fixed=False).

    Sends SIGINT to the tshark process group for a graceful shutdown so that
    the pcap file is properly finalized. If the process does not exit within
    'timeout' seconds, escalates to SIGTERM and then SIGKILL as a last resort.

    Args:
        proc:    The subprocess.Popen returned by start_capture.
        timeout: Seconds to wait for graceful shutdown before escalating.
    """
    if proc is None:
        return

    # If it's already finished, nothing to do.
    if proc.poll() is not None:
        return

    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        # Fallback: try to terminate the single process
        try:
            proc.terminate()
            proc.wait(timeout=timeout)
            return
        except Exception:
            return

    try:
        # Ask tshark to stop nicely so it writes the capture footer.
        os.killpg(pgid, signal.SIGINT)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGTERM)
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
            proc.wait()

