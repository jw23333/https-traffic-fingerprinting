#!/usr/bin/env python3
"""
process_pcap.py

Beginner-friendly helper to read a .pcap, extract only HTTPS packets (TCP/UDP 443),
label direction (outgoing/incoming), compute a signed length (+out, -in), and
save everything to a CSV for analysis.

Requirements:
- tshark must be installed (brew install wireshark)
- You do NOT need sudo to run this script (reading .pcap is a normal file read)

Example:
    python3 process_pcap.py --pcap ./safari_20251027T142659Z.pcap --iface en1
"""

import argparse       # parse command-line arguments
import csv            # write the output CSV file
import os             # file paths
import subprocess     # run tshark and ipconfig commands
from pathlib import Path

# The same BPF filter we used for capture: HTTPS (TLS/QUIC)
HTTPS_BPF_FILTER = "tcp.port==443 || udp.port==443"


def get_local_ips(iface: str) -> set[str]:
    """Return a set of local IP addresses (IPv4 and IPv6) for the interface on macOS.

    We primarily parse `ifconfig <iface>` to collect both IPv4 (inet) and IPv6 (inet6)
    addresses. As a fallback for IPv4, we attempt `ipconfig getifaddr <iface>`.
    Zone IDs in IPv6 (e.g., "%en0") are stripped for matching with tshark output.
    """
    addrs: set[str] = set()

    # Parse ifconfig output for both inet and inet6 addresses
    try:
        proc = subprocess.run([
            "ifconfig", iface
        ], check=True, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            line = line.strip()
            # IPv4 lines look like: "inet 192.168.1.10 netmask ..."
            if line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2:
                    addrs.add(parts[1])
            # IPv6 lines look like: "inet6 fe80::1%en0 prefixlen ... scopeid ..."
            elif line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    # Strip zone id if present (e.g., fe80::1%en0)
                    if "%" in addr:
                        addr = addr.split("%", 1)[0]
                    addrs.add(addr)
    except subprocess.CalledProcessError:
        # ifconfig failed; we'll try an IPv4-only fallback below
        pass

    # Fallback: ipconfig getifaddr (IPv4 only)
    if not any("." in a for a in addrs):
        try:
            result = subprocess.run(
                ["ipconfig", "getifaddr", iface],
                check=True,
                capture_output=True,
                text=True,
            )
            ipv4 = result.stdout.strip()
            if ipv4:
                addrs.add(ipv4)
        except subprocess.CalledProcessError:
            # Ignore; we'll validate later
            pass

    if not addrs:
        raise RuntimeError(
            f"Could not determine local IPs for interface '{iface}'. "
            "Run 'tshark -D' to confirm your interface and try again."
        )

    return addrs


def run_tshark_fields(pcap_path: str) -> list:
    """Use tshark to extract useful packet fields from the .pcap.

        We output these columns:
            time, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, tcp.stream, udp.stream, protocol

        Returns:
            A list of dicts, one per packet.
    """
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-Y", HTTPS_BPF_FILTER,
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "frame.len",
        "-e", "tcp.stream",
        "-e", "udp.stream",
        "-e", "_ws.col.Protocol",
    "-E", "header=y",
    "-E", "separator=,",
    "-E", "quote=n",
    "-E", "occurrence=f",
    ]

    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise FileNotFoundError("tshark not found. Install it with: brew install wireshark")

    # Parse CSV text into a list of dicts
    rows = []
    reader = csv.DictReader(proc.stdout.splitlines())
    for row in reader:
        rows.append(row)
    return rows


def add_direction_and_signed_len(rows: list, local_ips: set[str]) -> list:
    """Add 'direction' ('out'/'in') and 'signed_len' (+/- frame.len) to each packet.

    Direction is determined by whether the packet source address (IPv4 or IPv6)
    matches any of the local interface addresses.

    direction = 'out' if ip.src/ipv6.src in local_ips else 'in'
    signed_len = +frame.len for outgoing, -frame.len for incoming
    """
    result = []
    for row in rows:
        src_v4 = row.get('ip.src', '') or ''
        src_v6 = row.get('ipv6.src', '') or ''
        src = src_v4 if src_v4 else src_v6

        frame_len = row.get('frame.len', '')
        try:
            length = int(frame_len) if frame_len else 0
        except ValueError:
            length = 0

        direction = 'out' if src in local_ips else 'in'
        signed_len = length if direction == 'out' else -length

        new_row = dict(row)
        new_row['direction'] = direction
        new_row['signed_len'] = str(signed_len)
        result.append(new_row)
    return result


def write_csv(rows: list, out_csv: Path) -> None:
    """Write rows (list of dicts) to a CSV file with a stable column order."""
    if not rows:
        # Create an empty CSV with headers so downstream code doesn't break.
        headers = [
            'frame.time_relative','ip.src','ip.dst','ipv6.src','ipv6.dst','frame.len',
            'tcp.stream','udp.stream','_ws.col.Protocol','direction','signed_len'
        ]
        with out_csv.open('w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
        return

    # Define the column order; ensure all keys exist.
    fieldnames = [
        'frame.time_relative','ip.src','ip.dst','ipv6.src','ipv6.dst','frame.len',
        'tcp.stream','udp.stream','_ws.col.Protocol','direction','signed_len'
    ]
    with out_csv.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            # Fill missing keys with empty string
            out = {k: r.get(k, '') for k in fieldnames}
            w.writerow(out)


def default_out_csv_path(pcap_path: str) -> Path:
    """Return a default CSV path next to the pcap, with _dir.csv suffix."""
    p = Path(pcap_path)
    return p.with_name(p.stem + "_dir.csv")

def compute_bursts(labeled_rows: list, gap_seconds: float = 0.05) -> list:
    """Group packets into bursts: consecutive packets with same direction and small time gaps.

    A burst is represented as a dict with keys:
      start, end (float seconds), dir ('out'/'in'), count (int), bytes (int)
      stream (tcp.stream or 'udp:<id>' if available), proto (from _ws.col.Protocol)
    """
    # Sort by time to ensure correct order
    rows = sorted(labeled_rows, key=lambda x: float(x['frame.time_relative']))

    bursts = []
    current = None

    def flush():
        if current and current['count'] > 0:
            bursts.append(current.copy())

    for r in rows:
        t = float(r['frame.time_relative']) if r.get('frame.time_relative') else 0.0
        direction = r.get('direction', 'out')
        size = abs(int(r.get('signed_len', '0') or 0))
        proto = r.get('_ws.col.Protocol', '')
        tcp_stream = r.get('tcp.stream', '')
        udp_stream = r.get('udp.stream', '')
        stream = tcp_stream or (f"udp:{udp_stream}" if udp_stream else '')

        if current is None:
            current = {
                'start': t, 'end': t, 'dir': direction,
                'count': 1, 'bytes': size,
                'stream': stream, 'proto': proto,
            }
            continue

        same_dir = (direction == current['dir'])
        gap_ok = (t - current['end']) <= gap_seconds

        if same_dir and gap_ok:
            current['end'] = t
            current['count'] += 1
            current['bytes'] += size
        else:
            flush()
            current = {
                'start': t, 'end': t, 'dir': direction,
                'count': 1, 'bytes': size,
                'stream': stream, 'proto': proto,
            }

    flush()
    return bursts


def bursts_to_pairs(bursts: list) -> list:
    """Convert a list of bursts into out->in burst pairs.

    We only keep pairs where an outgoing burst is immediately followed by an incoming burst.
    Each pair is a dict with keys:
      index, out_bytes, in_bytes, out_pkts, in_pkts,
      out_start, out_end, in_start, in_end
    """
    pairs = []
    idx = 0
    i = 0
    while i + 1 < len(bursts):
        b1 = bursts[i]
        b2 = bursts[i + 1]
        if b1['dir'] == 'out' and b2['dir'] == 'in':
            pairs.append({
                'index': idx,
                'out_bytes': b1['bytes'], 'in_bytes': b2['bytes'],
                'out_pkts': b1['count'], 'in_pkts': b2['count'],
                'out_start': b1['start'], 'out_end': b1['end'],
                'in_start': b2['start'], 'in_end': b2['end'],
            })
            idx += 1
            i += 2
        else:
            # Skip bursts that don't form an out->in pair
            i += 1
    return pairs


def get_pairs_from_pcap(pcap_path: str, iface: str, gap_ms: float = 50.0) -> list:
        """Return burst pairs parsed from a pcap entirely in-memory.

        This is the convenient backend function other modules should call when
        they want to process a pcap without writing intermediate CSV files.

        Returns:
            A list of pair dicts (same format as written by `write_pairs_csv`).
        """
        pcap_path = os.path.abspath(os.path.expanduser(pcap_path))

        # Determine local IPs for direction labeling
        local_ips = get_local_ips(iface)

        # Extract packet fields from the pcap using tshark
        rows = run_tshark_fields(pcap_path)

        # Label packets and compute bursts/pairs
        labeled = add_direction_and_signed_len(rows, local_ips)
        bursts = compute_bursts(labeled, gap_seconds=gap_ms / 1000.0)
        pairs = bursts_to_pairs(bursts)
        return pairs


def write_pairs_csv(pairs: list, out_csv: Path) -> None:
    """Write burst pairs to CSV."""
    fieldnames = [
        'index','out_bytes','in_bytes','out_pkts','in_pkts',
        'out_start','out_end','in_start','in_end'
    ]
    with out_csv.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for p in pairs:
            w.writerow({k: p.get(k, '') for k in fieldnames})


def default_pairs_csv_path(pcap_path: str) -> Path:
    """Return a default CSV path next to the pcap, with _pairs.csv suffix."""
    p = Path(pcap_path)
    return p.with_name(p.stem + "_pairs.csv")


def process_pcap(
    pcap_path: str,
    iface: str,
    packets_csv: str | None,
    pairs_csv: str | None,
    gap_ms: float = 50.0,
) -> tuple[Path | None, Path]:
    """Full processing pipeline: extract -> label -> bursts -> pairs.

    Args:
      pcap_path: path to the .pcap file to process
      iface:     capture interface name (used to get local IP, e.g., en0)
      packets_csv: optional path to save per-packet CSV (if None, skip)
      pairs_csv:   optional path to save burst-pairs CSV (default: <pcap>_pairs.csv)
      gap_ms:      gap threshold in milliseconds to split bursts (default 50 ms)
    Returns:
      (packets_csv_path_or_None, pairs_csv_path)
    """
    pcap_path = os.path.abspath(os.path.expanduser(pcap_path))
    pairs_path = Path(os.path.expanduser(pairs_csv)) if pairs_csv else default_pairs_csv_path(pcap_path)
    packets_path = Path(os.path.expanduser(packets_csv)) if packets_csv else None

    print(f"[+] Reading: {pcap_path}")
    local_ips = get_local_ips(iface)
    print(f"[+] Local IPs on {iface}: {', '.join(sorted(local_ips))}")

    print("[+] Extracting packet fields with tshark...")
    rows = run_tshark_fields(pcap_path)
    print(f"[+] Packets extracted: {len(rows)}")

    print("[+] Labeling direction and computing signed lengths...")
    labeled = add_direction_and_signed_len(rows, local_ips)

    # Optionally write per-packet CSV (debugging/inspection)
    if packets_path:
        print(f"[+] Writing per-packet CSV -> {packets_path}")
        write_csv(labeled, packets_path)

    print("[+] Building bursts...")
    bursts = compute_bursts(labeled, gap_seconds=gap_ms/1000.0)
    print(f"[+] Bursts: {len(bursts)}")

    print("[+] Making out->in burst pairs...")
    pairs = bursts_to_pairs(bursts)
    print(f"[+] Pairs: {len(pairs)}")

    print(f"[+] Writing burst pairs CSV -> {pairs_path}")
    write_pairs_csv(pairs, pairs_path)

    print("[✓] Done")
    return (packets_path, pairs_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Process a .pcap into burst pairs (optionally also save per-packet CSV)."
    )
    parser.add_argument('--pcap', required=True, help='Path to the .pcap file to process')
    parser.add_argument('--iface', default='en1', help='Network interface used for capture (default: en1)')
    parser.add_argument('--gap-ms', type=float, default=50.0, help='Gap (ms) to separate bursts (default: 50)')
    parser.add_argument('--pairs-csv', default=None, help='Output burst-pairs CSV path (default: <pcap>_pairs.csv)')
    parser.add_argument('--packets-csv', default=None, help='Optional per-packet CSV path (omit to skip)')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        process_pcap(
            pcap_path=args.pcap,
            iface=args.iface,
            packets_csv=args.packets_csv,
            pairs_csv=args.pairs_csv,
            gap_ms=args.gap_ms,
        )
    except FileNotFoundError as e:
        print(f"[!] {e}")
    except RuntimeError as e:
        print(f"[!] {e}")
    except subprocess.CalledProcessError as e:
        print(f"[!] tshark failed: {e}")


if __name__ == '__main__':
    main()
