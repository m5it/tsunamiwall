#!/usr/bin/env python3
"""Convenience viewer for TsunamiWall logs.

Reads the JSONL hit log and the per-country payload directories under the
current config's log_dir and presents the data in easy-to-read tables.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

# Add project root to the path so we can import tsunamiwall.config.
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsunamiwall.config import load_config


DEFAULT_TAIL = 50


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tsunamiwall-logs",
        description="View TsunamiWall honeypot hits and captured payloads.",
    )
    parser.add_argument(
        "--config",
        "-c",
        metavar="PATH",
        help="path to TsunamiWall YAML config file (default: auto-detect)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    recent_p = sub.add_parser("recent", help=f"show the last {DEFAULT_TAIL} honeypot hits")
    recent_p.add_argument("count", type=int, nargs="?", default=DEFAULT_TAIL, help="number of hits")

    sub.add_parser("tail", help="follow the live hit log (like tail -f)")

    by_ip = sub.add_parser("by-ip", help="show hits from one source IP")
    by_ip.add_argument("ip", help="source IPv4/IPv6 address")

    by_country = sub.add_parser("by-country", help="show hits from one country code")
    by_country.add_argument("country", help="two-letter country code (e.g. US, CN)")

    by_dst = sub.add_parser("by-dst", help="show hits on a destination port")
    by_dst.add_argument("port", type=int, help="destination port")

    payloads = sub.add_parser("payloads", help="list or show captured payloads")
    payloads.add_argument("ip", nargs="?", help="filter payloads by source IP")
    payloads.add_argument("--country", metavar="CC", help="filter payloads by country code")
    payloads.add_argument("--last", type=int, metavar="N", help="show only the N most recent payloads")

    sub.add_parser("stats", help="summary statistics: top IPs, countries and probed ports")

    dropped_p = sub.add_parser(
        "dropped",
        help="show top destination ports recently dropped by TsunamiWall (from dmesg/syslog)",
    )
    dropped_p.add_argument("count", type=int, nargs="?", default=20, help="number of ports to show")

    return parser


def _load_config(args: argparse.Namespace) -> tuple:
    """Return (config, log_dir_path)."""
    cfg = load_config(args.config if args.config else None)
    return cfg, Path(cfg.log_dir)


def _iter_hits(log_dir: Path) -> Iterator[dict]:
    """Yield JSON hit records from the hit log, oldest first."""
    path = log_dir / "hits.logl"
    try:
        if not path.exists():
            return
    except PermissionError as exc:
        raise PermissionError(
            f"Cannot read {path}: permission denied (try sudo)."
        ) from exc
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _format_hit(obj: dict) -> str:
    return (
        f"{obj.get('time', '?'):26} "
        f"{obj.get('src_ip', '?'):20} "
        f"country={obj.get('country_code', '?'):4} "
        f"src_port={obj.get('src_port', 0):6} "
        f"dst_port={obj.get('dst_port', 0):6} "
        f"size={obj.get('payload_size', 0):5}"
    )


def _print_hits(hits: list[dict]) -> None:
    if not hits:
        print("No hits.")
        return
    print(f"{'TIME':26} {'SRC IP':20} {'CC':4} {'SPORT':6} {'DPORT':6} {'SIZE':5}")
    print("-" * 80)
    for obj in hits:
        print(_format_hit(obj))


def cmd_recent(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = list(_iter_hits(log_dir))[-args.count :]
    _print_hits(hits)
    return 0


def cmd_tail(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    path = log_dir / "hits.logl"
    if not path.exists():
        print(f"Hit log not found: {path}")
        return 1

    print("Following hit log. Press Ctrl+C to stop.")
    with open(path, "r", encoding="utf-8") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                print(_format_hit(obj))
            except json.JSONDecodeError:
                pass


def cmd_by_ip(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = [h for h in _iter_hits(log_dir) if h.get("src_ip") == args.ip]
    _print_hits(hits)
    return 0


def cmd_by_country(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    cc = args.country.upper()
    hits = [h for h in _iter_hits(log_dir) if h.get("country_code", "").upper() == cc]
    _print_hits(hits)
    return 0


def cmd_by_dst(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    port = args.port
    hits = [h for h in _iter_hits(log_dir) if h.get("dst_port") == port]
    _print_hits(hits)
    return 0


def _payload_files(log_dir: Path, ip_filter: str | None = None, country_filter: str | None = None) -> list[Path]:
    """Return payload files matching optional filters, newest first."""
    base = log_dir / "bycountry"
    if not base.exists():
        return []
    patterns: list[str] = []
    if country_filter:
        cc = country_filter.upper()
        if ip_filter:
            patterns.append(f"{cc}/{ip_filter}/*")
        else:
            patterns.append(f"{cc}/*/*")
    elif ip_filter:
        patterns.append(f"*/{ip_filter}/*")
    else:
        patterns.append("*/*/*")

    files: list[Path] = []
    for pattern in patterns:
        files.extend(base.glob(pattern))
    # Sort by mtime descending.
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def _snip(path: Path, max_bytes: int = 2048) -> str:
    """Return a printable snippet of a raw payload file."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except Exception as exc:
        return f"<cannot read: {exc}>"
    if path.suffix == ".gz":
        try:
            data = gzip.decompress(data)
        except Exception:
            pass
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\n", " ").replace("\r", " ")
    if len(data) >= max_bytes:
        text += " ..."
    return text


def cmd_payloads(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    files = _payload_files(log_dir, ip_filter=args.ip, country_filter=args.country)
    if not files:
        print("No payloads found.")
        return 0

    if args.last:
        files = files[: args.last]

    print(f"{'COUNTRY':8} {'IP':20} {'TIME':20} {'FILE'}")
    print("-" * 100)
    for path in files:
        # Path is like .../bycountry/CC/IP/filename
        parts = path.relative_to(log_dir / "bycountry").parts
        cc = parts[0] if len(parts) > 0 else "?"
        ip = parts[1] if len(parts) > 1 else "?"
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))
        print(f"{cc:8} {ip:20} {mtime:20} {path}")
        print("  snippet:", _snip(path)[:160])
        print()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = list(_iter_hits(log_dir))
    if not hits:
        print("No hits to summarize.")
        return 0

    ips = Counter(h.get("src_ip", "?") for h in hits)
    countries = Counter(h.get("country_code", "?") for h in hits)
    dports = Counter(h.get("dst_port", 0) for h in hits)

    print(f"Total hits: {len(hits)}")
    print()
    print("Top source IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {ip:20} {count}")
    print()
    print("Top countries:")
    for cc, count in countries.most_common(10):
        print(f"  {cc:4} {count}")
    print()
    print("Top probed destination ports:")
    for port, count in dports.most_common(10):
        print(f"  {port:6} {count}")
    return 0


def _drop_log_lines() -> Iterable[str]:
    """Yield raw lines from the best available kernel log source."""
    permission_denied = False

    # Prefer dmesg because it includes iptables LOG entries even when
    # nothing is written to disk.
    try:
        result = subprocess.run(
            ["dmesg"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            yield from result.stdout.splitlines()
            return
        if "not permitted" in result.stderr.lower() or "operation not permitted" in result.stderr.lower() or "permission" in result.stderr.lower():
            permission_denied = True
    except (FileNotFoundError, PermissionError):
        permission_denied = True

    # Fallback to common on-disk log files.
    for candidate in ("/var/log/kern.log", "/var/log/syslog", "/var/log/messages"):
        try:
            with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                yield from fh
            return
        except PermissionError:
            permission_denied = True
        except FileNotFoundError:
            continue

    if permission_denied:
        raise PermissionError("Cannot read kernel logs: permission denied (try sudo).")


def _dropped_ports() -> Counter[int]:
    """Count TsunamiWall-dropped destination ports from available logs."""
    counter: Counter[int] = Counter()
    for line in _drop_log_lines():
        if "TSUNAMIWALL-DROP:" not in line:
            continue
        # Extract DPT=<port> from iptables LOG messages.
        for token in line.split():
            if token.startswith("DPT="):
                try:
                    counter[int(token.split("=", 1)[1])] += 1
                except ValueError:
                    pass
    return counter


def cmd_dropped(args: argparse.Namespace) -> int:
    try:
        ports = _dropped_ports()
    except PermissionError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    if not ports:
        print("No recent TsunamiWall drops found in dmesg/syslog.")
        print("(Drops are logged by iptables as TSUNAMIWALL-DROP: ... DPT=<port>)")
        return 0

    print(f"{'DST PORT':>10} {'DROPS':>8}")
    print("-" * 20)
    for port, count in ports.most_common(args.count):
        print(f"{port:>10} {count:>8}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    dispatch = {
        "recent": cmd_recent,
        "tail": cmd_tail,
        "by-ip": cmd_by_ip,
        "by-country": cmd_by_country,
        "by-dst": cmd_by_dst,
        "payloads": cmd_payloads,
        "stats": cmd_stats,
        "dropped": cmd_dropped,
    }
    try:
        return dispatch[args.command](args)
    except PermissionError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
