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

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tsunamiwall.config import load_config
from tsunamiwall.util import _format_hit_time

DEFAULT_TAIL = 50


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tsunamiwall-logs",
        description="View TsunamiWall honeypot hits and captured payloads.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__import__('tsunamiwall').__version__}",
    )
    parser.add_argument(
        "--config",
        "-c",
        metavar="PATH",
        help="path to TsunamiWall YAML config file (default: auto-detect)",
    )

    # Top-level flags for viewing modes.  Exactly one viewing mode must be
    # supplied.  These replace the previous sub-command syntax, so users can
    # write ``tsunamiwall-logs --stats`` instead of ``tsunamiwall-logs stats``.
    viewing = parser.add_argument_group("viewing modes")
    viewing.add_argument(
        "--recent",
        "-r",
        action="store_true",
        help=f"show the last {DEFAULT_TAIL} honeypot hits (default mode)",
    )
    viewing.add_argument(
        "--tail",
        "-t",
        action="store_true",
        help="follow the live hit log (like tail -f)",
    )
    viewing.add_argument(
        "--stats",
        "-s",
        action="store_true",
        help="summary statistics: top IPs, countries and probed ports",
    )
    viewing.add_argument(
        "--dropped",
        "-d",
        action="store_true",
        help="show top destination ports recently dropped by TsunamiWall",
    )
    viewing.add_argument(
        "--payloads",
        "-p",
        action="store_true",
        help="list or show captured payloads",
    )
    viewing.add_argument(
        "--recent-payloads",
        "-P",
        action="store_true",
        help=f"show the last {DEFAULT_TAIL} hits with a snippet of any captured payload",
    )

    # Filters and counts.  Used by --recent, --recent-payloads and --payloads.
    parser.add_argument(
        "--ip",
        "-i",
        metavar="IP",
        help="filter by source IPv4/IPv6 address",
    )
    parser.add_argument(
        "--country",
        "-C",
        metavar="CC",
        help="filter by two-letter country code (e.g. US, CN)",
    )
    parser.add_argument(
        "--src-port",
        "-S",
        metavar="PORT",
        type=int,
        help="filter by source port",
    )
    parser.add_argument(
        "--dst-port",
        "-D",
        metavar="PORT",
        type=int,
        help="filter by destination port",
    )
    parser.add_argument(
        "--last",
        "-n",
        metavar="N",
        type=int,
        help=f"show only the N most recent hits/payloads (default {DEFAULT_TAIL})",
    )
    parser.add_argument(
        "--date",
        metavar="YYYY-MM-DD",
        help="filter to a single calendar day (e.g. 2026-10-20); applies to hits and payloads",
    )
    parser.add_argument(
        "--bytes",
        "-b",
        metavar="N",
        type=int,
        default=160,
        help="max payload bytes to preview (default: 160)",
    )

    # Backward compatibility: accept old positional sub-commands and their
    # arguments and translate them into the new flag/filter form.  This lets
    # existing scripts and muscle memory keep working while the CLI moves to
    # a pure argument style.
    parser.add_argument(
        "_compat",
        nargs="*",
        help=argparse.SUPPRESS,
    )

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
        f"{_format_hit_time(obj.get('time', '')):20} "
        f"{obj.get('family', 'ipv4'):6} "
        f"{obj.get('src_ip', '?'):20} "
        f"country={obj.get('country_code', '?'):4} "
        f"src_port={obj.get('src_port', 0):6} "
        f"dst_port={obj.get('dst_port', 0):6} "
        f"size={obj.get('payload_size', 0):5}"
    )


def _sort_hits(hits: list[dict]) -> list[dict]:
    """Sort hit records newest-first; fall back to file order if time is missing."""
    return sorted(hits, key=lambda h: h.get("time", ""), reverse=True)


def _print_hits(hits: list[dict]) -> None:
    if not hits:
        print("No hits.")
        return
    print(f"{'TIME':20} {'FAMILY':6} {'SRC IP':20} {'CC':4} {'SPORT':6} {'DPORT':6} {'SIZE':5}")
    print("-" * 74)
    for obj in hits:
        print(_format_hit(obj))


def _hit_matches_date(hit: dict, date_str: str | None) -> bool:
    """Return True if *hit* falls on the requested --date (YYYY-MM-DD)."""
    if not date_str:
        return True
    hit_time = hit.get("time", "")
    if not hit_time:
        return False
    # Hit timestamps are ISO-8601: "2026-10-20T12:34:56Z" or "2026-10-20T12:34:56".
    return hit_time[:10] == date_str


def _filter_hits(hits: Iterable[dict], args: argparse.Namespace) -> list[dict]:
    """Apply --ip, --country, --src-port, --dst-port and --date filters."""
    result = list(hits)
    if args.ip:
        result = [h for h in result if h.get("src_ip") == args.ip]
    if args.country:
        cc = args.country.upper()
        result = [h for h in result if h.get("country_code", "").upper() == cc]
    if args.src_port is not None:
        result = [h for h in result if h.get("src_port") == args.src_port]
    if args.dst_port is not None:
        result = [h for h in result if h.get("dst_port") == args.dst_port]
    date_filter = getattr(args, "date", None)
    if date_filter:
        result = [h for h in result if _hit_matches_date(h, date_filter)]
    return result


def cmd_recent(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = _sort_hits(list(_iter_hits(log_dir)))
    hits = _filter_hits(hits, args)
    limit = args.last if args.last is not None else DEFAULT_TAIL
    _print_hits(hits[:limit])
    return 0


def _print_hit_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        obj = json.loads(line)
        print(_format_hit(obj))
    except json.JSONDecodeError:
        pass


def _current_inode(path: Path) -> int | None:
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


def _tail_matches(args: argparse.Namespace, obj: dict) -> bool:
    """Return True if a live hit matches the active filters."""
    if args.ip and obj.get("src_ip") != args.ip:
        return False
    if args.country and obj.get("country_code", "").upper() != args.country.upper():
        return False
    if args.src_port is not None and obj.get("src_port") != args.src_port:
        return False
    if args.dst_port is not None and obj.get("dst_port") != args.dst_port:
        return False
    date_filter = getattr(args, "date", None)
    if date_filter and not _hit_matches_date(obj, date_filter):
        return False
    return True


def cmd_tail(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    path = log_dir / "hits.logl"
    if not path.exists():
        print(f"Hit log not found: {path}")
        return 1

    print("Following hit log. Press Ctrl+C to stop.")

    inode = _current_inode(path)
    fh = open(path, "r", encoding="utf-8")
    try:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if line:
                try:
                    obj = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                if _tail_matches(args, obj):
                    print(_format_hit(obj))
                continue

            # No new data; check whether the file was rotated.
            time.sleep(0.2)
            new_inode = _current_inode(path)
            if new_inode is not None and new_inode != inode:
                # The daemon rotated the log; reopen the current file.
                fh.close()
                inode = new_inode
                fh = open(path, "r", encoding="utf-8")
                fh.seek(0, os.SEEK_END)
    finally:
        fh.close()


def cmd_by_ip(args: argparse.Namespace) -> int:
    return cmd_recent(args)


def cmd_by_country(args: argparse.Namespace) -> int:
    return cmd_recent(args)


def cmd_by_dst(args: argparse.Namespace) -> int:
    return cmd_recent(args)


def _payload_files(
    log_dir: Path,
    ip_filter: str | None = None,
    country_filter: str | None = None,
    date_filter: str | None = None,
) -> list[Path]:
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

    if date_filter:
        start_of_day = time.mktime(time.strptime(date_filter, "%Y-%m-%d"))
        end_of_day = start_of_day + 86400
        files = [p for p in files if start_of_day <= p.stat().st_mtime < end_of_day]

    # Sort by mtime descending.
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def _payload_bytes(path: Path, max_bytes: int = 2048) -> bytes:
    """Read up to max_bytes from a payload file, gunzipping if needed."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except Exception as exc:
        return b""
    if path.suffix == ".gz":
        try:
            data = gzip.decompress(data)
        except Exception:
            pass
    return data


def _hex_snip(data: bytes, max_bytes: int = 256) -> str:
    r"""Return a \xNN hex representation of the first bytes."""
    preview = data[:max_bytes]
    return "".join(f"\\x{b:02x}" for b in preview)


def _text_snip(data: bytes, max_bytes: int = 2048) -> str:
    """Return a printable text snippet of the first bytes."""
    text = data[:max_bytes].decode("utf-8", errors="replace")
    text = text.replace("\n", " ").replace("\r", " ")
    if len(data) > max_bytes:
        text += " ..."
    return text


def _snip(path: Path, max_bytes: int = 2048) -> str:
    """Return a printable snippet of a raw payload file."""
    data = _payload_bytes(path, max_bytes)
    if not data:
        return "<empty or cannot read>"
    return _text_snip(data, max_bytes)


def cmd_payloads(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    ip_filter = args.ip
    country_filter = args.country
    files = _payload_files(
        log_dir,
        ip_filter=ip_filter,
        country_filter=country_filter,
        date_filter=args.date,
    )
    if not files:
        print("No payloads found.")
        return 0

    if args.dst_port is not None:
        suffix = f"_{args.dst_port}_"
        files = [p for p in files if suffix in p.name]

    if args.src_port is not None:
        suffix = f"_{args.src_port}.bin"
        files = [p for p in files if p.name.endswith(suffix)]

    limit = args.last if args.last is not None else DEFAULT_TAIL
    if limit:
        files = files[:limit]

    print(f"{'COUNTRY':8} {'IP':20} {'TIME':20} {'FILE'}")
    print("-" * 100)
    for path in files:
        # Path is like .../bycountry/CC/IP/filename
        parts = path.relative_to(log_dir / "bycountry").parts
        cc = parts[0] if len(parts) > 0 else "?"
        ip = parts[1] if len(parts) > 1 else "?"
        mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))
        data = _payload_bytes(path, 256)
        full_size = path.stat().st_size
        print(f"{cc:8} {ip:20} {mtime:20} {path} size={full_size}")
        print(f"  text({len(data)}):  ", _text_snip(data, 160))
        print(f"  hex({len(data)}):   ", _hex_snip(data, 160))
        print()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = list(_iter_hits(log_dir))
    hits = _filter_hits(hits, args)
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


def _find_payload_for_hit(log_dir: Path, hit: dict) -> Path | None:
    """Find the payload file matching a hit's src_ip/src_port/dst_port."""
    src_ip = hit.get("src_ip", "?")
    src_port = hit.get("src_port")
    dst_port = hit.get("dst_port")
    if not src_ip or src_port is None or dst_port is None:
        return None
    # If the hit says no payload was captured, there is no file to find.
    if hit.get("payload_size", 0) == 0:
        return None
    base = log_dir / "bycountry"
    if not base.exists():
        return None

    # Country code may be UNKNOWN; search all countries as fallback.
    cc = hit.get("country_code", "*") or "*"
    candidates: list[Path] = []
    for pattern in (
        f"{cc}/{src_ip}/*_{dst_port}_{src_port}.bin",
        f"*/{src_ip}/*_{dst_port}_{src_port}.bin",
    ):
        candidates.extend(base.glob(pattern))
    if not candidates:
        return None
    # Prefer the file whose mtime is closest to the hit time, otherwise newest.
    hit_time = hit.get("time", "")
    candidates.sort(
        key=lambda p: (
            abs(p.stat().st_mtime - _hit_timestamp(hit_time)),
        )
    )
    return candidates[0]


def _hit_timestamp(hit_time: str) -> float:
    """Best-effort parse of ISO timestamps used in hit logs."""
    import time

    if not hit_time:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(hit_time[:19], fmt))
        except ValueError:
            pass
    return 0.0


def cmd_recent_payloads(args: argparse.Namespace) -> int:
    _, log_dir = _load_config(args)
    hits = _sort_hits(list(_iter_hits(log_dir)))
    hits = _filter_hits(hits, args)
    limit = args.last if args.last is not None else DEFAULT_TAIL
    hits = hits[:limit]
    if not hits:
        print("No hits.")
        return 0

    for hit in hits:
        print(_format_hit(hit))
        payload_path = _find_payload_for_hit(log_dir, hit)
        if payload_path is not None:
            data = _payload_bytes(payload_path, args.bytes)
            full_size = payload_path.stat().st_size
            print(f"  payload size: {full_size} bytes (showing first {len(data)})")
            print(f"  text({len(data)}):  ", _text_snip(data, args.bytes))
            print(f"  hex({len(data)}):   ", _hex_snip(data, args.bytes))
        else:
            print("  payload: (none captured)")
        print()
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

    limit = args.last if args.last is not None else 20
    print(f"{'DST PORT':>10} {'DROPS':>8}")
    print("-" * 20)
    for port, count in ports.most_common(limit):
        print(f"{port:>10} {count:>8}")
    return 0


# Backward-compatible mapping from old positional sub-command syntax to the
# new argument-based form.
_COMPAT_MODES = {
    "recent": ("recent",),
    "tail": ("tail",),
    "stats": ("stats",),
    "dropped": ("dropped",),
    "payloads": ("payloads",),
    "recent-payloads": ("recent-payloads",),
    "by-ip": ("recent", "ip"),
    "by-country": ("recent", "country"),
    "by-dst": ("recent", "dst_port"),
}


def _translate_old_syntax(argv: list[str]) -> list[str]:
    """Convert legacy ``tsunamiwall-logs SUBCMD [args...]`` into new flags.

    Examples:
        tsunamiwall-logs recent           -> --recent
        tsunamiwall-logs recent 20        -> --recent --last 20
        tsunamiwall-logs tail             -> --tail
        tsunamiwall-logs by-ip 1.2.3.4    -> --recent --ip 1.2.3.4
        tsunamiwall-logs by-dst 10005     -> --recent --dst-port 10005
        tsunamiwall-logs payloads 1.2.3.4 -> --payloads --ip 1.2.3.4
        tsunamiwall-logs payloads 10 by-ip 1.2.3.4 -> --payloads --last 10 --ip 1.2.3.4
        tsunamiwall-logs dropped 30       -> --dropped --last 30
    """
    if not argv:
        return argv

    head = argv[0]
    if head.startswith("-"):
        return argv

    mapping = _COMPAT_MODES.get(head)
    if not mapping:
        # Unknown command; let argparse report the error.
        return argv

    mode, *value_key = mapping
    translated = [f"--{mode}"]
    rest = argv[1:]

    # If the old sub-command takes a positional value (by-ip, by-country,
    # by-dst), translate that first positional argument into the matching
    # new filter flag.
    if value_key:
        key = value_key[0]
        if rest:
            translated.append(f"--{key.replace('_', '-')}")
            translated.append(rest.pop(0))

    i = 0
    while i < len(rest):
        token = rest[i]
        if token == "by-ip" and i + 1 < len(rest):
            translated.extend(["--ip", rest[i + 1]])
            i += 2
        elif token == "by-country" and i + 1 < len(rest):
            translated.extend(["--country", rest[i + 1]])
            i += 2
        elif token == "by-dst" and i + 1 < len(rest):
            translated.extend(["--dst-port", rest[i + 1]])
            i += 2
        elif token.isdigit():
            translated.extend(["--last", token])
            i += 1
        else:
            # For payloads, a bare first positional was treated as an IP.
            if mode == "payloads" and not token.startswith("-"):
                translated.extend(["--ip", token])
            i += 1

    return translated


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    raw_argv = _translate_old_syntax(raw_argv)
    args = parser.parse_args(raw_argv)

    # If no viewing mode was selected, default to --recent.
    if not any((args.recent, args.tail, args.stats, args.dropped, args.payloads, args.recent_payloads)):
        args.recent = True

    dispatch = {
        "recent": cmd_recent,
        "tail": cmd_tail,
        "by-ip": cmd_by_ip,
        "by-country": cmd_by_country,
        "by-dst": cmd_by_dst,
        "payloads": cmd_payloads,
        "recent-payloads": cmd_recent_payloads,
        "stats": cmd_stats,
        "dropped": cmd_dropped,
    }

    # Map the selected flag to the same dispatch keys used for backward compat.
    mode: str | None = None
    if args.recent:
        mode = "recent"
    elif args.tail:
        mode = "tail"
    elif args.stats:
        mode = "stats"
    elif args.dropped:
        mode = "dropped"
    elif args.payloads:
        mode = "payloads"
    elif args.recent_payloads:
        mode = "recent-payloads"

    # Filters are applied inside the viewing commands, so mode selection is
    # enough here.  The old by-ip/by-country/by-dst sub-commands also map to
    # "recent" but set their filter before delegating.
    try:
        return dispatch[mode](args)
    except PermissionError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
