"""Log/payload rotation helpers for TsunamiWall."""

from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import tarfile
import time
from collections import Counter
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("tsunamiwall.rotation")


def _current_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _count_lines(path: Path) -> int:
    """Count non-empty lines in a file quickly."""
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.strip():
                    count += 1
    except FileNotFoundError:
        pass
    return count


def _read_hits(path: Path) -> Iterable[dict]:
    """Yield JSON hit records from a hit log file."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _aggregate_hits(hits: Iterable[dict]) -> dict:
    """Return aggregate counters from hit records."""
    total = 0
    ips: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    dports: Counter[int] = Counter()
    for h in hits:
        total += 1
        ips[h.get("src_ip", "?")] += 1
        countries[h.get("country_code", "?")] += 1
        dports[h.get("dst_port", 0)] += 1
    return {
        "total": total,
        "ips": dict(ips),
        "countries": dict(countries),
        "dports": {str(k): v for k, v in dports.items()},
    }


def _load_hits_stats(stats_path: Path) -> dict:
    """Load merged hit statistics from disk, returning an empty aggregate if absent."""
    if not stats_path.exists():
        return {"total": 0, "ips": {}, "countries": {}, "dports": {}}
    try:
        data = json.loads(stats_path.read_text(encoding="utf-8"))
    except Exception:
        return {"total": 0, "ips": {}, "countries": {}, "dports": {}}
    data.setdefault("total", 0)
    data.setdefault("ips", {})
    data.setdefault("countries", {})
    data.setdefault("dports", {})
    return data


def _save_hits_stats(stats_path: Path, stats: dict) -> None:
    """Persist merged hit statistics to disk."""
    stats_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = stats_path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(stats_path)


def _merge_stats(existing: dict, new: dict) -> dict:
    """Merge *new* aggregate counters into *existing* and return the result."""
    merged = {
        "total": existing["total"] + new["total"],
        "ips": dict(Counter(existing["ips"]) + Counter(new["ips"])),
        "countries": dict(Counter(existing["countries"]) + Counter(new["countries"])),
        "dports": dict(Counter(existing["dports"]) + Counter(new["dports"])),
    }
    return merged


def archive_hit_log(
    hit_log_path: str,
    archive_dir: str,
    stats_path: str,
    max_hits: int,
) -> Path | None:
    """Archive *hit_log_path* if it contains more than *max_hits* entries.

    Steps:
      1. Merge statistics from the current log into *stats_path*.
      2. Compress the current log into a dated .tar.gz under *archive_dir*.
      3. Start a fresh empty log file.

    Returns the path of the created archive, or ``None`` if the log did not
    exceed the threshold or was empty.
    """
    path = Path(hit_log_path)
    if max_hits <= 0 or not path.exists():
        return None

    line_count = _count_lines(path)
    if line_count <= max_hits:
        return None

    stats = _aggregate_hits(_read_hits(path))
    if stats["total"] == 0:
        return None

    existing = _load_hits_stats(Path(stats_path))
    merged = _merge_stats(existing, stats)
    _save_hits_stats(Path(stats_path), merged)

    archive_base = Path(archive_dir)
    archive_base.mkdir(parents=True, exist_ok=True, mode=0o750)

    timestamp = time.strftime("%Y-%m-%dT%H-%M-%S")
    archive_name = f"hits-{timestamp}.tar.gz"
    archive_path = archive_base / archive_name

    # Write a compressed tar containing the current hits.logl.
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(path, arcname=path.name)

    # Start a fresh log.
    path.write_text("", encoding="utf-8")

    logger.info(
        "Archived %d hits from %s to %s (all-time total now %d)",
        stats["total"],
        path,
        archive_path,
        merged["total"],
    )
    return archive_path


def rotate_hit_log(hit_log_path: str, max_bytes: int, max_backups: int) -> Path | None:
    """Rotate *hit_log_path* if it exceeds *max_bytes*.

    Returns the path of the newly rotated file (the old log renamed to .1)
    or ``None`` if no rotation happened.

    Only *max_backups* backup files are retained. Older backups are deleted
    so rotation cannot fill the disk.
    """
    path = Path(hit_log_path)
    if max_bytes <= 0 or _current_size(path) <= max_bytes:
        return None

    # Shift existing backups up, leaving .1 free for the current log.
    suffixes = [int(p.suffix.lstrip(".")) for p in path.parent.glob(path.name + ".*") if p.suffix[1:].isdigit()]
    for i in sorted(suffixes, reverse=True):
        src = path.parent / f"{path.name}.{i}"
        dst = path.parent / f"{path.name}.{i + 1}"
        if dst.exists():
            dst.unlink()
        shutil.move(str(src), str(dst))

    # Rotate current log to .1 and create a fresh empty log file.
    rotated = path.parent / f"{path.name}.1"
    if rotated.exists():
        rotated.unlink()
    shutil.move(str(path), str(rotated))
    path.write_text("", encoding="utf-8")

    # Enforce the backup cap: delete anything beyond max_backups.
    if max_backups >= 0:
        for p in path.parent.glob(path.name + ".*"):
            suffix = p.suffix[1:]
            if suffix.isdigit() and int(suffix) > max_backups:
                try:
                    p.unlink()
                    logger.info("Pruned old log backup %s", p)
                except FileNotFoundError:
                    pass
                except PermissionError:
                    logger.warning("Permission denied removing %s", p)

    logger.info("Rotated %s to %s", path, rotated)
    return rotated


def cleanup_payloads(payload_log_dir: str, max_bytes: int) -> None:
    """Remove oldest payload files under *payload_log_dir* until total size
    is at or below *max_bytes*. Metadata files are left in place so session
    records remain browsable even after their payload bytes are gone.
    """
    if max_bytes <= 0:
        return

    base = Path(payload_log_dir)
    if not base.exists():
        return

    files = list((p, p.stat().st_size, p.stat().st_mtime) for p in base.rglob("*.bin") if p.is_file())
    files.sort(key=lambda item: item[2])
    total = sum(size for _, size, _ in files)
    if total <= max_bytes:
        return

    # Delete oldest files first until we are under the cap.
    for payload_path, size, _ in files:
        if total <= max_bytes:
            break
        try:
            payload_path.unlink()
            total -= size
            logger.info("Removed old payload %s (remaining payload bytes: %d)", payload_path, total)
        except FileNotFoundError:
            pass
        except PermissionError:
            logger.warning("Permission denied removing %s", payload_path)
