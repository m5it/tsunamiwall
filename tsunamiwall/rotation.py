"""Log/payload rotation helpers for TsunamiWall."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger("tsunamiwall.rotation")


def _current_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def rotate_hit_log(hit_log_path: str, max_bytes: int, max_backups: int) -> Path | None:
    """Rotate *hit_log_path* if it exceeds *max_bytes*.

    Returns the path of the newly rotated file (the old log renamed to .1)
    or ``None`` if no rotation happened.
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
