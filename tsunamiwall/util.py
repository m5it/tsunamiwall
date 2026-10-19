"""Small shared helpers for TsunamiWall."""

from __future__ import annotations

from datetime import datetime, timezone


def _format_hit_time(hit_time: str) -> str:
    """Convert a UTC ISO timestamp (e.g. 2026-10-17T19:50:33Z) to local time."""
    if not hit_time or hit_time == "?":
        return "?"
    try:
        dt = datetime.fromisoformat(hit_time.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return hit_time
