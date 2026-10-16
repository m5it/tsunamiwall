"""Live terminal UI for watching TsunamiWall honeypot hits in real time."""

from __future__ import annotations

import curses
import json
import os
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class DisplayHit:
    time: str
    src_ip: str
    src_port: int
    dst_port: int
    family: str


def parse_hit_line(line: str) -> DisplayHit | None:
    """Parse one JSONL honeypot hit line into a display record."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if obj.get("action") != "honeypot_hit":
        return None
    return DisplayHit(
        time=obj.get("time", "?"),
        src_ip=obj.get("src_ip", "?"),
        src_port=obj.get("src_port", 0),
        dst_port=obj.get("dst_port", 0),
        family=obj.get("family", "ipv4"),
    )


def _tail_file(path: str, callback: Callable[[str], None]) -> None:
    """Tail a text file, calling callback for each new line."""
    with open(path, "r", encoding="utf-8") as fh:
        # Start at end of file to show only new hits.
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            callback(line)


def _render(stdscr, hits: list[DisplayHit]) -> None:
    """Draw the live hit table."""
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Header
    header = " TsunamiWall Live Honeypot Hits — press 'q' to quit "
    stdscr.addstr(0, 0, header.ljust(width), curses.A_REVERSE)

    # Column headers
    col_fmt = "{:<23} {:>6} {:>15} {:>10} {:>10}"
    headers = col_fmt.format("TIME", "FAMILY", "SRC IP", "SRC PORT", "DST PORT")
    stdscr.addstr(2, 0, headers[: width - 1], curses.A_BOLD)
    stdscr.addstr(3, 0, "-" * (width - 1))

    # Body: show as many recent hits as fit.
    max_rows = max(0, height - 5)
    visible = hits[-max_rows:] if max_rows else []
    for idx, hit in enumerate(visible, start=4):
        row = col_fmt.format(
            hit.time,
            hit.family,
            hit.src_ip,
            str(hit.src_port),
            str(hit.dst_port),
        )
        # Highlight new entries briefly (last 3 visible).
        attr = curses.A_NORMAL
        if idx >= height - 3:
            attr = curses.A_BOLD
        stdscr.addstr(idx, 0, row[: width - 1], attr)

    stdscr.refresh()


def run_watch(log_path: str) -> int:
    """Run the curses live TUI."""

    hits: list[DisplayHit] = []

    def on_line(line: str) -> None:
        hit = parse_hit_line(line)
        if hit is None:
            return
        hits.append(hit)
        # Keep memory bounded.
        if len(hits) > 1000:
            hits[:] = hits[-500:]

    def curses_main(stdscr) -> int:
        curses.curs_set(0)
        stdscr.nodelay(True)

        # Render once immediately, then tail in a background-friendly way.
        last_render = 0.0
        with open(log_path, "r", encoding="utf-8") as fh:
            # Pre-load existing last 50 hits so the screen isn't empty.
            existing = fh.readlines()
            for line in existing[-50:]:
                on_line(line)
            fh.seek(0, os.SEEK_END)

            while True:
                # Read any new lines without blocking.
                line = fh.readline()
                if line:
                    on_line(line)

                # Throttle screen redraw.
                now = time.time()
                if now - last_render >= 0.25:
                    _render(stdscr, hits)
                    last_render = now

                # Non-blocking key check for 'q'.
                try:
                    key = stdscr.getch()
                    if key in (ord("q"), ord("Q")):
                        return 0
                except curses.error:
                    pass

                time.sleep(0.05)

    try:
        return curses.wrapper(curses_main)
    except KeyboardInterrupt:
        return 0
