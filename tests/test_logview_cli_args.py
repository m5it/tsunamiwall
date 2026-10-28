"""Tests for the new argument-based tsunamiwall-logs CLI syntax."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from scripts.tsunamiwall_logs import (
    _parser,
    _translate_old_syntax,
    main,
    cmd_recent,
    cmd_tail,
    cmd_payloads,
    cmd_stats,
    cmd_dropped,
    cmd_recent_payloads,
)


def _parse(argv: list[str]) -> argparse.Namespace:
    return _parser().parse_args(_translate_old_syntax(argv))


def test_new_recent_short_flag():
    args = _parse(["-r"])
    assert args.recent is True


def test_new_stats_short_flag():
    args = _parse(["-s"])
    assert args.stats is True


def test_new_tail_long_flag():
    args = _parse(["--tail"])
    assert args.tail is True


def test_new_filters_ip_and_dst_port():
    args = _parse(["--recent", "--ip", "1.2.3.4", "--dst-port", "22"])
    assert args.recent is True
    assert args.ip == "1.2.3.4"
    assert args.dst_port == 22


def test_new_payloads_with_filters():
    args = _parse(["--payloads", "--country", "US", "--src-port", "54321", "--last", "5"])
    assert args.payloads is True
    assert args.country == "US"
    assert args.src_port == 54321
    assert args.last == 5


def test_new_recent_payloads_with_bytes():
    args = _parse(["-P", "-n", "10", "-b", "256"])
    assert args.recent_payloads is True
    assert args.last == 10
    assert args.bytes == 256


def test_compat_recent_count():
    argv = _translate_old_syntax(["recent", "20"])
    args = _parser().parse_args(argv)
    assert args.recent is True
    assert args.last == 20


def test_compat_by_ip():
    argv = _translate_old_syntax(["by-ip", "1.2.3.4"])
    args = _parser().parse_args(argv)
    assert args.recent is True
    assert args.ip == "1.2.3.4"


def test_compat_by_country():
    argv = _translate_old_syntax(["by-country", "US"])
    args = _parser().parse_args(argv)
    assert args.recent is True
    assert args.country == "US"


def test_compat_by_dst():
    argv = _translate_old_syntax(["by-dst", "10005"])
    args = _parser().parse_args(argv)
    assert args.recent is True
    assert args.dst_port == 10005


def test_compat_payloads_with_terms():
    argv = _translate_old_syntax(["payloads", "10", "by-ip", "1.2.3.4", "by-dst", "22"])
    args = _parser().parse_args(argv)
    assert args.payloads is True
    assert args.last == 10
    assert args.ip == "1.2.3.4"
    assert args.dst_port == 22


def test_compat_dropped_count():
    argv = _translate_old_syntax(["dropped", "30"])
    args = _parser().parse_args(argv)
    assert args.dropped is True
    assert args.last == 30


def test_new_date_filter():
    args = _parse(["--stats", "--date", "2026-10-20"])
    assert args.stats is True
    assert args.date == "2026-10-20"


def test_version_flag_prints_version():
    """--version/-v should print the package version and exit."""
    from tsunamiwall import __version__
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0


def test_version_short_flag_prints_version():
    with pytest.raises(SystemExit) as exc_info:
        main(["-v"])
    assert exc_info.value.code == 0


def test_new_archive_flag():
    args = _parse(["--archive"])
    assert args.archive is True


def test_new_all_time_flag():
    args = _parse(["--stats", "--all-time"])
    assert args.stats is True
    assert args.all_time is True

