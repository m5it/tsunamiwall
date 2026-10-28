"""Tests for the stateful archived-log viewer (open/close/list archives)."""

from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path

import pytest

from scripts.tsunamiwall_logs import (
    cmd_close_archive,
    cmd_list_archives,
    cmd_open_archive,
    cmd_recent,
    cmd_stats,
    cmd_tail,
)


def _make_args(**kwargs):
    defaults = {
        "config": None,
        "ip": None,
        "country": None,
        "src_port": None,
        "dst_port": None,
        "date": None,
        "last": None,
        "bytes": 160,
        "all_time": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _build_archive(log_dir: Path, name: str, hits: list[dict]) -> Path:
    archive_dir = log_dir / "archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / name
    log_file = log_dir / "hits.logl"
    log_file.write_text("\n".join(json.dumps(h) for h in hits) + "\n", encoding="utf-8")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(log_file, arcname="hits.logl")
    return archive_path


def test_list_archives_shows_archives_and_sizes(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    archive1 = _build_archive(
        log_dir,
        "hits-2026-10-28T00-00-00.tar.gz",
        [{"time": "2026-10-28T00:00:00", "src_ip": "1.1.1.1", "src_port": 12345, "dst_port": 22, "country_code": "US", "payload_size": 0, "family": "ipv4"}],
    )
    archive2 = _build_archive(
        log_dir,
        "hits-2026-10-29T00-00-00.tar.gz",
        [{"time": "2026-10-29T00:00:00", "src_ip": "2.2.2.2", "src_port": 12346, "dst_port": 80, "country_code": "CN", "payload_size": 0, "family": "ipv4"}],
    )

    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    assert cmd_list_archives(_make_args()) == 0
    out = capsys.readouterr().out
    assert "hits-2026-10-29T00-00-00.tar.gz" in out
    assert "hits-2026-10-28T00-00-00.tar.gz" in out


def test_open_and_close_archive_switch_reading_source(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    archive = _build_archive(
        log_dir,
        "hits-2026-10-28T12-00-00.tar.gz",
        [
            {"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU", "payload_size": 0, "family": "ipv4"},
        ],
    )
    live_log = log_dir / "hits.logl"
    live_log.write_text(
        json.dumps({"time": "2026-10-29T12:00:00", "src_ip": "8.8.8.8", "src_port": 22222, "dst_port": 22, "country_code": "US", "payload_size": 0, "family": "ipv4"}) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    # Open archive.
    assert cmd_open_archive(_make_args(open_archive="2026-10-28")) == 0
    marker = log_dir / ".tsunamiwall-active-archive"
    assert marker.exists()
    assert marker.read_text(encoding="utf-8").strip() == str(archive)

    # Recent reads from archive.
    args = _make_args(recent=True)
    hits = list(__import__("scripts.tsunamiwall_logs", fromlist=["_iter_hits"])._iter_hits(log_dir))
    assert len(hits) == 1
    assert hits[0]["src_ip"] == "9.9.9.9"

    # Close archive.
    assert cmd_close_archive(_make_args()) == 0
    assert not marker.exists()

    hits = list(__import__("scripts.tsunamiwall_logs", fromlist=["_iter_hits"])._iter_hits(log_dir))
    assert len(hits) == 1
    assert hits[0]["src_ip"] == "8.8.8.8"


def test_recent_prints_archive_notice(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _build_archive(
        log_dir,
        "hits-2026-10-28T12-00-00.tar.gz",
        [{"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU", "payload_size": 0, "family": "ipv4"}],
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))
    cmd_open_archive(_make_args(open_archive="2026-10-28"))

    assert cmd_recent(_make_args(recent=True, last=1)) == 0
    out = capsys.readouterr().out
    assert "reading from archive" in out
    assert "9.9.9.9" in out


def test_tail_reads_archive_once(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _build_archive(
        log_dir,
        "hits-2026-10-28T12-00-00.tar.gz",
        [
            {"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU", "payload_size": 0, "family": "ipv4"},
            {"time": "2026-10-28T12:01:00", "src_ip": "8.8.8.8", "src_port": 22222, "dst_port": 22, "country_code": "US", "payload_size": 0, "family": "ipv4"},
        ],
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))
    cmd_open_archive(_make_args(open_archive="2026-10-28"))

    assert cmd_tail(_make_args(tail=True, ip="8.8.8.8")) == 0
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "9.9.9.9" not in out


def test_stats_from_archive_does_not_merge_all_time_stats(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _build_archive(
        log_dir,
        "hits-2026-10-28T12-00-00.tar.gz",
        [
            {"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU", "payload_size": 0, "family": "ipv4"},
        ],
    )
    # Create a stats file with unrelated larger totals.
    (log_dir / "hits-stats.json").write_text(
        json.dumps({"total": 9999, "ips": {"1.1.1.1": 9999}, "countries": {"XX": 9999}, "dports": {"9999": 9999}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))
    cmd_open_archive(_make_args(open_archive="2026-10-28"))

    assert cmd_stats(_make_args(stats=True)) == 0
    out = capsys.readouterr().out
    assert "Total hits: 1" in out
    assert "9.9.9.9" in out
    assert "1.1.1.1" not in out


def test_open_archive_ambiguous_prefix_errors(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _build_archive(
        log_dir,
        "hits-2026-10-28T10-00-00.tar.gz",
        [{"time": "2026-10-28T10:00:00", "src_ip": "1.1.1.1", "src_port": 12345, "dst_port": 22, "country_code": "US", "payload_size": 0, "family": "ipv4"}],
    )
    _build_archive(
        log_dir,
        "hits-2026-10-28T11-00-00.tar.gz",
        [{"time": "2026-10-28T11:00:00", "src_ip": "2.2.2.2", "src_port": 12346, "dst_port": 80, "country_code": "CN", "payload_size": 0, "family": "ipv4"}],
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    assert cmd_open_archive(_make_args(open_archive="2026-10-28")) == 1
    err = capsys.readouterr().err
    assert "Ambiguous archive prefix" in err


def test_open_archive_by_full_filename(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    archive = _build_archive(
        log_dir,
        "hits-2026-10-28T12-00-00.tar.gz",
        [{"time": "2026-10-28T12:00:00", "src_ip": "1.1.1.1", "src_port": 12345, "dst_port": 22, "country_code": "US", "payload_size": 0, "family": "ipv4"}],
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    assert cmd_open_archive(_make_args(open_archive="hits-2026-10-28T12-00-00.tar.gz")) == 0
    marker = log_dir / ".tsunamiwall-active-archive"
    assert marker.read_text(encoding="utf-8").strip() == str(archive)


def test_close_archive_when_none_open(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))
    assert cmd_close_archive(_make_args()) == 0
    assert "No archive was open" in capsys.readouterr().out
