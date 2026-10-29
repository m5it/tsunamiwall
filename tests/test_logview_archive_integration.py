"""Integration tests for tsunamiwall-logs stats merging archived statistics."""

from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path

import pytest

from scripts.tsunamiwall_logs import cmd_list_archives, cmd_open_archive, cmd_stats


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


def test_stats_merges_archived_and_current(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    # Archived stats: 1000 hits from 1.2.3.4 on port 22.
    stats = {
        "total": 1000,
        "ips": {"1.2.3.4": 1000},
        "countries": {"US": 1000},
        "dports": {"22": 1000},
    }
    (log_dir / "hits-stats.json").write_text(json.dumps(stats), encoding="utf-8")

    # Current log: 3 more hits on port 80.
    current_hits = [
        {"time": "2026-10-29T12:00:00", "src_ip": "5.6.7.8", "src_port": 12345, "dst_port": 80, "country_code": "CN", "payload_size": 0, "family": "ipv4"}
        for _ in range(3)
    ]
    (log_dir / "hits.logl").write_text("\n".join(json.dumps(h) for h in current_hits) + "\n", encoding="utf-8")

    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    cmd_stats(_make_args())
    out = capsys.readouterr().out

    assert "Total hits: 1003" in out
    assert "from archives + 3 current" in out
    assert "80" in out
    assert "22" in out


def test_stats_all_time_scans_tar_gz(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    archive_dir = log_dir / "archives"
    archive_dir.mkdir()

    archived_hits = [
        {"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU", "payload_size": 0, "family": "ipv4"}
        for _ in range(7)
    ]
    archive_path = archive_dir / "hits-2026-10-28T12-00-00.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        log_file = log_dir / "hits.logl"
        log_file.write_text("\n".join(json.dumps(h) for h in archived_hits) + "\n", encoding="utf-8")
        tar.add(log_file, arcname="hits.logl")
    log_file.write_text("")  # clear current log

    # Empty stats file.
    (log_dir / "hits-stats.json").write_text(json.dumps({"total": 0, "ips": {}, "countries": {}, "dports": {}}), encoding="utf-8")

    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    cmd_stats(_make_args(all_time=True))
    out = capsys.readouterr().out

    assert "Total hits: 7" in out
    assert "Includes all archived logs" in out
    assert "9.9.9.9" in out
    assert "443" in out


def test_stats_all_time_uses_archives_once_and_applies_filters(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    archive_dir = tmp_path / "custom-archives"
    archive_dir.mkdir(parents=True)

    archived_hits = [
        {"time": "2026-10-28T12:00:00", "src_ip": "9.9.9.9", "src_port": 11111, "dst_port": 443, "country_code": "RU"}
        for _ in range(2)
    ] + [
        {"time": "2026-10-28T12:01:00", "src_ip": "8.8.8.8", "src_port": 22222, "dst_port": 80, "country_code": "CN"}
    ]
    archive_path = archive_dir / "hits-2026-10-28T12-00-00.tar.gz"
    log_file = log_dir / "hits.logl"
    log_dir.mkdir()
    log_file.write_text("\n".join(json.dumps(h) for h in archived_hits) + "\n", encoding="utf-8")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(log_file, arcname="hits.logl")

    current_hit = {
        "time": "2026-10-29T12:00:00",
        "src_ip": "7.7.7.7",
        "src_port": 33333,
        "dst_port": 53,
        "country_code": "CN",
    }
    log_file.write_text(json.dumps(current_hit) + "\n", encoding="utf-8")
    (log_dir / "hits-stats.json").write_text(
        json.dumps({"total": 3, "ips": {"9.9.9.9": 2, "8.8.8.8": 1}, "countries": {"RU": 2, "CN": 1}, "dports": {"443": 2, "80": 1}}),
        encoding="utf-8",
    )

    from tsunamiwall.config import Config

    cfg = Config(log_dir=str(log_dir), hit_log_archive_dir=str(archive_dir))
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (cfg, log_dir))

    cmd_stats(_make_args(all_time=True, country="CN"))
    out = capsys.readouterr().out
    assert "Total hits: 2" in out
    assert "8.8.8.8" in out
    assert "7.7.7.7" in out
    assert "9.9.9.9" not in out


def test_archive_commands_use_configured_archive_directory(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    archive_dir = tmp_path / "custom-archives"
    archive_dir.mkdir(parents=True)
    archive_path = archive_dir / "hits-2026-10-28T12-00-00.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        pass

    from tsunamiwall.config import Config

    cfg = Config(log_dir=str(log_dir), hit_log_archive_dir=str(archive_dir))
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (cfg, log_dir))

    assert cmd_list_archives(_make_args()) == 0
    assert archive_path.name in capsys.readouterr().out
    assert cmd_open_archive(_make_args(open_archive="2026-10-28")) == 0
    assert (log_dir / ".tsunamiwall-active-archive").read_text(encoding="utf-8").strip() == str(archive_path)
