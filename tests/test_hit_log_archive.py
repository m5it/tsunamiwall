"""Tests for hit log archival and merged statistics."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from tsunamiwall.config import Config
from tsunamiwall.rotation import (
    _aggregate_hits,
    _load_hits_stats,
    _merge_stats,
    _read_hits,
    archive_hit_log,
)


def make_hits(n: int, start_time: str = "2026-10-29T00:00:00") -> list[dict]:
    """Return *n* simple hit records."""
    base_time = start_time[:19]
    return [
        {
            "time": f"{base_time[:-2]}{i:02d}",
            "src_ip": f"1.2.3.{i % 256}",
            "src_port": 10000 + i,
            "dst_port": 22 if i % 2 == 0 else 80,
            "country_code": "US" if i % 3 == 0 else "CN",
            "payload_size": 0,
            "family": "ipv4",
        }
        for i in range(n)
    ]


def test_archive_hit_log_creates_tar_gz_and_resets_log(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    hits = make_hits(110_000)
    hit_log = log_dir / "hits.logl"
    hit_log.write_text("\n".join(json.dumps(h) for h in hits) + "\n", encoding="utf-8")

    archive_dir = log_dir / "archives"
    stats_path = log_dir / "hits-stats.json"

    result = archive_hit_log(
        str(hit_log),
        str(archive_dir),
        str(stats_path),
        max_hits=100_000,
    )

    assert result is not None
    assert result.parent == archive_dir
    assert result.suffixes == [".tar", ".gz"]
    assert hit_log.exists()
    assert hit_log.read_text(encoding="utf-8") == ""

    # The archive should contain the old hits.logl.
    with tarfile.open(result, "r:gz") as tar:
        names = tar.getnames()
        assert any(name.endswith("hits.logl") for name in names)

    # Stats file should contain merged totals.
    stats = _load_hits_stats(stats_path)
    assert stats["total"] == 110_000
    assert sum(stats["ips"].values()) == 110_000


def test_archive_hit_log_does_nothing_below_threshold(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    hits = make_hits(50)
    hit_log = log_dir / "hits.logl"
    hit_log.write_text("\n".join(json.dumps(h) for h in hits) + "\n", encoding="utf-8")

    archive_dir = log_dir / "archives"
    stats_path = log_dir / "hits-stats.json"

    result = archive_hit_log(
        str(hit_log),
        str(archive_dir),
        str(stats_path),
        max_hits=100_000,
    )

    assert result is None
    assert not archive_dir.exists()


def test_aggregate_hits_counts_ips_countries_and_ports():
    hits = [
        {"src_ip": "1.2.3.4", "country_code": "US", "dst_port": 22},
        {"src_ip": "1.2.3.4", "country_code": "US", "dst_port": 22},
        {"src_ip": "5.6.7.8", "country_code": "CN", "dst_port": 80},
    ]
    stats = _aggregate_hits(hits)
    assert stats["total"] == 3
    assert stats["ips"] == {"1.2.3.4": 2, "5.6.7.8": 1}
    assert stats["countries"] == {"US": 2, "CN": 1}
    assert stats["dports"] == {"22": 2, "80": 1}


def test_merge_stats_combines_counters():
    a = {"total": 10, "ips": {"x": 3, "y": 2}, "countries": {"US": 5}, "dports": {"22": 5}}
    b = {"total": 5, "ips": {"x": 1, "z": 4}, "countries": {"US": 2, "CN": 3}, "dports": {"22": 2, "80": 3}}
    merged = _merge_stats(a, b)
    assert merged["total"] == 15
    assert merged["ips"] == {"x": 4, "y": 2, "z": 4}
    assert merged["countries"] == {"US": 7, "CN": 3}
    assert merged["dports"] == {"22": 7, "80": 3}


def test_read_hits_skips_bad_lines(tmp_path):
    path = tmp_path / "hits.logl"
    path.write_text(
        '{"time":"2026-10-29T00:00:00","src_ip":"1.2.3.4"}\nnot json\n',
        encoding="utf-8",
    )
    hits = list(_read_hits(path))
    assert len(hits) == 1
    assert hits[0]["src_ip"] == "1.2.3.4"
