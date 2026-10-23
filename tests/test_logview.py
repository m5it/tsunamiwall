import argparse
import json
import os
import time
from pathlib import Path

import pytest

from scripts.tsunamiwall_logs import (
    _dropped_ports,
    _filter_hits,
    _find_payload_for_hit,
    _hex_snip,
    _iter_hits,
    _payload_files,
    _sort_hits,
    _text_snip,
    cmd_recent,
    cmd_tail,
)
def make_sample_log(tmp_path: Path) -> Path:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    hits = [
        {
            "time": "2026-10-13T20:00:00",
            "action": "honeypot_hit",
            "src_ip": "1.2.3.4",
            "src_port": 54321,
            "dst_port": 10005,
            "country_code": "US",
            "payload_size": 7,
        },
        {
            "time": "2026-10-13T20:00:01",
            "action": "honeypot_hit",
            "src_ip": "5.6.7.8",
            "src_port": 11111,
            "dst_port": 10010,
            "country_code": "CN",
            "payload_size": 0,
        },
    ]
    path = log_dir / "hits.logl"
    with open(path, "w", encoding="utf-8") as fh:
        for h in hits:
            fh.write(json.dumps(h) + "\n")
    return log_dir


def test_iter_hits_reads_jsonl(tmp_path):
    log_dir = make_sample_log(tmp_path)
    hits = list(_iter_hits(log_dir))
    assert len(hits) == 2
    assert hits[0]["src_ip"] == "1.2.3.4"
    assert hits[1]["country_code"] == "CN"


def test_iter_hits_ignores_bad_lines(tmp_path):
    log_dir = make_sample_log(tmp_path)
    path = log_dir / "hits.logl"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    hits = list(_iter_hits(log_dir))
    assert len(hits) == 2


def test_payload_files_finds_by_country(tmp_path):
    log_dir = make_sample_log(tmp_path)
    base = log_dir / "bycountry" / "US" / "1.2.3.4"
    base.mkdir(parents=True)
    (base / "payload.bin").write_bytes(b"hello")

    assert len(_payload_files(log_dir)) == 1
    assert len(_payload_files(log_dir, country_filter="us")) == 1
    assert len(_payload_files(log_dir, country_filter="CN")) == 0
    assert len(_payload_files(log_dir, ip_filter="1.2.3.4")) == 1
    assert len(_payload_files(log_dir, ip_filter="9.9.9.9")) == 0


def test_find_payload_for_hit(tmp_path):
    log_dir = tmp_path / "logs"
    base = log_dir / "bycountry" / "US" / "1.2.3.4"
    base.mkdir(parents=True)
    # New payload filenames use nanosecond timestamp + dst_port + src_port.
    payload_file = base / "9999999999_10005_54321.bin"
    payload_file.write_bytes(b"hello scanner")

    hit = {
        "time": "2026-10-13T20:00:00Z",
        "src_ip": "1.2.3.4",
        "src_port": 54321,
        "dst_port": 10005,
        "country_code": "US",
        "payload_size": 13,
    }
    assert _find_payload_for_hit(log_dir, hit) == payload_file

    # Hits with no captured payload return None without scanning disk.
    no_payload_hit = {
        "time": "2026-10-13T20:00:01Z",
        "src_ip": "1.2.3.4",
        "src_port": 54322,
        "dst_port": 10005,
        "country_code": "US",
        "payload_size": 0,
    }
    assert _find_payload_for_hit(log_dir, no_payload_hit) is None

    # Missing port returns None.
    assert _find_payload_for_hit(log_dir, {"src_ip": "1.2.3.4"}) is None


def test_text_and_hex_snips():
    data = b"hello\x00 world"
    assert _text_snip(data, 100) == "hello\x00 world"
    assert _hex_snip(data, 100) == r"\x68\x65\x6c\x6c\x6f\x00\x20\x77\x6f\x72\x6c\x64"


def test_dropped_ports_parses_dpt(monkeypatch):
    sample_lines = [
        "TSUNAMIWALL-DROP: IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 DPT=12345",
        "TSUNAMIWALL-DROP: IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 DPT=12345",
        "TSUNAMIWALL-DROP: IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 DPT=80",
        "some other log line DPT=9999",
    ]
    monkeypatch.setattr("scripts.tsunamiwall_logs._drop_log_lines", lambda: iter(sample_lines))

    counts = _dropped_ports()
    assert counts[12345] == 2
    assert counts[80] == 1
    assert 9999 not in counts


def test_sort_hits_newest_first():
    hits = [
        {"time": "2026-10-17T19:00:00Z", "src_ip": "1.2.3.4"},
        {"time": "2026-10-17T21:00:00Z", "src_ip": "5.6.7.8"},
        {"time": "2026-10-17T20:00:00Z", "src_ip": "9.9.9.9"},
    ]
    sorted_hits = _sort_hits(hits)
    assert [h["src_ip"] for h in sorted_hits] == ["5.6.7.8", "9.9.9.9", "1.2.3.4"]


def test_recent_shows_newest_first(capsys, tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    path = log_dir / "hits.logl"
    path.write_text(
        '{"time":"2026-10-17T19:00:00Z","src_ip":"old"}\n'
        '{"time":"2026-10-17T21:00:00Z","src_ip":"new"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))
    cmd_recent(argparse.Namespace(config=None, ip=None, country=None, src_port=None, dst_port=None, last=2))
    out = capsys.readouterr().out
    assert out.index("new") < out.index("old")


def test_tail_reopens_after_rotation(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    path = log_dir / "hits.logl"
    path.write_text('{"time":"2026-10-17T19:00:00Z","src_ip":"old"}\n', encoding="utf-8")

    class FakeSleep:
        def __init__(self):
            self.calls = 0
        def __call__(self, _seconds):
            self.calls += 1
            if self.calls == 1:
                # Simulate daemon log rotation.
                path.rename(log_dir / "hits.logl.1")
                # Create a fresh log and append one line that tail will miss
                # because it seeks to end on reopen.
                path.write_text('{"time":"2026-10-17T20:00:00Z","src_ip":"mid"}\n', encoding="utf-8")
            elif self.calls == 2:
                # Append a newer line after tail has reopened the new file.
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write('{"time":"2026-10-17T21:00:00Z","src_ip":"new"}\n')
            elif self.calls >= 6:
                raise SystemExit(0)

    monkeypatch.setattr("time.sleep", FakeSleep())
    monkeypatch.setattr("scripts.tsunamiwall_logs._load_config", lambda _args: (None, log_dir))

    with pytest.raises(SystemExit):
        cmd_tail(argparse.Namespace(config=None, ip=None, country=None, src_port=None, dst_port=None))

    out = capsys.readouterr().out
    assert "old" not in out  # initial seek-to-end skipped it
    assert "new" in out


def test_filter_hits_applies_ip_and_dst():
    hits = [
        {"src_ip": "1.2.3.4", "dst_port": 22, "country_code": "US"},
        {"src_ip": "5.6.7.8", "dst_port": 22, "country_code": "CN"},
        {"src_ip": "1.2.3.4", "dst_port": 80, "country_code": "US"},
    ]
    args = argparse.Namespace(ip="1.2.3.4", country=None, src_port=None, dst_port=22)
    filtered = _filter_hits(hits, args)
    assert len(filtered) == 1
    assert filtered[0]["src_ip"] == "1.2.3.4"


def test_hit_matches_date():
    from scripts.tsunamiwall_logs import _hit_matches_date
    assert _hit_matches_date({"time": "2026-10-20T12:34:56Z"}, "2026-10-20") is True
    assert _hit_matches_date({"time": "2026-10-20T12:34:56"}, "2026-10-20") is True
    assert _hit_matches_date({"time": "2026-10-21T00:00:00Z"}, "2026-10-20") is False
    assert _hit_matches_date({"time": ""}, "2026-10-20") is False
    assert _hit_matches_date({"time": "2026-10-20T12:34:56Z"}, None) is True


def test_filter_hits_by_date():
    hits = [
        {"time": "2026-10-20T12:00:00Z", "src_ip": "1.2.3.4"},
        {"time": "2026-10-21T12:00:00Z", "src_ip": "5.6.7.8"},
        {"time": "2026-10-20T23:59:59Z", "src_ip": "9.9.9.9"},
    ]
    args = argparse.Namespace(ip=None, country=None, src_port=None, dst_port=None, date="2026-10-20")
    filtered = _filter_hits(hits, args)
    assert [h["src_ip"] for h in filtered] == ["1.2.3.4", "9.9.9.9"]


def test_payload_files_filter_by_date(tmp_path):
    from scripts.tsunamiwall_logs import _payload_files
    import time
    log_dir = tmp_path / "logs"
    base = log_dir / "bycountry" / "US" / "1.2.3.4"
    base.mkdir(parents=True)
    f1 = base / "1000000000_80_12345.bin"
    f1.write_bytes(b"old")
    f2 = base / "2000000000_80_12345.bin"
    f2.write_bytes(b"new")
    # Set mtimes to known dates
    day1 = time.mktime(time.strptime("2026-10-20", "%Y-%m-%d")) + 3600
    day2 = time.mktime(time.strptime("2026-10-21", "%Y-%m-%d")) + 3600
    os.utime(f1, (day1, day1))
    os.utime(f2, (day2, day2))

    files = _payload_files(log_dir, date_filter="2026-10-20")
    assert files == [f1]

