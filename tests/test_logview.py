import json
import argparse
from pathlib import Path

import pytest

from scripts.tsunamiwall_logs import (
    _dropped_ports,
    _find_payload_for_hit,
    _hex_snip,
    _iter_hits,
    _parse_payload_terms,
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


def test_parse_payload_terms_by_ip():
    args = argparse.Namespace(term=["3", "by-ip", "190.186.22.12"], country=None, last=None)
    ip, cc, _dst, last = _parse_payload_terms(args)
    assert ip == "190.186.22.12"
    assert last == 3
    assert cc is None
    assert _dst is None


def test_parse_payload_terms_by_country():
    args = argparse.Namespace(term=["by-country", "DE", "5"], country=None, last=None)
    ip, cc, _dst, last = _parse_payload_terms(args)
    assert ip is None
    assert cc == "DE"
    assert last == 5
    assert _dst is None


def test_parse_payload_terms_backward_compat_ip():
    args = argparse.Namespace(term=["1.2.3.4"], country=None, last=None)
    ip, cc, _dst, last = _parse_payload_terms(args)
    assert ip == "1.2.3.4"
    assert cc is None
    assert _dst is None
    assert last is None


def test_parse_payload_terms_by_dst():
    args = argparse.Namespace(term=["3", "by-dst", "22"], country=None, last=None)
    ip, cc, dst, last = _parse_payload_terms(args)
    assert dst == 22
    assert last == 3
    assert ip is None
    assert cc is None


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
    cmd_recent(argparse.Namespace(config=None, count=2))
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
        cmd_tail(argparse.Namespace(config=None))

    out = capsys.readouterr().out
    assert "old" not in out  # initial seek-to-end skipped it
    assert "new" in out


def test_parse_payload_terms_option_by_ip():
    args = argparse.Namespace(term=[], country=None, last=3, by_ip="1.2.3.4", by_country=None, by_dst=None)
    ip, cc, dst, last = _parse_payload_terms(args)
    assert ip == "1.2.3.4"
    assert last == 3
    assert cc is None
    assert dst is None


def test_parse_payload_terms_option_by_dst():
    args = argparse.Namespace(term=["5"], country=None, last=None, by_ip=None, by_country=None, by_dst=22)
    ip, cc, dst, last = _parse_payload_terms(args)
    assert dst == 22
    assert last == 5
    assert ip is None
    assert cc is None

