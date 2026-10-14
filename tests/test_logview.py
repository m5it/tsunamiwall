import json
from pathlib import Path

from scripts.tsunamiwall_logs import (
    _dropped_ports,
    _find_payload_for_hit,
    _hex_snip,
    _iter_hits,
    _payload_files,
    _text_snip,
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
    payload_file = base / "2026-10-13T20-00-00_10005.bin"
    payload_file.write_bytes(b"hello scanner")

    hit = {
        "time": "2026-10-13T20:00:00Z",
        "src_ip": "1.2.3.4",
        "dst_port": 10005,
        "country_code": "US",
    }
    assert _find_payload_for_hit(log_dir, hit) == payload_file

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



