import json
from pathlib import Path

from scripts.tsunamiwall_logs import _iter_hits, _payload_files


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
