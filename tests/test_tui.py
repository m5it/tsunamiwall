import json

from tsunamiwall.tui import DisplayHit, parse_hit_line


def test_parse_hit_line_valid():
    line = json.dumps(
        {
            "time": "2026-10-11T22:48:41Z",
            "src_ip": "220.249.82.190",
            "src_port": 61000,
            "dst_port": 10348,
            "proto": "tcp",
            "action": "honeypot_hit",
        }
    )
    hit = parse_hit_line(line)
    assert hit == DisplayHit(
        time="2026-10-11T22:48:41Z",
        src_ip="220.249.82.190",
        src_port=61000,
        dst_port=10348,
    )


def test_parse_hit_line_ignores_non_hit():
    line = json.dumps({"time": "now", "src_ip": "1.2.3.4", "action": "drop"})
    assert parse_hit_line(line) is None


def test_parse_hit_line_ignores_garbage():
    assert parse_hit_line("not json") is None
