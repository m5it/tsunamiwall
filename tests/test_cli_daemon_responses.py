import json
import sys

import pytest

from tsunamiwall.cli import _print_response, main


def test_print_response_handles_dict_ok():
    assert _print_response({"ok": True, "foo": "bar"}) == 0


def test_print_response_handles_dict_error():
    assert _print_response({"ok": False, "error": "boom"}) == 1


def test_print_response_handles_string():
    assert _print_response("unexpected string") == 1


def test_daemon_invalid_port_returns_error_dict(monkeypatch, tmp_path):
    sent = []

    def fake_send(args, cmd):
        sent.append(cmd)
        return {"ok": False, "error": "invalid port"}

    monkeypatch.setattr("tsunamiwall.cli._send", fake_send)

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 0\n", encoding="utf-8")

    argv = ["-c", str(cfg), "allow", "70000"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    code = main(argv)

    assert code == 1


def test_status_response_includes_config(monkeypatch, tmp_path, capsys):
    """The status command should include the active configuration in the response."""
    sent = []

    def fake_send(args, cmd):
        sent.append(cmd)
        return {
            "ok": True,
            "config": {
                "honeypot_start": 10000,
                "honeypot_end": 65535,
                "max_honeypots": 900,
                "firewall_backend": "auto",
            },
            "allowed_ports": [22, 80],
            "blocked_ports": [],
            "honeypots": [10005, 10006],
        }

    monkeypatch.setattr("tsunamiwall.cli._send", fake_send)

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 900\n", encoding="utf-8")

    argv = ["-c", str(cfg), "status"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    code = main(argv)

    assert code == 0
    assert sent == [{"action": "status"}]
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True
    assert "config" in parsed
    assert parsed["config"]["honeypot_start"] == 10000
    assert parsed["config"]["honeypot_end"] == 65535
