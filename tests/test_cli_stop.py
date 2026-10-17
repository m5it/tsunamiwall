import json
import sys

import pytest

from tsunamiwall.cli import main


def test_stop_command_sends_stop_action(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 5\n", encoding="utf-8")

    sent = []

    def fake_send(args, cmd):
        sent.append(cmd)
        return {"ok": True, "message": "stopped"}

    monkeypatch.setattr("tsunamiwall.cli._send", fake_send)
    monkeypatch.setattr("os.path.exists", lambda path: True)

    argv = ["-c", str(cfg), "stop"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    code = main(argv)

    assert code == 0
    assert sent == [{"action": "stop"}]


def test_stop_with_stale_socket_cleans_up(monkeypatch, tmp_path):
    """If the daemon socket exists but is not responding, stop should not crash."""
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("max_honeypots: 5\n", encoding="utf-8")

    from tsunamiwall.cli import DaemonUnreachable

    def fake_send(args, cmd):
        raise DaemonUnreachable("connection refused")

    monkeypatch.setattr("tsunamiwall.cli._send", fake_send)

    removed = []

    def fake_remove(path):
        removed.append(path)

    monkeypatch.setattr("os.remove", fake_remove)
    monkeypatch.setattr("os.path.exists", lambda path: path.endswith("daemon.sock"))

    argv = ["-c", str(cfg), "stop"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    code = main(argv)

    assert code == 1
    assert any("daemon.sock" in str(p) for p in removed)
