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
