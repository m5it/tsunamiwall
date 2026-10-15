import os
import tempfile
from pathlib import Path

from tsunamiwall.cli import cmd_reset


class FakeArgs:
    def __init__(self, config=None):
        self.config = config


def test_reset_falls_back_to_emergency_when_no_socket(monkeypatch, tmp_path):
    cfg_file = tmp_path / "cfg.yaml"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cfg_file.write_text(
        f"run_dir: {run_dir}\nlog_dir: {tmp_path / 'log'}\n",
        encoding="utf-8",
    )

    called = {"emergency": False}

    def fake_emergency():
        called["emergency"] = True

    monkeypatch.setattr("tsunamiwall.emergency.emergency_reset", fake_emergency)

    args = FakeArgs(str(cfg_file))
    cmd_reset(args)
    assert called["emergency"] is True
