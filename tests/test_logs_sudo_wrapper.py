"""Regression tests for the tsunamiwall-logs sudo wrapper."""

from pathlib import Path


def _exec_wrapper_with_mocks(monkeypatch, euid, cfg):
    """Load scripts/tsunamiwall-logs in a controlled namespace and return _need_sudo."""
    import os
    import sys

    script = Path("scripts/tsunamiwall-logs")
    source = script.read_text(encoding="utf-8")
    namespace = {
        "__file__": str(script),
        "__name__": "tsunamiwall_logs_wrapper",
        "os": os,
        "sys": sys,
        "main": lambda: 0,
        "load_config": lambda _path=None: cfg,
    }
    sys.path.insert(0, str(Path.cwd()))
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    exec(compile(source, str(script), "exec"), namespace)
    return namespace["_need_sudo"]


def test_need_sudo_false_when_root(monkeypatch):
    cfg = type("C", (), {"log_dir": "/tmp"})()
    need_sudo = _exec_wrapper_with_mocks(monkeypatch, 0, cfg)
    assert need_sudo() is False


def test_need_sudo_false_when_log_dir_readable(monkeypatch):
    import os

    cfg = type("C", (), {"log_dir": "/some/path"})()
    monkeypatch.setattr(os, "access", lambda _path, _mode: True)
    need_sudo = _exec_wrapper_with_mocks(monkeypatch, 1000, cfg)
    assert need_sudo() is False


def test_need_sudo_true_when_log_dir_unreadable(monkeypatch):
    import os

    cfg = type("C", (), {"log_dir": "/some/path"})()
    monkeypatch.setattr(os, "access", lambda _path, _mode: False)
    need_sudo = _exec_wrapper_with_mocks(monkeypatch, 1000, cfg)
    assert need_sudo() is True
