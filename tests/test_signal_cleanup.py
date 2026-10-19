import asyncio
from pathlib import Path

import pytest

from tsunamiwall.config import Config
from tsunamiwall.daemon import Daemon


@pytest.mark.asyncio
async def test_request_stop_runs_cleanup(monkeypatch, tmp_path, fake_firewall):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()

    cfg = Config(
        run_dir=str(run_dir),
        log_dir=str(log_dir),
        payload_log_dir=str(payload_dir),
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())

    daemon = Daemon(cfg)
    daemon.allowed_ports = {8080}

    # Patch _hard_exit so tests don't actually exit.
    hard_exit_called = False

    def fake_hard_exit():
        nonlocal hard_exit_called
        hard_exit_called = True

    monkeypatch.setattr(daemon, "_hard_exit", fake_hard_exit)

    start_task = asyncio.create_task(daemon.start())
    # Give start() time to set up signal handlers and reach the wait.
    await asyncio.sleep(0.1)

    # Simulate SIGTERM/Ctrl+C by invoking the signal handler directly.
    daemon._request_stop()

    # Wait for start() to return after running cleanup.
    try:
        await asyncio.wait_for(start_task, timeout=5.0)
    except asyncio.TimeoutError:
        pytest.fail("daemon.start() did not return after _request_stop")

    assert not (Path(cfg.pid_path)).exists(), "PID file should be removed"
    assert (Path(cfg.state_path)).exists(), "State file should be saved"
    assert not hard_exit_called, "Hard exit should not be needed"

    # IPv4 and IPv6 resets should both be recorded.
    resets = [c for c in fake_firewall if c[0] == "reset"]
    assert ("reset", "ipv4", "TSUNAMIWALL") in resets
    assert ("reset", "ipv6", "TSUNAMIWALL6") in resets



@pytest.mark.asyncio
async def test_stop_resets_ipv6_even_when_disabled(monkeypatch, tmp_path, fake_firewall):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()

    cfg = Config(
        run_dir=str(run_dir),
        log_dir=str(log_dir),
        payload_log_dir=str(payload_dir),
        max_honeypots=0,
        enable_ipv6=False,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())

    daemon = Daemon(cfg)
    daemon.allowed_ports = {8080}

    def fake_hard_exit():
        pass

    monkeypatch.setattr(daemon, "_hard_exit", fake_hard_exit)

    start_task = asyncio.create_task(daemon.start())
    await asyncio.sleep(0.1)
    daemon._request_stop()

    try:
        await asyncio.wait_for(start_task, timeout=5.0)
    except asyncio.TimeoutError:
        pytest.fail("daemon.start() did not return after _request_stop")

    resets = [c for c in fake_firewall if c[0] == "reset"]
    assert ("reset", "ipv4", "TSUNAMIWALL") in resets
    assert ("reset", "ipv6", "TSUNAMIWALL6") in resets, "IPv6 reset should be attempted even when disabled"

