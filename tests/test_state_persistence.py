import json
from pathlib import Path

from tsunamiwall.config import Config
from tsunamiwall.daemon import Daemon


def test_daemon_loads_saved_state(tmp_path, monkeypatch, fake_firewall):
    state_file = tmp_path / "daemon-state.json"
    state_file.write_text(
        json.dumps(
            {
                "allowed_ports": [8080, 8443],
                "allowed_per_ip": {
                    "203.0.113.0/24": [9090],
                    "198.51.100.45": [1234, 5678],
                },
            }
        ),
        encoding="utf-8",
    )

    cfg = Config(
        run_dir=str(tmp_path),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
    )

    # Avoid touching iptables or real sockets in the test.
    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())

    daemon = Daemon(cfg)

    assert daemon.allowed_ports == {8080, 8443}
    assert daemon.allowed_per_ip["203.0.113.0/24"] == {9090}
    assert daemon.allowed_per_ip["198.51.100.45"] == {1234, 5678}


def test_daemon_saves_state_after_reconcile(tmp_path, monkeypatch, fake_firewall):
    cfg = Config(
        run_dir=str(tmp_path),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())

    daemon = Daemon(cfg)
    daemon.allowed_ports = {2222}
    daemon.allowed_per_ip = {"10.0.0.0/8": {3333}}

    import asyncio

    asyncio.run(daemon._reconcile())

    state_file = Path(cfg.state_path)
    assert state_file.exists()
    data = json.loads(state_file.read_text(encoding="utf-8"))
    assert data["allowed_ports"] == [2222]
    assert data["allowed_per_ip"] == {"10.0.0.0/8": [3333]}
