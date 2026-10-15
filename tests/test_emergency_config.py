import pytest

from tsunamiwall.config import Config, load_config
from tsunamiwall.emergency import emergency_reset


def test_emergency_reset_uses_custom_chain(monkeypatch, tmp_path):
    cfg_file = tmp_path / "cfg.yaml"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cfg_file.write_text(
        "iptables_chain: CUSTOM-CHAIN\n"
        f"run_dir: {run_dir}\n"
        f"log_dir: {tmp_path / 'log'}\n",
        encoding="utf-8",
    )

    cfg = load_config(str(cfg_file))
    assert cfg.iptables_chain == "CUSTOM-CHAIN"

    received = []

    def fake_stop_daemon_if_running(cfg):
        received.append(("stop", cfg.iptables_chain))

    def fake_reset(chain):
        received.append(("reset", chain))

    monkeypatch.setattr("tsunamiwall.emergency.stop_daemon_if_running", fake_stop_daemon_if_running)
    monkeypatch.setattr("tsunamiwall.emergency.reset", fake_reset)
    monkeypatch.setattr("tsunamiwall.emergency.os.geteuid", lambda: 0)
    monkeypatch.setattr("tsunamiwall.emergency.time.sleep", lambda s: None)

    emergency_reset(cfg)

    assert ("stop", "CUSTOM-CHAIN") in received
    assert ("reset", "CUSTOM-CHAIN") in received


def test_cli_reset_passes_config_to_emergency_reset(monkeypatch, tmp_path):
    from tsunamiwall.cli import cmd_reset, DaemonUnreachable

    class FakeArgs:
        def __init__(self, config=None):
            self.config = config

    cfg_file = tmp_path / "cfg.yaml"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cfg_file.write_text(
        "iptables_chain: CLI-CUSTOM\n"
        f"run_dir: {run_dir}\n"
        f"log_dir: {tmp_path / 'log'}\n",
        encoding="utf-8",
    )

    received_cfg = []

    def fake_send(args, cmd):
        raise DaemonUnreachable("no daemon")

    def fake_emergency(cfg):
        received_cfg.append(cfg)

    monkeypatch.setattr("tsunamiwall.cli._send", fake_send)
    monkeypatch.setattr("tsunamiwall.emergency.emergency_reset", fake_emergency)

    args = FakeArgs(str(cfg_file))
    cmd_reset(args)

    assert len(received_cfg) == 1
    assert received_cfg[0].iptables_chain == "CLI-CUSTOM"
