import pytest

from tsunamiwall.config import Config, load_config
from tsunamiwall.emergency import emergency_reset


def test_emergency_reset_uses_custom_chain(monkeypatch, tmp_path, fake_firewall):
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

    monkeypatch.setattr("tsunamiwall.emergency.stop_daemon_if_running", fake_stop_daemon_if_running)
    monkeypatch.setattr("tsunamiwall.emergency.os.geteuid", lambda: 0)
    monkeypatch.setattr("tsunamiwall.emergency.time.sleep", lambda s: None)

    emergency_reset(cfg)

    reset_calls = [c for c in fake_firewall if c[0] == "reset"]
    assert ("stop", "CUSTOM-CHAIN") in received
    assert reset_calls, "emergency reset should call backend reset"
    ipv4_resets = [c for c in reset_calls if c[1] == "ipv4"]
    ipv6_resets = [c for c in reset_calls if c[1] == "ipv6"]
    assert ipv4_resets, "IPv4 reset should occur"
    assert ipv4_resets[0][2] == "CUSTOM-CHAIN"
    assert ipv6_resets, "IPv6 reset should always be attempted"
    assert ipv6_resets[0][2] == "CUSTOM-CHAIN6"


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


def test_emergency_reset_always_resets_ipv6_even_when_disabled(monkeypatch, tmp_path, fake_firewall):
    cfg_file = tmp_path / "cfg.yaml"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cfg_file.write_text(
        "iptables_chain: CUSTOM-CHAIN\n"
        "enable_ipv6: false\n"
        f"run_dir: {run_dir}\n"
        f"log_dir: {tmp_path / 'log'}\n",
        encoding="utf-8",
    )

    cfg = load_config(str(cfg_file))
    assert not cfg.enable_ipv6

    monkeypatch.setattr("tsunamiwall.emergency.stop_daemon_if_running", lambda _cfg: None)
    monkeypatch.setattr("tsunamiwall.emergency.os.geteuid", lambda: 0)
    monkeypatch.setattr("tsunamiwall.emergency.time.sleep", lambda s: None)

    emergency_reset(cfg)

    ipv6_resets = [c for c in fake_firewall if c[0] == "reset" and c[1] == "ipv6"]
    assert ipv6_resets, "IPv6 reset should be attempted even when enable_ipv6 is false"
    assert ipv6_resets[0][2] == "CUSTOM-CHAIN6"


def test_emergency_reset_ip6tables_only_resets_ipv6_primary_chain(monkeypatch, tmp_path, fake_firewall):
    cfg_file = tmp_path / "cfg.yaml"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cfg_file.write_text(
        "iptables_chain: CUSTOM-CHAIN\n"
        "firewall_backend: ip6tables\n"
        "enable_ipv6: false\n"
        f"run_dir: {run_dir}\n"
        f"log_dir: {tmp_path / 'log'}\n",
        encoding="utf-8",
    )

    cfg = load_config(str(cfg_file))
    assert cfg.firewall_backend == "ip6tables"

    monkeypatch.setattr("tsunamiwall.emergency.stop_daemon_if_running", lambda _cfg: None)
    monkeypatch.setattr("tsunamiwall.emergency.os.geteuid", lambda: 0)
    monkeypatch.setattr("tsunamiwall.emergency.time.sleep", lambda s: None)

    emergency_reset(cfg)

    reset_calls = [c for c in fake_firewall if c[0] == "reset"]
    ipv4_resets = [c for c in reset_calls if c[1] == "ipv4"]
    ipv6_resets = [c for c in reset_calls if c[1] == "ipv6"]
    assert not ipv4_resets, "IPv4 reset should not happen in ip6tables-only mode"
    assert ipv6_resets, "IPv6 reset should happen for the primary chain"
    assert ipv6_resets[0][2] == "CUSTOM-CHAIN"
    assert not any(c[2] == "CUSTOM-CHAIN6" for c in ipv6_resets), "secondary IPv6 chain should not be reset"

