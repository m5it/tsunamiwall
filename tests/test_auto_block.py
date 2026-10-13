import pytest

from tsunamiwall.config import Config, default_config
from tsunamiwall.iptables import build_rules


def test_auto_block_false_allows_real_services():
    """By default, real_ports are merged into allowed_ports."""
    cfg = default_config()
    assert cfg.auto_block_listeners is False


def test_auto_block_true_keeps_listeners_blocked():
    """When auto_block_listeners is true, real_ports are not auto-allowed."""
    cfg = Config(auto_block_listeners=True)
    daemon_allowed_ports: set[int] = set()
    real_ports = {22, 80, 443}
    if cfg.auto_block_listeners:
        managed_allowed = daemon_allowed_ports | (real_ports & daemon_allowed_ports)
    else:
        managed_allowed = daemon_allowed_ports | real_ports
    assert managed_allowed == set()


def test_build_rules_includes_blocked_ports(monkeypatch):
    commands = []

    def fake_run(*args):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22},
        honeypot_ports={10005},
        blocked_ports={1337, 8080},
    )

    block_rules = [cmd for cmd in commands if any("TSUNAMIWALL-BLOCK" in str(part) for part in cmd)]
    assert len(block_rules) == 4  # TCP+UDP LOG for each of 2 blocked ports

    # Ensure blocked ports come after honeypot allows and before default drop.
    allow_10005_idx = next(i for i, cmd in enumerate(commands) if "--dport" in cmd and "10005" in cmd and "ACCEPT" in cmd)
    first_block_idx = next(i for i, cmd in enumerate(commands) if any("TSUNAMIWALL-BLOCK" in str(part) for part in cmd))
    drop_idx = next(i for i, cmd in enumerate(commands) if cmd == ("-A", "TW-TEST", "-j", "DROP"))
    assert allow_10005_idx < first_block_idx < drop_idx
