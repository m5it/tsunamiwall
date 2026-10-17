import pytest

from tsunamiwall.config import Config
from tsunamiwall.daemon import Daemon


@pytest.mark.asyncio
async def test_ipv6_rules_built_when_enabled(monkeypatch, tmp_path, fake_firewall):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert ipv4_calls, "IPv4 rules should always be built"
    assert ipv6_calls, "IPv6 rules should be built when enable_ipv6 is true"
    assert ipv6_calls[0][2] == "TSUNAMIWALL6"


@pytest.mark.asyncio
async def test_ipv6_rules_not_built_when_disabled(monkeypatch, tmp_path, fake_firewall):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=False,
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert not ipv6_calls, "IPv6 rules should not be built when enable_ipv6 is false"


def test_ipv6_chain_property():
    cfg = Config(iptables_chain="CUSTOM")
    assert cfg.ipv6_chain == "CUSTOM6"
