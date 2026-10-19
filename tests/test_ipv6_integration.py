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
    # Honeypots bind IPv4 only, so IPv6 rules must not advertise honeypot ports.
    assert ipv6_calls[0][4] == set(), "IPv6 honeypot ports should be empty"


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


@pytest.mark.asyncio
async def test_ipv6_rules_with_honeypots_do_not_open_honeypot_ports(monkeypatch, tmp_path, fake_firewall):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        honeypot_start=30000,
        honeypot_end=30005,
        max_honeypots=5,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: {30000, 30001, 30002})

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert ipv4_calls[0][4] == {30000, 30001, 30002}, "IPv4 should advertise honeypot ports"
    assert ipv6_calls[0][4] == set(), "IPv6 must not advertise honeypot ports without listeners"


@pytest.mark.asyncio
async def test_ip6tables_only_backend_builds_ipv6_not_ipv4(monkeypatch, tmp_path, fake_firewall):
    """With firewall_backend=ip6tables, only an IPv6 ruleset is built."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        firewall_backend="ip6tables",
        enable_ipv6=False,  # explicitly off; backend still drives IPv6
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert not ipv4_calls, "IPv4 rules should not be built in ip6tables-only mode"
    assert ipv6_calls, "IPv6 rules should be built in ip6tables-only mode"
    assert ipv6_calls[0][2] == "TSUNAMIWALL"

