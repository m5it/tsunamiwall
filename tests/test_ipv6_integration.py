import pytest

from tsunamiwall.config import Config
from tsunamiwall.daemon import Daemon


@pytest.mark.asyncio
async def test_ipv6_rules_built_when_enabled(monkeypatch, tmp_path):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        max_honeypots=0,
    )

    calls = []

    def fake_ipv4(*args, **kwargs):
        calls.append(("ipv4", args, kwargs))

    def fake_ipv6(*args, **kwargs):
        calls.append(("ipv6", args, kwargs))

    monkeypatch.setattr("tsunamiwall.daemon.build_rules", fake_ipv4)
    monkeypatch.setattr("tsunamiwall.daemon.build_rules_ipv6", fake_ipv6)
    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in calls if c[0] == "ipv4"]
    ipv6_calls = [c for c in calls if c[0] == "ipv6"]
    assert ipv4_calls, "IPv4 rules should always be built"
    assert ipv6_calls, "IPv6 rules should be built when enable_ipv6 is true"
    assert ipv6_calls[0][1][0] == "TSUNAMIWALL6"


@pytest.mark.asyncio
async def test_ipv6_rules_not_built_when_disabled(monkeypatch, tmp_path):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=False,
        max_honeypots=0,
    )

    calls = []

    def fake_ipv4(*args, **kwargs):
        calls.append(("ipv4", args, kwargs))

    def fake_ipv6(*args, **kwargs):
        calls.append(("ipv6", args, kwargs))

    monkeypatch.setattr("tsunamiwall.daemon.build_rules", fake_ipv4)
    monkeypatch.setattr("tsunamiwall.daemon.build_rules_ipv6", fake_ipv6)
    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv6_calls = [c for c in calls if c[0] == "ipv6"]
    assert not ipv6_calls, "IPv6 rules should not be built when enable_ipv6 is false"


def test_ipv6_chain_property():
    cfg = Config(iptables_chain="CUSTOM")
    assert cfg.ipv6_chain == "CUSTOM6"
