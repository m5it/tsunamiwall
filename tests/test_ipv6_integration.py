from pathlib import Path

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


@pytest.mark.asyncio
async def test_ipv6_enabled_includes_ipv6_ports_in_managed_allowed(monkeypatch, tmp_path, fake_firewall):
    """When enable_ipv6 is true, _reconcile should discover and allow IPv6-only ports."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        auto_block_listeners=False,
        max_honeypots=0,
    )

    def fake_discover_ports(*, include_tcp, include_udp, include_ipv6):
        ports = {8080}  # IPv4 service
        if include_ipv6:
            ports.add(8443)  # IPv6-only service
        return ports

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", fake_discover_ports)
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert ipv4_calls, "IPv4 rules should be built"
    assert ipv6_calls, "IPv6 rules should be built"
    # Both the IPv4 and IPv6 rulesets must include the IPv6-only service port.
    assert 8443 in ipv4_calls[0][3], "IPv6-only port must be allowed in IPv4 ruleset when enable_ipv6 is true"
    assert 8443 in ipv6_calls[0][3], "IPv6-only port must be allowed in IPv6 ruleset"


@pytest.mark.asyncio
async def test_ip6tables_only_includes_ipv6_ports_in_managed_allowed(monkeypatch, tmp_path, fake_firewall):
    """When firewall_backend is ip6tables, _reconcile should discover and allow IPv6-only ports."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        firewall_backend="ip6tables",
        enable_ipv6=False,
        auto_block_listeners=False,
        max_honeypots=0,
    )

    def fake_discover_ports(*, include_tcp, include_udp, include_ipv6):
        ports = {8080}  # IPv4 service (should be ignored by the IPv6 backend)
        if include_ipv6:
            ports.add(8443)  # IPv6-only service
        return ports

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", fake_discover_ports)
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    ipv4_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    ipv6_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv6"]
    assert not ipv4_calls, "IPv4 rules should not be built in ip6tables-only mode"
    assert ipv6_calls, "IPv6 rules should be built"
    assert 8443 in ipv6_calls[0][3], "IPv6-only port must be allowed in IPv6 ruleset"


@pytest.mark.asyncio
async def test_ipv6_disabled_does_not_discover_ipv6_ports(monkeypatch, tmp_path, fake_firewall):
    """When IPv6 is not enabled, _reconcile should not ask discover_ports for IPv6."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=False,
        firewall_backend="iptables",
        auto_block_listeners=False,
        max_honeypots=0,
    )

    calls = []

    def fake_discover_ports(*, include_tcp, include_udp, include_ipv6):
        calls.append({"include_ipv6": include_ipv6})
        return {8080}

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", fake_discover_ports)
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    await daemon._reconcile()

    assert calls, "discover_ports should be called"
    assert not any(c["include_ipv6"] for c in calls), "IPv6 discovery should be disabled"


@pytest.mark.asyncio
async def test_ipv6_startup_failure_is_fatal(monkeypatch, tmp_path, fake_firewall):
    """When IPv6 build_rules fails during initial startup, the daemon must fail."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    class FailingIPv6Backend:
        def __init__(self, calls):
            self.calls = calls

        def build_rules(self, chain, allowed, honeypots, *, family, **kwargs):
            self.calls.append(("build", family, chain))
            if family == "ipv6":
                raise RuntimeError("simulated IPv6 failure")

        def reset(self, chain, family="ipv4"):
            self.calls.append(("reset", family, chain))

        def is_available(self):
            return True

    def factory(cfg, family):
        return FailingIPv6Backend(fake_firewall)

    monkeypatch.setattr("tsunamiwall.daemon.get_backend", factory)

    daemon = Daemon(cfg)
    with pytest.raises(RuntimeError, match="simulated IPv6 failure"):
        await daemon._reconcile()


@pytest.mark.asyncio
async def test_ipv6_reconcile_failure_is_tolerated_after_startup(monkeypatch, tmp_path, fake_firewall):
    """After startup, an IPv6 ruleset failure should be logged but not crash."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    call_count = {"build": 0}

    class CountingIPv6Backend:
        def __init__(self):
            self.calls = 0

        def build_rules(self, chain, allowed, honeypots, *, family, **kwargs):
            self.calls += 1
            if family == "ipv6" and self.calls > 1:
                raise RuntimeError("transient IPv6 failure")

        def reset(self, chain, family="ipv4"):
            pass

        def is_available(self):
            return True

    def factory(cfg, family):
        return CountingIPv6Backend()

    monkeypatch.setattr("tsunamiwall.daemon.get_backend", factory)

    daemon = Daemon(cfg)
    await daemon._reconcile()  # startup succeeds
    daemon._startup_phase = False
    await daemon._reconcile()  # transient failure is tolerated


@pytest.mark.asyncio
async def test_startup_rollback_on_ipv6_failure(monkeypatch, tmp_path):
    """If IPv6 build_rules fails during start(), stop() must roll back primary rules and the PID file."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        enable_ipv6=True,
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    calls = []

    class FailingIPv6Backend:
        def __init__(self, family):
            self.family = family

        def build_rules(self, chain, allowed, honeypots, *, family, **kwargs):
            calls.append(("build", family, chain))
            if family == "ipv6":
                raise RuntimeError("simulated IPv6 failure")

        def reset(self, chain, family="ipv4"):
            calls.append(("reset", family, chain))

        def is_available(self):
            return True

    monkeypatch.setattr("tsunamiwall.daemon.get_backend", lambda cfg, family: FailingIPv6Backend(family))

    daemon = Daemon(cfg)
    with pytest.raises(RuntimeError, match="simulated IPv6 failure"):
        await daemon.start()

    assert not Path(cfg.pid_path).exists(), "PID file must be removed on startup rollback"
    resets = [c for c in calls if c[0] == "reset"]
    assert any(c[1] == "ipv4" for c in resets), "IPv4 chain must be reset during rollback"
    assert any(c[1] == "ipv6" for c in resets), "IPv6 chain must be reset during rollback"

