import pytest

from tsunamiwall.config import Config
from tsunamiwall.daemon import Daemon
from tsunamiwall.honeypot import HoneypotServer
from tsunamiwall.iptables import build_rules


def _commands_from_build_rules(monkeypatch, **kwargs):
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)
    build_rules("TW-TEST", **kwargs)
    return commands


def test_blocked_port_drop_precedes_accepts(monkeypatch):
    """Blocked ports must be dropped before any per-IP or global ACCEPT rules."""
    commands = _commands_from_build_rules(
        monkeypatch,
        allowed_ports={22, 80},
        honeypot_ports={10005},
        allowed_per_ip={"192.168.1.5": {8080, 8443}},
        blocked_ports={8080},
    )

    block_indices = [i for i, cmd in enumerate(commands) if any("TSUNAMIWALL-BLOCK" in str(part) for part in cmd)]
    assert block_indices, "blocked-port rules must be emitted"

    # No ACCEPT rules for the blocked port from any source.
    for idx, cmd in enumerate(commands):
        if "ACCEPT" in cmd and "--dport" in cmd:
            dport = cmd[cmd.index("--dport") + 1]
            assert dport != "8080", "blocked port must not have an ACCEPT rule"

    # The first block rule comes before the first per-IP or global allow rule.
    first_allow_idx = next(
        i
        for i, cmd in enumerate(commands)
        if "ACCEPT" in cmd and "--dport" in cmd and cmd[cmd.index("--dport") + 1] != "8080"
    )
    assert min(block_indices) < first_allow_idx


@pytest.mark.asyncio
async def test_blocked_discovered_service_not_allowed(monkeypatch, tmp_path, fake_firewall):
    """A listening service on a blocked port must not be auto-allowed globally."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: {22, 8080})
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    daemon.blocked_ports = {8080}

    await daemon._reconcile()

    build_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    assert build_calls, "IPv4 rules should have been built"
    allowed = build_calls[-1][3]
    assert 22 in allowed, "unblocked listening service should be auto-allowed"
    assert 8080 not in allowed, "blocked listening service must not be auto-allowed"


@pytest.mark.asyncio
async def test_blocked_port_not_a_honeypot(monkeypatch, tmp_path, fake_firewall):
    """A blocked port must not be picked up as a honeypot listener."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        honeypot_start=10000,
        honeypot_end=10002,
        max_honeypots=3,
    )

    async def fake_hp_start(self):
        return None

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr(HoneypotServer, "start", fake_hp_start)

    daemon = Daemon(cfg)
    daemon.blocked_ports = {10000, 10001}

    await daemon._reconcile()

    build_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    honeypots = build_calls[-1][4]
    assert 10000 not in honeypots, "blocked port must not become a honeypot"
    assert 10001 not in honeypots, "blocked port must not become a honeypot"
    assert 10002 in honeypots, "unblocked available port should become a honeypot"


@pytest.mark.asyncio
async def test_blocked_per_ip_port_suppressed(monkeypatch, tmp_path, fake_firewall):
    """A per-IP allow rule is suppressed when the same port is globally blocked."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        max_honeypots=0,
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: set())
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    daemon.allowed_per_ip = {"192.168.1.5": {8080, 8443}}
    daemon.blocked_ports = {8080}

    await daemon._reconcile()

    build_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    allowed, per_ip = build_calls[-1][3], build_calls[-1][6]
    assert 8080 not in allowed, "blocked port must not be globally allowed"
    assert per_ip.get("192.168.1.5", set()) == {8443}, "blocked port must be removed from per-IP allow"


def test_build_rules_blocked_per_ip_not_emitted(monkeypatch):
    """build_rules must not emit per-IP ACCEPT rules for a globally blocked port."""
    commands = _commands_from_build_rules(
        monkeypatch,
        allowed_ports={22},
        honeypot_ports=set(),
        allowed_per_ip={"192.168.1.5": {8080, 8443}},
        blocked_ports={8080},
    )

    per_ip_dports = {
        cmd[cmd.index("--dport") + 1]
        for cmd in commands
        if "-s" in cmd and cmd[cmd.index("-s") + 1] == "192.168.1.5" and "ACCEPT" in cmd
    }
    assert "8080" not in per_ip_dports, "globally blocked port must not have per-IP ACCEPT"
    assert "8443" in per_ip_dports, "unblocked per-IP port should still be allowed"
