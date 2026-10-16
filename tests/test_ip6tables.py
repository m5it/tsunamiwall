import pytest

from tsunamiwall.ip6tables import Ip6tablesError, build_rules, run_ip6tables


def test_run_ip6tables_uses_correct_binary(monkeypatch):
    commands = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        class Result:
            returncode = 0
            stderr = ""
        return Result()

    monkeypatch.setattr("subprocess.run", fake_run)
    run_ip6tables("-L")

    assert commands and commands[0][0] == "ip6tables"


def test_build_rules_creates_ipv6_chain(monkeypatch):
    commands = []

    def fake_run(*args):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.ip6tables.run_ip6tables", fake_run)

    build_rules(
        "TW-TEST6",
        allowed_ports={22},
        honeypot_ports={10005},
        blocked_ports={1337},
        allowed_per_ip={"2001:db8::/32": {8080}},
    )

    # Should build in shadow chain and swap.
    assert any("TW-TEST6_NEW" in str(cmd) for cmd in commands)
    assert any("-j" in cmd and "LOG" in cmd and "TSUNAMIWALL-DROP" in str(cmd) for cmd in commands)
    assert any("-j" in cmd and "DROP" in cmd for cmd in commands)

    # Rate limiting present on LOG rules.
    log_commands = [cmd for cmd in commands if "LOG" in cmd]
    for cmd in log_commands:
        assert "limit" in cmd, f"LOG rule missing rate limit matcher: {cmd}"

    # IPv6-specific blocked port log.
    block_logs = [cmd for cmd in commands if "TSUNAMIWALL-BLOCK" in str(cmd)]
    assert block_logs


def test_build_rules_shadow_swap_atomic(monkeypatch):
    commands = []

    def fake_run(*args):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.ip6tables.run_ip6tables", fake_run)

    build_rules(
        "TW-TEST6",
        allowed_ports={22},
        honeypot_ports=set(),
    )

    # INPUT jump should be installed to shadow, then renamed.
    assert any(cmd[:4] == ("-I", "INPUT", "1", "-j") and "TW-TEST6_NEW" in cmd for cmd in commands)
    assert any(cmd[:2] == ("-E", "TW-TEST6") and "TW-TEST6_OLD" in cmd for cmd in commands)
    assert any(cmd[:2] == ("-E", "TW-TEST6_NEW") and "TW-TEST6" in cmd for cmd in commands)


def test_build_rules_rollback_on_failure(monkeypatch):
    commands = []
    fail_after = 5

    def fake_run(*args):
        nonlocal fail_after
        commands.append(args)
        fail_after -= 1
        if fail_after == 0:
            raise Ip6tablesError("simulated failure")

    monkeypatch.setattr("tsunamiwall.ip6tables.run_ip6tables", fake_run)

    with pytest.raises(Ip6tablesError):
        build_rules(
            "TW-TEST6",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # Active chain jump should be restored.
    assert any(cmd[:4] == ("-I", "INPUT", "1", "-j") and "TW-TEST6" in cmd for cmd in commands)
