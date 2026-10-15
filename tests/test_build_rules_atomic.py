import pytest

from tsunamiwall.iptables import build_rules


def _dport_idx(args, dport):
    if "--dport" not in args:
        return None
    return args.index("--dport") + 1 if args[args.index("--dport") + 1] == str(dport) else None


def test_build_rules_uses_shadow_chain_and_swaps(monkeypatch):
    """build_rules should build in a shadow chain, swap, and clean up the old chain."""
    commands = []

    def fake_run(*args):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22, 80},
        honeypot_ports={10005},
        blocked_ports={1337},
        allowed_per_ip={"192.168.1.5": {8080}},
    )

    # All rule population should target the shadow chain.
    assert not any(
        "TW-TEST" in cmd and "ACCEPT" in cmd and "-A" in cmd
        for cmd in commands
    ), "no rules should be appended directly to the active chain"

    shadow_appends = [cmd for cmd in commands if "TW-TEST_NEW" in cmd and "-A" in cmd]
    assert shadow_appends, "rules must be appended to the shadow chain"

    # Shadow chain must end with a DROP so it is fail-closed during construction.
    shadow_drop = [cmd for cmd in commands if "TW-TEST_NEW" in cmd and "-j" in cmd and "DROP" in cmd]
    assert shadow_drop, "shadow chain must have a DROP target"

    # Atomic swap: install jump to shadow, then rename active to old and shadow to active.
    jump_to_shadow = [cmd for cmd in commands if cmd[:4] == ("-I", "INPUT", "1", "-j") and "TW-TEST_NEW" in cmd]
    assert jump_to_shadow, "INPUT should jump to the shadow chain during swap"

    rename_active_to_old = [cmd for cmd in commands if cmd[:2] == ("-E", "TW-TEST") and "TW-TEST_OLD" in cmd]
    assert rename_active_to_old, "active chain should be renamed to _OLD"

    rename_shadow_to_active = [cmd for cmd in commands if cmd[:2] == ("-E", "TW-TEST_NEW") and "TW-TEST" in cmd and "TW-TEST_NEW" in cmd]
    assert rename_shadow_to_active, "shadow chain should be renamed to active name"


def test_build_rules_active_chain_never_flushed_empty(monkeypatch):
    """The active chain must not be flushed while it is jumped from INPUT."""
    commands = []

    def fake_run(*args):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22},
        honeypot_ports=set(),
    )

    flushes = [cmd for cmd in commands if "-F" in cmd]
    assert not any("TW-TEST" in cmd and "TW-TEST_NEW" not in cmd and "TW-TEST_OLD" not in cmd for cmd in flushes), \
        "active chain must not be flushed during normal build_rules"


def test_build_rules_rollback_on_shadow_failure(monkeypatch):
    """If populating the shadow chain fails, the active chain's jump must be restored."""
    commands = []
    should_fail = True

    def fake_run(*args):
        commands.append(args)
        if should_fail and "TW-TEST_NEW" in args and "ACCEPT" in args:
            from tsunamiwall.iptables import IptablesError
            raise IptablesError("simulated failure")

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    with pytest.raises(Exception):
        build_rules(
            "TW-TEST",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # The active chain must still have its INPUT jump restored.
    restored_jump = [cmd for cmd in commands if cmd[:4] == ("-I", "INPUT", "1", "-j") and "TW-TEST" in cmd]
    assert restored_jump, "active chain jump must be restored after shadow build failure"

    # Shadow jump should have been removed.
    removed_shadow_jump = [cmd for cmd in commands if cmd[:2] == ("-D", "INPUT") and "TW-TEST_NEW" in cmd]
    assert removed_shadow_jump, "incomplete shadow chain jump must be removed"
