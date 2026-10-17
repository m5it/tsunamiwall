import pytest

from tsunamiwall.iptables import IptablesError, build_rules


def _dport_idx(args, dport):
    if "--dport" not in args:
        return None
    return args.index("--dport") + 1 if args[args.index("--dport") + 1] == str(dport) else None


def test_build_rules_uses_shadow_chain_and_swaps(monkeypatch):
    """build_rules should build in a shadow chain, swap, and clean up the old chain."""
    commands = []

    def fake_run(*args, **kwargs):
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

    def fake_run(*args, **kwargs):
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

    def fake_run(*args, **kwargs):
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


def test_build_rules_installs_shadow_jump_before_removing_old(monkeypatch):
    """The shadow jump must be inserted before the active jump is removed."""
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", lambda chain: True)

    build_rules(
        "TW-TEST",
        allowed_ports={22},
        honeypot_ports=set(),
    )

    input_cmds = [cmd for cmd in commands if cmd[0] in ("-I", "-D") and cmd[1] == "INPUT"]
    assert input_cmds[0][:4] == ("-I", "INPUT", "1", "-j"), "first INPUT manipulation must insert a jump"
    assert "TW-TEST_NEW" in input_cmds[0], "first INPUT jump must target the shadow chain"


def test_build_rules_rollback_on_rename_active_to_old(monkeypatch):
    """If renaming the active chain to _OLD fails, revert to the active chain."""
    commands = []
    chains = {"TW-TEST"}
    trigger = {"fail": True}

    def fake_run(*args, **kwargs):
        commands.append(args)
        if args[0] == "-N":
            chains.add(args[1])
        elif args[0] == "-X":
            chains.discard(args[1])
        elif args[0] == "-E":
            old, new = args[1], args[2]
            if trigger["fail"] and old == "TW-TEST" and new == "TW-TEST_OLD":
                raise IptablesError("simulated rename failure")
            chains.discard(old)
            chains.add(new)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", lambda chain: chain in chains)

    with pytest.raises(IptablesError):
        build_rules(
            "TW-TEST",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # The shadow jump should be removed and the active chain jump restored at top.
    inserts = [cmd for cmd in commands if cmd[:4] == ("-I", "INPUT", "1", "-j")]
    assert any("TW-TEST" in cmd and "TW-TEST_NEW" not in cmd for cmd in inserts), \
        "rollback must install a jump to the active chain"
    assert any(cmd[:2] == ("-D", "INPUT") and "TW-TEST_NEW" in cmd for cmd in commands), \
        "rollback must remove the shadow jump"


def test_build_rules_rollback_on_rename_shadow_to_active(monkeypatch):
    """If renaming the shadow chain to the active name fails, restore the old ruleset."""
    commands = []
    chains = {"TW-TEST"}
    trigger = {"fail": True}

    def fake_run(*args, **kwargs):
        commands.append(args)
        if args[0] == "-N":
            chains.add(args[1])
        elif args[0] == "-X":
            chains.discard(args[1])
        elif args[0] == "-E":
            old, new = args[1], args[2]
            if trigger["fail"] and old == "TW-TEST_NEW" and new == "TW-TEST":
                raise IptablesError("simulated shadow rename failure")
            chains.discard(old)
            chains.add(new)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", lambda chain: chain in chains)

    with pytest.raises(IptablesError):
        build_rules(
            "TW-TEST",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # The old ruleset should be renamed back to the active name.
    rollback_rename = [cmd for cmd in commands if cmd[:2] == ("-E", "TW-TEST_OLD") and "TW-TEST" in cmd]
    assert rollback_rename, "rollback must rename TW-TEST_OLD back to TW-TEST"

    # INPUT must be restored to jump to the active chain name.
    inserts = [cmd for cmd in commands if cmd[:4] == ("-I", "INPUT", "1", "-j")]
    assert any("TW-TEST" in cmd and "TW-TEST_NEW" not in cmd and "TW-TEST_OLD" not in cmd for cmd in inserts), \
        "rollback must install a jump to the restored active chain"
