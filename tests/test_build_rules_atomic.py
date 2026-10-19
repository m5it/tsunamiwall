import pytest

from tsunamiwall.iptables import IptablesError, build_rules


def _mock_jump_detection(monkeypatch):
    """Make _jump_exists return False so build_rules performs its INPUT inserts."""
    monkeypatch.setattr("tsunamiwall.iptables._jump_exists", lambda chain: False)



def _dport_idx(args, dport):
    if "--dport" not in args:
        return None
    return args.index("--dport") + 1 if args[args.index("--dport") + 1] == str(dport) else None


def test_build_rules_uses_shadow_chain_and_swaps(monkeypatch):
    _mock_jump_detection(monkeypatch)
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
    _mock_jump_detection(monkeypatch)
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
    jumps = {"TW-TEST": 1}  # existing active jump

    def fake_run(*args, **kwargs):
        commands.append(args)
        if args[0] == "-I" and "INPUT" in args:
            jumps[args[4]] = jumps.get(args[4], 0) + 1
        elif args[0] == "-D" and "INPUT" in args:
            chain = args[3]
            if jumps.get(chain, 0) > 0:
                jumps[chain] -= 1
            else:
                raise IptablesError("no jump")
        elif should_fail and "TW-TEST_NEW" in args and "ACCEPT" in args:
            raise IptablesError("simulated failure")

    def fake_jump_exists(chain):
        return jumps.get(chain, 0) > 0

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)
    monkeypatch.setattr("tsunamiwall.iptables._jump_exists", fake_jump_exists)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", lambda chain: chain in jumps or chain == "TW-TEST_NEW")

    with pytest.raises(Exception):
        build_rules(
            "TW-TEST",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # The active chain jump must be preserved (not duplicated) after shadow build failure.
    assert jumps["TW-TEST"] == 1, "active chain jump must be preserved after shadow build failure"

    # Shadow jump should have been removed.
    removed_shadow_jump = [cmd for cmd in commands if cmd[:2] == ("-D", "INPUT") and "TW-TEST_NEW" in cmd]
    assert removed_shadow_jump, "incomplete shadow chain jump must be removed"


def test_build_rules_installs_shadow_jump_before_removing_old(monkeypatch):
    _mock_jump_detection(monkeypatch)
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
    _mock_jump_detection(monkeypatch)
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
    _mock_jump_detection(monkeypatch)
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



def test_install_jump_if_missing_uses_check_command(monkeypatch):
    """_install_jump_if_missing should use -C, not parse -L output for -j."""
    from tsunamiwall.iptables import _install_jump_if_missing

    run_calls = []

    def fake_run_iptables(*args, **kwargs):
        run_calls.append(args)
        if args[:3] == ("-C", "INPUT", "-j"):
            return  # jump exists
        if args[0] in ("-I", "-D", "-F", "-X", "-E", "-N"):
            return
        raise IptablesError("unexpected")

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run_iptables)

    _install_jump_if_missing("TSUNAMIWALL")

    assert any(c[:3] == ("-C", "INPUT", "-j") and "TSUNAMIWALL" in c for c in run_calls)
    assert not any(c[0] == "-I" for c in run_calls), "no insert when jump already exists"


def test_install_jump_if_missing_inserts_when_absent(monkeypatch):
    from tsunamiwall.iptables import _install_jump_if_missing

    run_calls = []

    def fake_run_iptables(*args, **kwargs):
        run_calls.append(args)
        if args[:3] == ("-C", "INPUT", "-j"):
            raise IptablesError("jump does not exist")

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run_iptables)

    _install_jump_if_missing("TSUNAMIWALL")

    assert any(c[:4] == ("-I", "INPUT", "1", "-j") and "TSUNAMIWALL" in c for c in run_calls)


def test_delete_chain_removes_all_duplicate_jumps(monkeypatch):
    from tsunamiwall.iptables import delete_chain

    removals = []
    jumps = {"TSUNAMIWALL": 3}

    def fake_run_iptables(*args, **kwargs):
        removals.append(args)
        if args[:2] == ("-D", "INPUT") and "TSUNAMIWALL" in args:
            if jumps["TSUNAMIWALL"] > 0:
                jumps["TSUNAMIWALL"] -= 1
                return
            raise IptablesError("no more jumps")

    def fake_jump_exists(chain):
        return jumps.get(chain, 0) > 0

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run_iptables)
    monkeypatch.setattr("tsunamiwall.iptables._jump_exists", fake_jump_exists)
    monkeypatch.setattr("tsunamiwall.iptables.flush_chain", lambda chain: None)

    delete_chain("TSUNAMIWALL")

    jump_removals = [c for c in removals if c[:2] == ("-D", "INPUT")]
    assert len(jump_removals) == 3, "all duplicate jumps must be removed"


def test_reset_cleans_new_and_old_chains(monkeypatch):
    from tsunamiwall.iptables import reset

    deleted = []

    def fake_delete_chain(chain):
        deleted.append(chain)

    monkeypatch.setattr("tsunamiwall.iptables.delete_chain", fake_delete_chain)

    reset("TSUNAMIWALL")

    assert sorted(deleted) == ["TSUNAMIWALL", "TSUNAMIWALL_NEW", "TSUNAMIWALL_OLD"]


def test_build_rules_no_duplicate_jump_after_rollback(monkeypatch):
    """Rollback must not add a duplicate jump if the active jump already exists."""
    from tsunamiwall import iptables as iptables_mod
    commands = []
    jumps = {"TSUNAMIWALL": 1}  # one existing jump to active chain

    def fake_run_iptables(*args, **kwargs):
        commands.append(args)
        if args[:3] == ("-C", "INPUT", "-j"):
            chain = args[3]
            if jumps.get(chain, 0) == 0:
                raise IptablesError("rule does not exist")
            return
        if args[0] == "-I":
            chain = args[4]
            jumps[chain] = jumps.get(chain, 0) + 1
        elif args[0] == "-D":
            chain = args[3]
            if jumps.get(chain, 0) > 0:
                jumps[chain] -= 1
            else:
                raise IptablesError("no jump")

    def fake_chain_exists(chain):
        return chain in jumps or chain.endswith("_NEW")

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run_iptables)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", fake_chain_exists)

    # Make the rename from active to old fail so rollback runs.
    original = iptables_mod._rename_chain
    def fail_rename_active_to_old(old, new):
        if old == "TSUNAMIWALL" and new == "TSUNAMIWALL_OLD":
            raise IptablesError("simulated")
        original(old, new)

    monkeypatch.setattr("tsunamiwall.iptables._rename_chain", fail_rename_active_to_old)

    with pytest.raises(IptablesError):
        build_rules(
            "TSUNAMIWALL",
            allowed_ports={22},
            honeypot_ports=set(),
        )

    # Active jump should remain exactly 1, not duplicated.
    assert jumps["TSUNAMIWALL"] == 1, f"expected 1 active jump, got {jumps['TSUNAMIWALL']}"

