import json

from tsunamiwall.iptables import build_rules


def test_build_rules_includes_per_ip(monkeypatch, tmp_path):
    """Per-IP allow rules should be added before global allow rules."""
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22, 80},
        honeypot_ports={10005},
        trusted_ips=["10.0.0.0/8"],
        allowed_per_ip={"192.168.1.5": {8080, 8443}},
    )

    # Find the indices of the per-ip rules and the global allow rules.
    per_ip_indices = []
    global_indices = []
    for idx, args in enumerate(commands):
        if "-s" in args:
            pos = args.index("-s")
            if args[pos + 1] == "192.168.1.5":
                per_ip_indices.append(idx)
        if "--dport" in args and "-s" not in args:
            pos = args.index("--dport")
            if args[pos + 1] in ("22", "80"):
                global_indices.append(idx)

    assert per_ip_indices, "no per-IP rules emitted"
    assert global_indices, "no global allow rules emitted"
    assert max(per_ip_indices) < min(global_indices), "per-IP rules must come before global allows"

    # Count per-IP rules: 2 ports x 2 protocols = 4.
    per_ip_rule_count = sum(
        1
        for args in commands
        if "-s" in args and args[args.index("-s") + 1] == "192.168.1.5" and "--dport" in args
    )
    assert per_ip_rule_count == 4


def test_build_rules_empty_per_ip_ignored(monkeypatch):
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22},
        honeypot_ports=set(),
        allowed_per_ip={"192.168.1.5": set(), "192.168.2.0/24": set()},
    )

    assert not any(
        "-s" in args and args[args.index("-s") + 1] in ("192.168.1.5", "192.168.2.0/24")
        for args in commands
    )
