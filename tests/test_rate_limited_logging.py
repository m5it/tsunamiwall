from tsunamiwall.iptables import build_rules


def test_build_rules_adds_rate_limit_to_log_rules(monkeypatch):
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules(
        "TW-TEST",
        allowed_ports={22},
        honeypot_ports=set(),
        blocked_ports={1337},
        log_rate_limit=15,
        log_rate_burst=30,
    )

    log_rules = [cmd for cmd in commands if "LOG" in cmd]
    for cmd in log_rules:
        assert "-m" in cmd and "limit" in cmd, f"LOG rule missing rate limit matcher: {cmd}"
        assert "--limit" in cmd, f"LOG rule missing --limit: {cmd}"
        limit_idx = cmd.index("--limit")
        assert cmd[limit_idx + 1] == "15/second"
        assert "--limit-burst" in cmd, f"LOG rule missing --limit-burst: {cmd}"
        burst_idx = cmd.index("--limit-burst")
        assert cmd[burst_idx + 1] == "30"


def test_rate_limit_defaults_used_when_not_specified(monkeypatch):
    commands = []

    def fake_run(*args, **kwargs):
        commands.append(args)

    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run)

    build_rules("TW-TEST", allowed_ports={22}, honeypot_ports=set())

    log_rules = [cmd for cmd in commands if "LOG" in cmd]
    assert log_rules, "at least one LOG rule should exist"
    for cmd in log_rules:
        assert "--limit" in cmd
        limit_idx = cmd.index("--limit")
        assert cmd[limit_idx + 1] == "10/second"
