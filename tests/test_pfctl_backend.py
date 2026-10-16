import re
import tempfile
import types
from pathlib import Path

import pytest

from tsunamiwall.config import Config
from tsunamiwall.firewall import PfctlBackend, PfctlError


def _intercept_pfctl_build(backend, **kwargs):
    """Run build_rules with an instance _run that records the temp file rules.

    The real _run is replaced on the instance so no pfctl command is executed,
    but build_rules still writes and cleans up its temporary rule file.
    """
    captured: list[tuple[tuple[str, ...], list[str]]] = []

    def fake_run(*args):
        path = args[args.index("-f") + 1]
        rules = Path(path).read_text(encoding="utf-8").splitlines()
        captured.append((args, rules))

    backend._run = fake_run  # type: ignore[method-assign]
    backend.build_rules("testanchor/ipv4", **kwargs)
    assert len(captured) == 1
    return captured[0]


def test_pfctl_build_rules_ipv4():
    backend = PfctlBackend(Config(pfctl_anchor="testanchor"))
    args, rules = _intercept_pfctl_build(
        backend,
        allowed_ports={22, 80},
        honeypot_ports={10005},
        blocked_ports={1337},
        trusted_ips=["203.0.113.0/24"],
        allowed_per_ip={"198.51.100.5": {8080}},
        family="ipv4",
    )
    assert args[:2] == ("-a", "testanchor/ipv4")
    assert "-f" in args
    assert any("inet" in line for line in rules)
    assert any("pass in quick inet from 203.0.113.0/24" in line for line in rules)
    assert any("pass in quick inet proto tcp from 198.51.100.5 to any port 8080" in line for line in rules)
    assert any("pass in quick inet proto tcp from any to any port 22" in line for line in rules)
    assert any("pass in quick inet proto tcp from any to any port 10005" in line for line in rules)
    assert any("block drop in log quick inet proto tcp from any to any port 1337" in line for line in rules)
    assert any("block drop in log quick inet from any to any" in line for line in rules)


def test_pfctl_build_rules_ipv6():
    backend = PfctlBackend(Config(pfctl_anchor="testanchor"))
    args, rules = _intercept_pfctl_build(
        backend,
        allowed_ports={22},
        honeypot_ports=set(),
        family="ipv6",
    )
    assert args[1] == "testanchor/ipv6"
    assert all("inet6" in line for line in rules if "from" in line or "to" in line)


def test_pfctl_anchor_path():
    cfg = Config(pfctl_anchor="com.example.tw")
    backend = PfctlBackend(cfg)
    assert backend._anchor("ipv4") == "com.example.tw/ipv4"


def test_pfctl_reset_flushes_anchor(monkeypatch):
    backend = PfctlBackend(Config(pfctl_anchor="testanchor"))
    calls = []

    def fake_run(*args):
        calls.append(args)

    backend._run = fake_run  # type: ignore[method-assign]
    backend.reset("ignored", family="ipv4")

    assert any("-a" in cmd and "testanchor/ipv4" in cmd and "-F" in cmd for cmd in calls)


def test_pfctl_reset_swallows_failure(caplog):
    backend = PfctlBackend(Config(pfctl_anchor="testanchor"))

    def fake_run(*args):
        raise PfctlError("simulated failure")

    backend._run = fake_run  # type: ignore[method-assign]
    backend.reset("ignored", family="ipv4")
    assert "Could not flush pfctl anchor" in caplog.text
