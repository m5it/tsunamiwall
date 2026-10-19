import sys
from pathlib import Path

import pytest

from tsunamiwall.config import Config
from tsunamiwall.firewall import (
    FirewallBackend,
    IptablesBackend,
    NoopBackend,
    PfctlBackend,
    _filter_ips,
    _filter_per_ip,
    detect_backend_name,
    get_backend,
)


def test_detect_backend_name_linux():
    assert detect_backend_name() == ("pfctl" if sys.platform == "darwin" else "iptables")


def test_get_backend_auto_selects_pfctl_on_macos(monkeypatch):
    cfg = Config(firewall_backend="auto")
    monkeypatch.setattr("sys.platform", "darwin")
    backend = get_backend(cfg, family="ipv4")
    assert isinstance(backend, PfctlBackend)


def test_get_backend_auto_selects_iptables_on_linux(monkeypatch):
    cfg = Config(firewall_backend="auto")
    monkeypatch.setattr("sys.platform", "linux")
    backend = get_backend(cfg, family="ipv4")
    assert isinstance(backend, IptablesBackend)
    assert backend.command == "iptables"


def test_get_backend_auto_selects_ip6tables_for_ipv6(monkeypatch):
    cfg = Config(firewall_backend="auto")
    monkeypatch.setattr("sys.platform", "linux")
    backend = get_backend(cfg, family="ipv6")
    assert isinstance(backend, IptablesBackend)
    assert backend.command == "ip6tables"


def test_get_backend_noop():
    cfg = Config(firewall_backend="noop")
    backend = get_backend(cfg, family="ipv4")
    assert isinstance(backend, NoopBackend)


def test_get_backend_explicit_ip6tables():
    cfg = Config(firewall_backend="ip6tables")
    backend = get_backend(cfg, family="ipv4")
    assert isinstance(backend, IptablesBackend)
    assert backend.command == "ip6tables"


def test_config_accepts_ip6tables_backend():
    cfg = Config(firewall_backend="ip6tables")
    assert cfg.firewall_backend == "ip6tables"


def test_config_rejects_unknown_backend():
    with pytest.raises(ValueError):
        Config(firewall_backend="windows")


def test_iptables_backend_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/iptables" if name == "iptables" else None)
    assert IptablesBackend(command="iptables").is_available()


def test_pfctl_backend_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/sbin/pfctl" if name == "pfctl" else None)
    assert PfctlBackend(cfg=Config()).is_available()


def test_iptables_backend_filters_trusted_ips_by_family(monkeypatch):
    """IPv4 backend must not receive IPv6 trusted IPs and vice versa."""
    monkeypatch.setattr("tsunamiwall.iptables.ensure_chain", lambda chain: None)
    monkeypatch.setattr("tsunamiwall.iptables._chain_exists", lambda chain: False)
    monkeypatch.setattr("tsunamiwall.iptables.flush_chain", lambda chain: None)
    monkeypatch.setattr("tsunamiwall.iptables._remove_jump", lambda chain: None)

    calls = []
    def fake_run_iptables(*args, **kwargs):
        calls.append(args)
    monkeypatch.setattr("tsunamiwall.iptables.run_iptables", fake_run_iptables)

    backend = IptablesBackend(command="iptables")
    backend.build_rules(
        "TSUNAMIWALL",
        {22},
        {10005},
        trusted_ips=["192.0.2.1", "2001:db8::1", "10.0.0.0/8"],
        allowed_per_ip={"192.0.2.5": {80}, "2001:db8::5": {443}},
        family="ipv4",
    )

    trusted_args = [
        args for args in calls
        if len(args) >= 6 and args[:2] == ("-A", "TSUNAMIWALL_NEW") and args[2] == "-s" and args[4] == "-j" and args[5] == "ACCEPT"
    ]
    sources = {args[3] for args in trusted_args}
    assert sources == {"192.0.2.1", "10.0.0.0/8"}
    assert "2001:db8::1" not in sources

    per_ip_args = [
        args for args in calls
        if len(args) == 10 and args[:2] == ("-A", "TSUNAMIWALL_NEW") and args[2] == "-s" and "ACCEPT" in args
    ]
    per_ip_sources = {args[3] for args in per_ip_args}
    assert per_ip_sources == {"192.0.2.5"}
    assert "2001:db8::5" not in per_ip_sources


def test_ip6tables_backend_filters_trusted_ips_by_family(monkeypatch):
    """IPv6 backend must not receive IPv4 trusted IPs."""
    monkeypatch.setattr("tsunamiwall.ip6tables.ensure_chain", lambda chain: None)
    monkeypatch.setattr("tsunamiwall.ip6tables._chain_exists", lambda chain: False)
    monkeypatch.setattr("tsunamiwall.ip6tables.flush_chain", lambda chain: None)
    monkeypatch.setattr("tsunamiwall.ip6tables._remove_jump", lambda chain: None)

    calls = []
    def fake_run_ip6tables(*args, **kwargs):
        calls.append(args)
    monkeypatch.setattr("tsunamiwall.ip6tables.run_ip6tables", fake_run_ip6tables)

    backend = IptablesBackend(command="ip6tables")
    backend.build_rules(
        "TSUNAMIWALL6",
        {22},
        {10005},
        trusted_ips=["192.0.2.1", "2001:db8::1", "::/0"],
        allowed_per_ip={"192.0.2.5": {80}, "2001:db8::5": {443}},
        family="ipv6",
    )

    trusted_args = [
        args for args in calls
        if len(args) >= 6 and args[:2] == ("-A", "TSUNAMIWALL6_NEW") and args[2] == "-s" and args[4] == "-j" and args[5] == "ACCEPT"
    ]
    sources = {args[3] for args in trusted_args}
    assert sources == {"2001:db8::1", "::/0"}
    assert "192.0.2.1" not in sources

    per_ip_args = [
        args for args in calls
        if len(args) == 10 and args[:2] == ("-A", "TSUNAMIWALL6_NEW") and args[2] == "-s" and "ACCEPT" in args
    ]
    per_ip_sources = {args[3] for args in per_ip_args}
    assert per_ip_sources == {"2001:db8::5"}
    assert "192.0.2.5" not in per_ip_sources


def test_pfctl_backend_filters_by_family(monkeypatch):
    """pfctl backend should only emit rules for the requested address family."""
    monkeypatch.setattr("shutil.which", lambda name: "/sbin/pfctl")
    backend = PfctlBackend(cfg=Config())

    configs = []
    original_run = backend._run
    def fake_run(*args):
        # Read the temp config before it is deleted.
        config_path = args[-1]
        configs.append(Path(config_path).read_text(encoding="utf-8"))
        return ""
    monkeypatch.setattr(backend, "_run", fake_run)

    backend.build_rules(
        "tsunamiwall",
        {22},
        {10005},
        trusted_ips=["192.0.2.1", "2001:db8::1"],
        allowed_per_ip={"192.0.2.5": {80}, "2001:db8::5": {443}},
        family="ipv4",
    )

    assert len(configs) == 1
    config_text = configs[0]
    assert "192.0.2.1" in config_text
    assert "192.0.2.5" in config_text
    assert "2001:db8::1" not in config_text
    assert "2001:db8::5" not in config_text
    assert "inet6" not in config_text


def test_ip_family_helpers():
    assert _filter_ips(["192.0.2.1", "2001:db8::1", "10.0.0.0/8", "bad"], "ipv4") == ["192.0.2.1", "10.0.0.0/8"]
    assert _filter_ips(["192.0.2.1", "2001:db8::1", "::/0"], "ipv6") == ["2001:db8::1", "::/0"]
    assert _filter_per_ip({"192.0.2.1": [22], "2001:db8::1": [22, 80]}, "ipv4") == {"192.0.2.1": {22}}
    assert _filter_per_ip({"192.0.2.1": [22], "2001:db8::1": [22, 80]}, "ipv6") == {"2001:db8::1": {22, 80}}


def test_noop_backend_build_rules_does_nothing():
    backend = NoopBackend()
    backend.build_rules("CHAIN", {22}, {10005})
    backend.reset("CHAIN")
