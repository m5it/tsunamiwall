import sys

import pytest

from tsunamiwall.config import Config
from tsunamiwall.firewall import (
    FirewallBackend,
    IptablesBackend,
    NoopBackend,
    PfctlBackend,
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


def test_noop_backend_build_rules_does_nothing():
    backend = NoopBackend()
    backend.build_rules("CHAIN", {22}, {10005})
    backend.reset("CHAIN")
