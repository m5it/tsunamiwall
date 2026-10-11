import pytest

from tsunamiwall.config import Config, default_config, safe_ports


def test_default_config_is_valid():
    cfg = default_config()
    assert cfg.honeypot_start == 10_000
    assert cfg.honeypot_end == 65_535
    assert cfg.max_honeypots > 0


def test_config_rejects_bad_port_range():
    with pytest.raises(ValueError):
        Config(honeypot_start=70000, honeypot_end=10000)


def test_safe_ports_excludes_used():
    cfg = Config(honeypot_start=10_000, honeypot_end=10_010, max_honeypots=100)
    used = {10_005, 10_009}
    available = safe_ports(used, cfg)
    assert 10_005 not in available
    assert 10_009 not in available
    assert 10_000 in available
    assert 10_010 in available


def test_safe_ports_respects_max():
    cfg = Config(honeypot_start=10_000, honeypot_end=65_535, max_honeypots=5)
    available = safe_ports(set(), cfg)
    assert len(available) == 5
