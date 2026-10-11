import os
import tempfile

import pytest

from tsunamiwall.config import Config, load_config


def test_trusted_ips_accepted_and_validated():
    cfg = Config(trusted_ips=["203.0.113.45", "198.51.100.0/24"])
    assert "203.0.113.45" in cfg.trusted_ips
    assert "198.51.100.0/24" in cfg.trusted_ips


def test_trusted_ips_reject_invalid():
    with pytest.raises(ValueError, match="invalid IP/CIDR"):
        Config(trusted_ips=["not-an-ip"])


def test_load_config_with_trusted_ips():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write("trusted_ips:\n")
        fh.write("  - 203.0.113.45\n")
        fh.write("  - 2001:db8::/32\n")
        path = fh.name
    try:
        cfg = load_config(path)
        assert cfg.trusted_ips == ["203.0.113.45", "2001:db8::/32"]
    finally:
        os.remove(path)
