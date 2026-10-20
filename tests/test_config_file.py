import os
import tempfile

import pytest

from tsunamiwall.config import Config, load_config


def test_load_config_from_explicit_path():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write("honeypot_start: 12000\n")
        fh.write("honeypot_end: 13000\n")
        fh.write("max_honeypots: 50\n")
        path = fh.name
    try:
        cfg = load_config(path)
        assert cfg.honeypot_start == 12_000
        assert cfg.honeypot_end == 13_000
        assert cfg.max_honeypots == 50
    finally:
        os.remove(path)


def test_load_config_uses_defaults_when_file_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = os.path.join(tmpdir, "missing.yaml")
        cfg = load_config(missing)
        assert cfg.honeypot_start == 10_000


def test_load_config_rejects_unknown_key():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write("unknown_key: 123\n")
        path = fh.name
    try:
        with pytest.raises(ValueError, match="Unknown config key"):
            load_config(path)
    finally:
        os.remove(path)


def test_load_config_rejects_bad_value():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write("honeypot_start: not_a_number\n")
        path = fh.name
    try:
        with pytest.raises((ValueError, TypeError)):
            load_config(path)
    finally:
        os.remove(path)


def test_load_config_via_environment(monkeypatch):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write("discovery_interval: 5.0\n")
        path = fh.name
    try:
        monkeypatch.setenv("TSUNAMIWALL_CONFIG", path)
        cfg = load_config()
        assert cfg.discovery_interval == 5.0
    finally:
        os.remove(path)


def test_load_config_accepts_string_booleans():
    """Quoted "true" / "false" strings should be parsed as booleans."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write('enable_ipv6: "true"\n')
        fh.write('auto_block_listeners: "false"\n')
        path = fh.name
    try:
        cfg = load_config(path)
        assert cfg.enable_ipv6 is True
        assert cfg.auto_block_listeners is False
    finally:
        os.remove(path)


def test_load_config_rejects_invalid_string_booleans():
    """Arbitrary string values for boolean fields should raise."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        fh.write('enable_ipv6: "yes"\n')
        path = fh.name
    try:
        with pytest.raises(ValueError, match="must be a boolean"):
            load_config(path)
    finally:
        os.remove(path)

