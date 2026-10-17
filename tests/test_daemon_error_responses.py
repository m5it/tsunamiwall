"""Verify the daemon always returns JSON dicts, never pre-encoded strings."""
import json

import pytest

from tsunamiwall.daemon import Daemon
from tsunamiwall.config import Config


@pytest.fixture
def minimal_daemon(tmp_path):
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
        max_honeypots=0,
    )
    return Daemon(cfg)


@pytest.mark.asyncio
async def test_invalid_port_response_is_dict(minimal_daemon):
    resp = await minimal_daemon._process_command({"action": "allow", "port": 70000})
    assert isinstance(resp, dict)
    assert resp.get("ok") is False
    assert "invalid port" in resp.get("error", "")


@pytest.mark.asyncio
async def test_invalid_ports_response_is_dict(minimal_daemon):
    resp = await minimal_daemon._process_command({"action": "allow_many", "ports": [80, 70000]})
    assert isinstance(resp, dict)
    assert resp.get("ok") is False


@pytest.mark.asyncio
async def test_invalid_ip_response_is_dict(minimal_daemon):
    resp = await minimal_daemon._process_command({"action": "allow_many", "ports": [80], "ip": "not-an-ip"})
    assert isinstance(resp, dict)
    assert resp.get("ok") is False
    assert "invalid ip" in resp.get("error", "")


@pytest.mark.asyncio
async def test_block_invalid_ports_response_is_dict(minimal_daemon):
    resp = await minimal_daemon._process_command({"action": "block_many", "ports": [70000]})
    assert isinstance(resp, dict)
    assert resp.get("ok") is False


@pytest.mark.asyncio
async def test_unknown_action_response_is_dict(minimal_daemon):
    resp = await minimal_daemon._process_command({"action": "nope"})
    assert isinstance(resp, dict)
    assert resp.get("ok") is False
    assert "unknown action" in resp.get("error", "")


@pytest.mark.asyncio
async def test_handle_client_invalid_json_writes_dict(monkeypatch, minimal_daemon):
    writes = []

    class FakeWriter:
        def write(self, data):
            writes.append(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    class FakeReader:
        async def read(self, n):
            return b"not valid json"

    await minimal_daemon._handle_client(FakeReader(), FakeWriter())
    assert len(writes) == 1
    parsed = json.loads(writes[0].decode("utf-8"))
    assert isinstance(parsed, dict)
    assert parsed.get("ok") is False


@pytest.mark.asyncio
async def test_status_response_includes_config(minimal_daemon):
    """Status should expose the active configuration so users can audit it."""
    resp = await minimal_daemon._process_command({"action": "status"})
    assert isinstance(resp, dict)
    assert resp.get("ok") is True
    assert "config" in resp
    cfg = resp["config"]
    assert cfg["honeypot_start"] == 10000
    assert cfg["honeypot_end"] == 65535
    assert cfg["max_honeypots"] == 0
    assert cfg["firewall_backend"] == "auto"
    assert "iptables_chain" in cfg
    assert "log_dir" in cfg
