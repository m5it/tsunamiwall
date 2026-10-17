import pytest

from tsunamiwall.daemon import Daemon
from tsunamiwall.config import Config


@pytest.mark.asyncio
async def test_per_ip_port_not_auto_allowed_globally(monkeypatch, tmp_path, fake_firewall):
    """If a port is allowed only for a specific IP, discovery should not create a global allow rule."""
    cfg = Config(
        run_dir=str(tmp_path / "run"),
        log_dir=str(tmp_path / "logs"),
        payload_log_dir=str(tmp_path / "payloads"),
    )

    monkeypatch.setattr("tsunamiwall.daemon.discover_ports", lambda **kwargs: {7983, 22})
    monkeypatch.setattr("tsunamiwall.daemon.safe_ports", lambda used, cfg: set())

    daemon = Daemon(cfg)
    daemon.allowed_per_ip = {"2.139.221.31": {7983}}

    await daemon._reconcile()

    build_calls = [c for c in fake_firewall if c[0] == "build" and c[1] == "ipv4"]
    allowed = build_calls[-1][3]

    # Port 7983 is only in allowed_per_ip, not globally allowed.
    assert 7983 not in allowed
    # Port 22 has a listener but no per-IP rule, so it is auto-allowed globally.
    assert 22 in allowed
