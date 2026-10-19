import os
import tempfile
from pathlib import Path

from tsunamiwall.config import Config
from tsunamiwall.honeypot import PayloadSession, default_payload_writer


def test_payload_writer_creates_country_and_ip_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(
            payload_log_dir=tmpdir,
            log_dir=tmpdir,
            run_dir=tmpdir,
        )
        writer = default_payload_writer(cfg)
        session = PayloadSession(
            start_time="2026-10-12T01:00:00Z",
            src_ip="8.8.8.8",
            src_port=12345,
            dst_port=10348,
            country="UNKNOWN",
            payload=b"hello scanner",
        )
        writer(session)

        # Country should have been resolved; 8.8.8.8 is US.
        assert session.country == "US"
        ip_dir = Path(tmpdir) / "US" / "8.8.8.8"
        assert ip_dir.is_dir()
        meta_file = ip_dir / "sessions.logl"
        assert meta_file.exists()
        payload_files = list(ip_dir.glob("*.bin"))
        assert len(payload_files) == 1
        assert payload_files[0].read_bytes() == b"hello scanner"


def test_payload_writer_does_not_overwrite_same_second():
    """Multiple probes from the same IP to the same dst port in the same second
    must create separate payload files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(
            payload_log_dir=tmpdir,
            log_dir=tmpdir,
            run_dir=tmpdir,
        )
        writer = default_payload_writer(cfg)
        for i in range(3):
            writer(
                PayloadSession(
                    start_time="2026-10-12T01:00:00Z",
                    src_ip="8.8.8.8",
                    src_port=12345 + i,
                    dst_port=10348,
                    payload=b"probe",
                )
            )

        ip_dir = Path(tmpdir) / "US" / "8.8.8.8"
        payload_files = list(ip_dir.glob("*.bin"))
        assert len(payload_files) == 3


def test_payload_writer_skips_empty_payloads():
    """Timed-out or zero-byte probes should not create payload files or metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(
            payload_log_dir=tmpdir,
            log_dir=tmpdir,
            run_dir=tmpdir,
        )
        writer = default_payload_writer(cfg)
        writer(
            PayloadSession(
                start_time="2026-10-12T01:00:00Z",
                src_ip="8.8.8.8",
                src_port=12345,
                dst_port=10348,
                payload=b"",
            )
        )

        ip_dir = Path(tmpdir) / "US" / "8.8.8.8"
        assert not list(ip_dir.glob("*.bin")), "empty payload must not create a .bin file"
        assert not (ip_dir / "sessions.logl").exists(), "empty payload must not create metadata"



def test_payload_callback_does_not_invoke_cleanup(tmp_path, monkeypatch):
    """The per-hit payload callback must not run retention cleanup synchronously."""
    import asyncio
    from tsunamiwall.daemon import Daemon

    cfg = Config(
        payload_log_dir=str(tmp_path / "payloads"),
        log_dir=str(tmp_path / "logs"),
        run_dir=str(tmp_path / "run"),
        max_honeypots=0,
    )

    cleanup_called = []
    monkeypatch.setattr(
        "tsunamiwall.daemon.cleanup_payloads",
        lambda _log_dir, _max: cleanup_called.append(True),
    )

    daemon = Daemon(cfg)
    session = PayloadSession(
        start_time="2026-10-19T01:00:00Z",
        src_ip="8.8.8.8",
        src_port=12345,
        dst_port=10348,
        payload=b"probe",
    )
    daemon._payload_callback(session)

    assert not cleanup_called, "cleanup_payloads must not be called from the per-hit callback"

