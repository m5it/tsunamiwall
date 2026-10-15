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
