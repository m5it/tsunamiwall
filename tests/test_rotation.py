import tempfile
from pathlib import Path

from tsunamiwall.config import Config
from tsunamiwall.rotation import cleanup_payloads, rotate_hit_log


def test_rotate_hit_log_when_over_max_bytes():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "hits.logl"
        log_path.write_text("x" * 2000, encoding="utf-8")

        rotated = rotate_hit_log(str(log_path), max_bytes=1000, max_backups=3)
        assert rotated is not None
        assert rotated.exists()
        assert log_path.exists()
        assert log_path.read_text(encoding="utf-8") == ""


def test_no_rotation_when_under_max_bytes():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "hits.logl"
        log_path.write_text("small", encoding="utf-8")

        rotated = rotate_hit_log(str(log_path), max_bytes=1000, max_backups=3)
        assert rotated is None


def test_rotation_shifts_backups():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "hits.logl"
        log_path.write_text("x" * 2000, encoding="utf-8")
        (Path(tmpdir) / "hits.logl.1").write_text("old1", encoding="utf-8")
        (Path(tmpdir) / "hits.logl.2").write_text("old2", encoding="utf-8")

        rotate_hit_log(str(log_path), max_bytes=1000, max_backups=3)

        assert log_path.read_text(encoding="utf-8") == ""
        assert (Path(tmpdir) / "hits.logl.1").read_text(encoding="utf-8") == "x" * 2000
        assert (Path(tmpdir) / "hits.logl.2").read_text(encoding="utf-8") == "old1"
        assert (Path(tmpdir) / "hits.logl.3").read_text(encoding="utf-8") == "old2"


def test_cleanup_payloads_removes_oldest_first():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        old = base / "US" / "1.2.3.4" / "old.bin"
        new = base / "US" / "1.2.3.4" / "new.bin"
        old.parent.mkdir(parents=True)
        old.write_bytes(b"old" * 100)
        new.write_bytes(b"new" * 100)

        # Make old visibly older.
        import os
        import time

        now = time.time()
        os.utime(str(old), (now - 100, now - 100))
        os.utime(str(new), (now, now))

        cleanup_payloads(str(base), max_bytes=len("new" * 100) + 10)

        assert not old.exists(), "oldest payload should be removed first"
        assert new.exists(), "newest payload should be retained"


def test_cleanup_payloads_leaves_metadata():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        payload = base / "US" / "1.2.3.4" / "probe.bin"
        meta = base / "US" / "1.2.3.4" / "sessions.logl"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"x" * 1000)
        meta.write_text('{"time":"now"}\n', encoding="utf-8")

        cleanup_payloads(str(base), max_bytes=100)

        assert not payload.exists()
        assert meta.exists(), "metadata file should survive payload cleanup"
