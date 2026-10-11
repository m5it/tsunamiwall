import os
import tempfile

from tsunamiwall.cli import _read_ports_file


def test_read_ports_file_ignores_blank_and_comments():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
        fh.write("# comment\n")
        fh.write("22\n")
        fh.write("\n")
        fh.write("  443 \n")
        fh.write("8080\n")
        path = fh.name
    try:
        assert _read_ports_file(path) == [22, 443, 8080]
    finally:
        os.remove(path)
