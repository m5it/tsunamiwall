import re
import sys

import pytest

from tsunamiwall.cli import main


def test_version_flag_prints_version(monkeypatch, capsys):
    argv = ["--version"]
    monkeypatch.setattr(sys, "argv", ["tsunamiwall"] + argv)
    with pytest.raises(SystemExit) as exc_info:
        main(argv)
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert re.match(r"tsunamiwall \d+\.\d+\.\d+", captured.out)
