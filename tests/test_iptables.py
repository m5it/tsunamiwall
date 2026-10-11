import subprocess

import pytest

from tsunamiwall.config import Config
from tsunamiwall.iptables import build_rules, ensure_chain, flush_chain, reset, run_iptables


@pytest.fixture
def chain():
    return "TW-TEST"


def test_ensure_chain_creates(chain):
    # Best effort: only run if iptables is available.
    if not _iptables_available():
        pytest.skip("iptables not available")
    reset(chain)
    ensure_chain(chain)
    # Should not raise; calling twice should also be safe.
    ensure_chain(chain)


def _iptables_available() -> bool:
    try:
        subprocess.run(["iptables", "-L", "-n"], capture_output=True, check=True)
        return True
    except Exception:
        return False
