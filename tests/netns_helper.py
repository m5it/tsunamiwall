"""Helpers for running code inside an isolated Linux network namespace."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


def netns_available() -> bool:
    """Return True if this process can create a network namespace.

    Root can always create network namespaces. Unprivileged processes may be
    able to create user+network namespaces when the kernel allows it.
    """
    if os.geteuid() == 0:
        return True
    try:
        subprocess.run(
            ["unshare", "-r", "-n", "true"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception:
        return False


def run_in_netns(code: str, *, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run Python *code* inside a fresh network namespace.

    The code runs with the same Python interpreter as the test process and with
    the project root on ``PYTHONPATH``. If the calling process is root, only a
    network namespace is unshared; otherwise an unprivileged user namespace is
    also created and mapped to root.
    """
    if not netns_available():
        raise RuntimeError("Network namespaces are not available on this host")

    script = textwrap.dedent(code)
    project_root = str(Path(__file__).resolve().parent.parent)

    env = os.environ.copy()
    env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

    if os.geteuid() == 0:
        cmd = ["unshare", "-n", sys.executable, "-c", script]
    else:
        cmd = ["unshare", "-r", "-n", sys.executable, "-c", script]

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def setup_loopback() -> None:
    """Bring the loopback interface up inside the current network namespace."""
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
