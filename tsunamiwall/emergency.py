"""Standalone emergency reset tool for TsunamiWall."""

import logging
import os
import signal
import sys
import time
from pathlib import Path

from .config import default_config
from .iptables import reset

logger = logging.getLogger("tsunamiwall.emergency")


def stop_daemon_if_running() -> None:
    """Send SIGTERM to the daemon if its PID file exists and points to a live process."""
    cfg = default_config()
    pid_path = cfg.pid_path
    if not os.path.exists(pid_path):
        return
    try:
        pid = int(Path(pid_path).read_text(encoding="utf-8").strip())
    except ValueError:
        return
    try:
        os.kill(pid, signal.SIGTERM)
        logger.info("Sent SIGTERM to daemon process %d", pid)
    except ProcessLookupError:
        logger.warning("PID file exists but process %d is not running", pid)
    except PermissionError:
        logger.warning("Permission denied sending SIGTERM to process %d", pid)


def emergency_reset() -> None:
    """Stop the daemon and flush all TsunamiWall iptables rules."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if os.geteuid() != 0:
        logger.error("Emergency reset must be run as root")
        sys.exit(1)

    cfg = default_config()
    stop_daemon_if_running()

    # Wait briefly for the daemon to terminate so iptables rules are not rewritten.
    time.sleep(1.0)

    reset(cfg.iptables_chain)

    # Clean up runtime files.
    for path in (cfg.socket_path, cfg.pid_path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except PermissionError:
            logger.warning("Permission denied removing %s", path)

    logger.info("TsunamiWall emergency reset complete")


def main() -> int:
    emergency_reset()
    return 0


if __name__ == "__main__":
    sys.exit(main())
