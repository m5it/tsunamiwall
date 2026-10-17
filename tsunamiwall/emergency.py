"""Standalone emergency reset tool for TsunamiWall."""

import logging
import os
import signal
import sys
import time
from pathlib import Path

from .config import default_config
from .firewall import get_backend

logger = logging.getLogger("tsunamiwall.emergency")


def stop_daemon_if_running(cfg=None) -> None:
    """Send SIGTERM to the daemon if its PID file exists and points to a live process."""
    cfg = cfg or default_config()
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


def emergency_reset(cfg=None) -> None:
    """Stop the daemon and flush all TsunamiWall iptables rules."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if os.geteuid() != 0:
        logger.error("Emergency reset must be run as root")
        sys.exit(1)

    cfg = cfg or default_config()
    stop_daemon_if_running(cfg)

    # Wait briefly for the daemon to terminate so iptables rules are not rewritten.
    time.sleep(1.0)

    backend = get_backend(cfg, family="ipv4")
    backend.reset(cfg.iptables_chain, family="ipv4")
    if cfg.enable_ipv6:
        backend_ipv6 = get_backend(cfg, family="ipv6")
        try:
            backend_ipv6.reset(cfg.ipv6_chain, family="ipv6")
        except Exception:
            logger.exception("IPv6 emergency reset failed")

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
