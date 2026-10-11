"""Safe wrapper around iptables for TsunamiWall-managed rules."""

from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Iterable

logger = logging.getLogger("tsunamiwall.iptables")


class IptablesError(Exception):
    """Raised when an iptables command fails unexpectedly."""


def run_iptables(*args: str) -> None:
    """Run iptables with the given arguments, raising on error."""
    cmd = ["iptables", "-w", "10"] + list(args)
    logger.debug("Running: %s", " ".join(shlex.quote(a) for a in cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = f"iptables failed ({result.returncode}): {result.stderr.strip()}"
        logger.error(msg)
        raise IptablesError(msg)


def ensure_chain(chain: str) -> None:
    """Create the chain if it does not exist."""
    try:
        run_iptables("-N", chain)
    except IptablesError:
        # Chain likely already exists; ignore.
        pass


def flush_chain(chain: str) -> None:
    """Flush all rules in the given chain."""
    run_iptables("-F", chain)


def delete_chain(chain: str) -> None:
    """Remove the jump from INPUT and delete the chain."""
    try:
        run_iptables("-D", "INPUT", "-j", chain)
    except IptablesError:
        pass
    flush_chain(chain)
    try:
        run_iptables("-X", chain)
    except IptablesError:
        pass


def install_jump(chain: str) -> None:
    """Add the TsunamiWall chain jump to INPUT if not already present."""
    # Remove any stale jumps first to avoid duplicates, then add one at top.
    try:
        run_iptables("-D", "INPUT", "-j", chain)
    except IptablesError:
        pass
    run_iptables("-I", "INPUT", "1", "-j", chain)


def build_rules(
    chain: str,
    allowed_ports: Iterable[int],
    honeypot_ports: Iterable[int],
    trusted_ips: Iterable[str] | None = None,
) -> None:
    """Rebuild the TsunamiWall chain with the current policy.

    Rules (in order):
      1. Allow trusted source IPs/CIDRs.
      2. Allow loopback.
      3. Allow established/related.
      4. Allow explicit real-service ports.
      5. Allow honeypot ports.
      6. Log and drop everything else.
    """
    allowed = sorted(set(allowed_ports))
    honeypots = sorted(set(honeypot_ports))
    trusted = sorted(set(trusted_ips or ()))

    ensure_chain(chain)
    flush_chain(chain)

    # 1. Trusted IPs/CIDRs always bypass the firewall.
    for ip in trusted:
        run_iptables("-A", chain, "-s", ip, "-j", "ACCEPT")
    # 2. Loopback
    run_iptables("-A", chain, "-i", "lo", "-j", "ACCEPT")
    # 3. Existing connections
    run_iptables("-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    # 4. Real services (TCP+UDP)
    for port in allowed:
        run_iptables("-A", chain, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
        run_iptables("-A", chain, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
    # 5. Honeypot ports (TCP only in v1)
    for port in honeypots:
        run_iptables("-A", chain, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
    # 6. Default drop with logging
    run_iptables("-A", chain, "-j", "LOG", "--log-prefix", "TSUNAMIWALL-DROP: ", "--log-level", "4")
    run_iptables("-A", chain, "-j", "DROP")

    install_jump(chain)


def reset(chain: str) -> None:
    """Remove all TsunamiWall rules and leave the chain empty/deleted."""
    try:
        delete_chain(chain)
    except IptablesError as exc:
        logger.warning("Reset encountered error but continuing: %s", exc)
