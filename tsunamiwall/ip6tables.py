"""Safe wrapper around ip6tables for TsunamiWall-managed rules."""

from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Iterable

logger = logging.getLogger("tsunamiwall.ip6tables")


class Ip6tablesError(Exception):
    """Raised when an ip6tables command fails unexpectedly."""


def run_ip6tables(*args: str) -> None:
    """Run ip6tables with the given arguments, raising on error."""
    cmd = ["ip6tables", "-w", "5"] + list(args)
    logger.debug("Running: %s", " ".join(shlex.quote(a) for a in cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as exc:
        msg = f"ip6tables command timed out after 10s: {' '.join(shlex.quote(a) for a in cmd)}"
        logger.error(msg)
        raise Ip6tablesError(msg) from exc
    if result.returncode != 0:
        msg = f"ip6tables failed ({result.returncode}): {result.stderr.strip()}"
        logger.error(msg)
        raise Ip6tablesError(msg)


def _chain_exists(chain: str) -> bool:
    cmd = ["ip6tables", "-w", "10", "-n", "-L", chain]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def ensure_chain(chain: str) -> None:
    if not _chain_exists(chain):
        run_ip6tables("-N", chain)


def flush_chain(chain: str) -> None:
    run_ip6tables("-F", chain)


def _remove_jump(chain: str) -> None:
    try:
        run_ip6tables("-D", "INPUT", "-j", chain)
    except Ip6tablesError:
        pass


def _install_jump_if_missing(chain: str) -> None:
    cmd = ["ip6tables", "-w", "10", "-n", "-L", "INPUT"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and f"-j {chain}" in result.stdout:
        return
    run_ip6tables("-I", "INPUT", "1", "-j", chain)


def _rename_chain(old: str, new: str) -> None:
    """Rename a user-defined chain; ip6tables updates all references automatically."""
    run_ip6tables("-E", old, new)


def build_rules(
    chain: str,
    allowed_ports: Iterable[int],
    honeypot_ports: Iterable[int],
    trusted_ips: Iterable[str] | None = None,
    allowed_per_ip: dict[str, Iterable[int]] | None = None,
    blocked_ports: Iterable[int] | None = None,
    log_rate_limit: int = 10,
    log_rate_burst: int = 20,
) -> None:
    """Atomically rebuild the IPv6 TsunamiWall chain using a shadow chain.

    Mirrors the IPv4 policy in tsunamiwall/iptables.py but targets ip6tables.
    The active chain is never left without an INPUT target during the swap.
    """
    blocked = set(blocked_ports or ())
    allowed = sorted(set(allowed_ports) - blocked)
    honeypots = sorted(set(honeypot_ports) - blocked)
    blocked_sorted = sorted(blocked)
    trusted = sorted(set(trusted_ips or ()))
    per_ip: dict[str, set[int]] = {
        ip: set(ports) - blocked
        for ip, ports in (allowed_per_ip or {}).items()
        if ports
    }

    ensure_chain(chain)
    shadow = f"{chain}_NEW"

    try:
        if _chain_exists(shadow):
            flush_chain(shadow)
        else:
            run_ip6tables("-N", shadow)
    except Ip6tablesError:
        logger.exception("Failed to prepare IPv6 shadow chain %s", shadow)
        raise

    try:
        for ip in trusted:
            run_ip6tables("-A", shadow, "-s", ip, "-j", "ACCEPT")
        run_ip6tables("-A", shadow, "-i", "lo", "-j", "ACCEPT")
        run_ip6tables("-A", shadow, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        for port in blocked_sorted:
            run_ip6tables(
                "-A",
                shadow,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-m",
                "limit",
                "--limit",
                f"{log_rate_limit}/second",
                "--limit-burst",
                str(log_rate_burst),
                "-j",
                "LOG",
                "--log-prefix",
                "TSUNAMIWALL-BLOCK: ",
                "--log-level",
                "4",
            )
            run_ip6tables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "DROP")
            run_ip6tables(
                "-A",
                shadow,
                "-p",
                "udp",
                "--dport",
                str(port),
                "-m",
                "limit",
                "--limit",
                f"{log_rate_limit}/second",
                "--limit-burst",
                str(log_rate_burst),
                "-j",
                "LOG",
                "--log-prefix",
                "TSUNAMIWALL-BLOCK: ",
                "--log-level",
                "4",
            )
            run_ip6tables("-A", shadow, "-p", "udp", "--dport", str(port), "-j", "DROP")
        for ip in sorted(per_ip):
            for port in sorted(per_ip[ip]):
                run_ip6tables("-A", shadow, "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
                run_ip6tables("-A", shadow, "-s", ip, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        for port in allowed:
            run_ip6tables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
            run_ip6tables("-A", shadow, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        for port in honeypots:
            run_ip6tables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
        run_ip6tables(
            "-A",
            shadow,
            "-m",
            "limit",
            "--limit",
            f"{log_rate_limit}/second",
            "--limit-burst",
            str(log_rate_burst),
            "-j",
            "LOG",
            "--log-prefix",
            "TSUNAMIWALL-DROP: ",
            "--log-level",
            "4",
        )
        run_ip6tables("-A", shadow, "-j", "DROP")
    except Ip6tablesError:
        logger.exception("Failed to populate IPv6 shadow chain %s", shadow)
        _remove_jump(shadow)
        try:
            flush_chain(shadow)
        except Ip6tablesError:
            pass
        _install_jump_if_missing(chain)
        raise

    # Atomic swap: activate the shadow ruleset without ever leaving INPUT
    # without a target. See tsunamiwall/iptables.py for the full explanation.
    old = f"{chain}_OLD"
    try:
        if _chain_exists(old):
            flush_chain(old)
            run_ip6tables("-X", old)
        _install_jump_if_missing(shadow)
        _remove_jump(chain)
        _rename_chain(chain, old)
        _rename_chain(shadow, chain)
    except Ip6tablesError:
        logger.exception("Atomic IPv6 chain swap failed for %s", chain)
        try:
            if _chain_exists(old) and not _chain_exists(chain):
                _rename_chain(old, chain)
            _install_jump_if_missing(chain)
            _remove_jump(shadow)
        except Ip6tablesError as rollback_exc:
            logger.critical("Rollback after IPv6 swap failure also failed: %s", rollback_exc)
        raise

    try:
        _remove_jump(old)
        if _chain_exists(old):
            flush_chain(old)
            run_ip6tables("-X", old)
    except Ip6tablesError:
        logger.warning("Could not clean up IPv6 old chain %s; leaving it in place", old)


def reset(chain: str) -> None:
    """Remove all TsunamiWall IPv6 rules and leave the chain empty/deleted."""
    try:
        try:
            run_ip6tables("-D", "INPUT", "-j", chain)
        except Ip6tablesError:
            pass
        flush_chain(chain)
        try:
            run_ip6tables("-X", chain)
        except Ip6tablesError:
            pass
    except Ip6tablesError as exc:
        logger.warning("IPv6 reset encountered error but continuing: %s", exc)
