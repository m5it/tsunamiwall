"""Safe wrapper around iptables for TsunamiWall-managed rules."""

from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Iterable

logger = logging.getLogger("tsunamiwall.iptables")


class IptablesError(Exception):
    """Raised when an iptables command fails unexpectedly."""


def run_iptables(*args: str, quiet: bool = False) -> None:
    """Run iptables with the given arguments, raising on error.

    Set *quiet=True* for best-effort cleanup commands whose failure is expected
    and handled by the caller (e.g. deleting a rule that may not exist).
    """
    cmd = ["iptables", "-w", "5"] + list(args)
    logger.debug("Running: %s", " ".join(shlex.quote(a) for a in cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as exc:
        msg = f"iptables command timed out after 10s: {' '.join(shlex.quote(a) for a in cmd)}"
        logger.error(msg)
        raise IptablesError(msg) from exc
    if result.returncode != 0:
        msg = f"iptables failed ({result.returncode}): {result.stderr.strip()}"
        if not quiet:
            logger.error(msg)
        raise IptablesError(msg)


def _chain_exists(chain: str) -> bool:
    """Return True if the given custom chain already exists."""
    cmd = ["iptables", "-w", "10", "-n", "-L", chain]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def ensure_chain(chain: str) -> None:
    """Create the chain if it does not exist."""
    if not _chain_exists(chain):
        run_iptables("-N", chain)


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


def _install_jump_if_missing(chain: str) -> None:
    """Add the TsunamiWall chain jump to INPUT at the top if not already present."""
    cmd = ["iptables", "-w", "10", "-n", "-L", "INPUT"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and f"-j {chain}" in result.stdout:
        return
    run_iptables("-I", "INPUT", "1", "-j", chain)


def _remove_jump(chain: str) -> None:
    """Remove any jump to *chain* from INPUT without failing if absent."""
    try:
        run_iptables("-D", "INPUT", "-j", chain, quiet=True)
    except IptablesError:
        pass


def _rename_chain(old: str, new: str) -> None:
    """Rename a user-defined chain; iptables updates all references automatically."""
    run_iptables("-E", old, new)


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
    """Atomically rebuild the TsunamiWall chain using a shadow chain.

    Rules (in order):
      1. Allow trusted source IPs/CIDRs.
      2. Allow loopback.
      3. Allow established/related.
      4. Explicitly blocked ports (TCP+UDP) — dropped before any allow rules.
      5. Allow per-source-IP/CIDR ports.
      6. Allow explicit real-service ports globally.
      7. Allow honeypot ports.
      8. Log and drop everything else.

    The active chain is never flushed-empty during the update. Instead, a fresh
    shadow chain is populated and then swapped in. The INPUT jump is moved by
    inserting the shadow jump first and removing the old jump second, so packets
    never pass through a gap with no target. The chains are then renamed so the
    active ruleset keeps the configured name. If any command fails, the previous
    ruleset is restored under the configured chain name.
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

    # Prepare a clean shadow chain.
    try:
        if _chain_exists(shadow):
            flush_chain(shadow)
        else:
            run_iptables("-N", shadow)
    except IptablesError:
        logger.exception("Failed to prepare shadow chain %s", shadow)
        raise

    # Build the new ruleset in the shadow chain.
    try:
        # 1. Trusted IPs/CIDRs always bypass the firewall.
        for ip in trusted:
            run_iptables("-A", shadow, "-s", ip, "-j", "ACCEPT")
        # 2. Loopback
        run_iptables("-A", shadow, "-i", "lo", "-j", "ACCEPT")
        # 3. Existing connections
        run_iptables("-A", shadow, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        # 4. Explicitly blocked ports (TCP+UDP) — logged and dropped even if a service listens.
        for port in blocked_sorted:
            run_iptables(
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
            run_iptables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "DROP")
            run_iptables(
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
            run_iptables("-A", shadow, "-p", "udp", "--dport", str(port), "-j", "DROP")
        # 5. Per-source-IP/CIDR allowed ports (TCP+UDP)
        for ip in sorted(per_ip):
            for port in sorted(per_ip[ip]):
                run_iptables("-A", shadow, "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
                run_iptables("-A", shadow, "-s", ip, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        # 6. Real services (TCP+UDP)
        for port in allowed:
            run_iptables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
            run_iptables("-A", shadow, "-p", "udp", "--dport", str(port), "-j", "ACCEPT")
        # 7. Honeypot ports (TCP only in v1)
        for port in honeypots:
            run_iptables("-A", shadow, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
        # 8. Default drop with logging (rate-limited to avoid flooding dmesg)
        run_iptables(
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
        run_iptables("-A", shadow, "-j", "DROP")
    except IptablesError:
        logger.exception("Failed to populate shadow chain %s; leaving existing rules in place", shadow)
        # Make sure no jump points at the incomplete shadow chain.
        _remove_jump(shadow)
        try:
            flush_chain(shadow)
        except IptablesError:
            pass
        # Ensure the original chain is still jumped to by name.
        _install_jump_if_missing(chain)
        raise

    # Atomic swap: activate the shadow ruleset without ever leaving INPUT
    # without a target. We insert the shadow jump first, then remove the old
    # one (brief overlap where both exist, but shadow is active). Finally we
    # rename the chains so the active chain keeps the configured name and the
    # old chain becomes chain_OLD for cleanup.
    old = f"{chain}_OLD"
    try:
        if _chain_exists(old):
            flush_chain(old)
            run_iptables("-X", old)
        _install_jump_if_missing(shadow)
        _remove_jump(chain)
        _rename_chain(chain, old)
        _rename_chain(shadow, chain)
    except IptablesError:
        logger.exception("Atomic chain swap failed for %s", chain)
        # Best-effort rollback: revert INPUT to the previous ruleset under the
        # configured chain name. The order matters: restore the name, install a
        # jump to it at the top, then strip the temporary shadow jump.
        try:
            if _chain_exists(old) and not _chain_exists(chain):
                # Old ruleset was moved to chain_OLD and shadow->chain failed.
                # Bring the old ruleset back to the configured name.
                _rename_chain(old, chain)
            # Ensure INPUT jumps to the chain named {chain} (old/previous rules).
            _install_jump_if_missing(chain)
            # Drop any remaining shadow jump so the next rebuild starts clean.
            _remove_jump(shadow)
        except IptablesError as rollback_exc:
            logger.critical("Rollback after swap failure also failed: %s", rollback_exc)
        raise

    # Clean up the old chain and any stale jump to it.
    try:
        _remove_jump(old)
        if _chain_exists(old):
            flush_chain(old)
            run_iptables("-X", old)
    except IptablesError:
        logger.warning("Could not clean up old chain %s; leaving it in place", old)


def reset(chain: str) -> None:
    """Remove all TsunamiWall rules and leave the chain empty/deleted."""
    try:
        delete_chain(chain)
    except IptablesError as exc:
        logger.warning("Reset encountered error but continuing: %s", exc)
