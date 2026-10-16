"""Firewall backend abstraction for TsunamiWall.

Provides a common interface for Linux iptables and macOS pfctl, plus a no-op
backend for testing or unsupported platforms.
"""

from __future__ import annotations

import abc
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from .config import Config
from .ip6tables import build_rules as _build_rules_ipv6, reset as _reset_ipv6
from .iptables import IptablesError, build_rules as _build_rules, reset as _reset

logger = logging.getLogger("tsunamiwall.firewall")


class FirewallBackend(abc.ABC):
    """Abstract firewall rule backend."""

    @abc.abstractmethod
    def build_rules(
        self,
        chain: str,
        allowed_ports: Iterable[int],
        honeypot_ports: Iterable[int],
        *,
        trusted_ips: Iterable[str] | None = None,
        allowed_per_ip: dict[str, Iterable[int]] | None = None,
        blocked_ports: Iterable[int] | None = None,
        log_rate_limit: int = 10,
        log_rate_burst: int = 20,
        family: str = "ipv4",
    ) -> None:
        """Rebuild the ruleset for the given address family."""

    @abc.abstractmethod
    def reset(self, chain: str, family: str = "ipv4") -> None:
        """Remove all TsunamiWall-managed rules for the given family."""

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if the required command-line tool is present."""


class NoopBackend(FirewallBackend):
    """Backend that does nothing."""

    def build_rules(
        self,
        chain: str,
        allowed_ports: Iterable[int],
        honeypot_ports: Iterable[int],
        *,
        trusted_ips: Iterable[str] | None = None,
        allowed_per_ip: dict[str, Iterable[int]] | None = None,
        blocked_ports: Iterable[int] | None = None,
        log_rate_limit: int = 10,
        log_rate_burst: int = 20,
        family: str = "ipv4",
    ) -> None:
        logger.info("No-op backend: skipping firewall rule update")

    def reset(self, chain: str, family: str = "ipv4") -> None:
        logger.info("No-op backend: skipping firewall reset")

    def is_available(self) -> bool:
        return True


class IptablesBackend(FirewallBackend):
    """Linux iptables backend for IPv4 or IPv6."""

    def __init__(self, *, command: str = "iptables"):
        self.command = command

    def _run(self, *args: str) -> None:
        cmd = [self.command, "-w", "5"] + list(args)
        logger.debug("Running: %s", " ".join(shlex.quote(a) for a in cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise IptablesError(f"{self.command} failed ({result.returncode}): {result.stderr.strip()}")

    def build_rules(
        self,
        chain: str,
        allowed_ports: Iterable[int],
        honeypot_ports: Iterable[int],
        *,
        trusted_ips: Iterable[str] | None = None,
        allowed_per_ip: dict[str, Iterable[int]] | None = None,
        blocked_ports: Iterable[int] | None = None,
        log_rate_limit: int = 10,
        log_rate_burst: int = 20,
        family: str = "ipv4",
    ) -> None:
        if self.command == "ip6tables":
            _build_rules_ipv6(
                chain,
                allowed_ports,
                honeypot_ports,
                trusted_ips=trusted_ips,
                allowed_per_ip=allowed_per_ip,
                blocked_ports=blocked_ports,
                log_rate_limit=log_rate_limit,
                log_rate_burst=log_rate_burst,
            )
            return

        _build_rules(
            chain,
            allowed_ports,
            honeypot_ports,
            trusted_ips=trusted_ips,
            allowed_per_ip=allowed_per_ip,
            blocked_ports=blocked_ports,
            log_rate_limit=log_rate_limit,
            log_rate_burst=log_rate_burst,
        )

    def reset(self, chain: str, family: str = "ipv4") -> None:
        if self.command == "ip6tables":
            _reset_ipv6(chain)
            return
        _reset(chain)

    def is_available(self) -> bool:
        return shutil.which(self.command) is not None


class PfctlBackend(FirewallBackend):
    """macOS pfctl backend using anchors.

    The user must add the base anchor to /etc/pf.conf once:

        anchor "tsunamiwall/*"

    and then load the main ruleset with `sudo pfctl -f /etc/pf.conf`.
    TsunamiWall only manages the contents of the sub-anchors.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _anchor(self, family: str) -> str:
        return f"{self.cfg.pfctl_anchor}/{family}"

    def _run(self, *args: str) -> None:
        cmd = ["pfctl"] + list(args)
        logger.debug("Running: %s", " ".join(shlex.quote(a) for a in cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise PfctlError(f"pfctl failed ({result.returncode}): {result.stderr.strip()}")

    def build_rules(
        self,
        chain: str,
        allowed_ports: Iterable[int],
        honeypot_ports: Iterable[int],
        *,
        trusted_ips: Iterable[str] | None = None,
        allowed_per_ip: dict[str, Iterable[int]] | None = None,
        blocked_ports: Iterable[int] | None = None,
        log_rate_limit: int = 10,
        log_rate_burst: int = 20,
        family: str = "ipv4",
    ) -> None:
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

        anchor = self._anchor(family)
        lines: list[str] = []
        af = "inet" if family == "ipv4" else "inet6"

        # Skip loopback; established state is handled by pf keep state.
        for ip in trusted:
            lines.append(f"pass in quick {af} from {ip} to any keep state")
        for ip, ports in per_ip.items():
            for port in sorted(ports):
                lines.append(f"pass in quick {af} proto tcp from {ip} to any port {port}")
                lines.append(f"pass in quick {af} proto udp from {ip} to any port {port}")
        for port in allowed:
            lines.append(f"pass in quick {af} proto tcp from any to any port {port}")
            lines.append(f"pass in quick {af} proto udp from any to any port {port}")
        for port in honeypots:
            lines.append(f"pass in quick {af} proto tcp from any to any port {port}")
        for port in blocked_sorted:
            lines.append(f"block drop in log quick {af} proto tcp from any to any port {port}")
            lines.append(f"block drop in log quick {af} proto udp from any to any port {port}")
        lines.append(f"block drop in log quick {af} from any to any")

        # Write rules to a temp file and atomically load into the anchor.
        fd, path = tempfile.mkstemp(prefix="tsunamiwall-pfctl-", suffix=".conf")
        path_obj = Path(path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            self._run("-a", anchor, "-f", str(path_obj))
            logger.info("Loaded pfctl rules into anchor %s", anchor)
        finally:
            try:
                path_obj.unlink()
            except FileNotFoundError:
                pass

    def reset(self, chain: str, family: str = "ipv4") -> None:
        anchor = self._anchor(family)
        try:
            self._run("-a", anchor, "-F", "rules")
            logger.info("Flushed pfctl anchor %s", anchor)
        except PfctlError:
            logger.warning("Could not flush pfctl anchor %s; it may not exist", anchor)

    def is_available(self) -> bool:
        return shutil.which("pfctl") is not None


class PfctlError(Exception):
    """Raised when a pfctl command fails unexpectedly."""


def detect_backend_name() -> str:
    """Return the default backend name for the current platform."""
    if sys.platform == "darwin":
        return "pfctl"
    return "iptables"


def get_backend(cfg: Config, family: str = "ipv4") -> FirewallBackend:
    """Return a firewall backend instance for the configured platform and family."""
    requested = cfg.firewall_backend
    if requested == "auto":
        backend_name = detect_backend_name()
    else:
        backend_name = requested

    if backend_name == "noop":
        return NoopBackend()
    if backend_name == "pfctl":
        return PfctlBackend(cfg)
    if backend_name == "iptables":
        return IptablesBackend(command="iptables" if family == "ipv4" else "ip6tables")
    if backend_name == "ip6tables":
        return IptablesBackend(command="ip6tables")

    # Fallback: try to detect at runtime.
    backend_name = detect_backend_name()
    if backend_name == "pfctl":
        return PfctlBackend(cfg)
    return IptablesBackend(command="iptables" if family == "ipv4" else "ip6tables")
