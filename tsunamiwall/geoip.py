"""Offline country-code lookup for honeypot source IPs.

Uses `iptocc` if installed, otherwise falls back to "UNKNOWN".
Install the optional dependency with:

    pip install iptocc
"""

from __future__ import annotations

import logging

logger = logging.getLogger("tsunamiwall.geoip")


def country_code(ip: str) -> str:
    """Return ISO country code for an IP, or 'UNKNOWN' if lookup fails."""
    try:
        # iptocc is an optional dependency.
        from iptocc import country_code as _iptocc_cc  # type: ignore[import]

        result = _iptocc_cc(ip)
        # iptocc may return None for private/unspecified ranges.
        return result if isinstance(result, str) else "UNKNOWN"
    except Exception as exc:
        logger.debug("Country lookup failed for %s: %s", ip, exc)
        return "UNKNOWN"


def sanitize_ip(ip: str) -> str:
    """Return a filesystem-safe representation of an IP address."""
    # IPv6 colons are not safe in all filesystems; replace them.
    return ip.replace(":", "_")
