"""Shared test fixtures for TsunamiWall."""

import pytest

from tsunamiwall.firewall import FirewallBackend


class _FakeBackend(FirewallBackend):
    """Record-only firewall backend for unit tests."""

    def __init__(self, family: str, calls: list):
        self.family = family
        self.calls = calls

    def build_rules(
        self,
        chain: str,
        allowed_ports: set,
        honeypot_ports: set,
        *,
        trusted_ips=None,
        allowed_per_ip=None,
        blocked_ports=None,
        log_rate_limit: int = 10,
        log_rate_burst: int = 20,
        family: str = "ipv4",
    ) -> None:
        self.calls.append(
            (
                "build",
                family,
                chain,
                set(allowed_ports),
                set(honeypot_ports),
                set(blocked_ports or ()),
                allowed_per_ip,
            )
        )

    def reset(self, chain: str, family: str = "ipv4") -> None:
        self.calls.append(("reset", family, chain))

    def is_available(self) -> bool:
        return True


@pytest.fixture
def fake_firewall(monkeypatch):
    """Patch the firewall backend factory to return record-only fakes.

    Yields a shared call log that records every build_rules and reset call
    made by any fake backend created during the test.
    """
    calls: list = []

    def factory(cfg, family: str = "ipv4"):
        return _FakeBackend(family, calls)

    monkeypatch.setattr("tsunamiwall.daemon.get_backend", factory)
    monkeypatch.setattr("tsunamiwall.emergency.get_backend", factory)
    return calls
