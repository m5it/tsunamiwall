"""Daemon-level integration tests inside isolated network namespaces.

These tests start a real TsunamiWall daemon in a network namespace and verify
that it installs and removes iptables rules, survives restart, and rolls back
partial firewall state when startup fails.
"""

from __future__ import annotations

import pytest

from tests.netns_helper import netns_available, run_in_netns


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_daemon_ipv4_startup_and_cleanup():
    """A daemon started in a netns installs IPv4 rules and removes them on stop."""
    code = '''
    import asyncio
    import os
    import subprocess
    import tempfile
    from tsunamiwall.config import Config
    from tsunamiwall.daemon import Daemon

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            run_dir=tmp,
            log_dir=os.path.join(tmp, "logs"),
            payload_log_dir=os.path.join(tmp, "payloads"),
            enable_ipv6=False,
            max_honeypots=0,
        )
        daemon = Daemon(cfg)

        async def run():
            task = asyncio.create_task(daemon.start())
            # Wait for the initial reconcile to write rules.
            await asyncio.sleep(1)

            result = subprocess.run(
                ["iptables", "-L", "TSUNAMIWALL", "-n"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert "TSUNAMIWALL" in result.stdout

            daemon._request_stop()
            await task

        asyncio.run(run())

        result = subprocess.run(
            ["iptables", "-L", "TSUNAMIWALL", "-n"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0 or "No chain" in result.stderr
        assert not os.path.exists(cfg.pid_path)
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns daemon test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_daemon_restart_reinstalls_rules():
    """Stopping and starting the daemon leaves the ruleset in place."""
    code = '''
    import asyncio
    import os
    import subprocess
    import tempfile
    from tsunamiwall.config import Config
    from tsunamiwall.daemon import Daemon

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            run_dir=tmp,
            log_dir=os.path.join(tmp, "logs"),
            payload_log_dir=os.path.join(tmp, "payloads"),
            enable_ipv6=False,
            max_honeypots=0,
        )

        async def cycle():
            daemon = Daemon(cfg)
            task = asyncio.create_task(daemon.start())
            await asyncio.sleep(1)
            daemon._request_stop()
            await task

            daemon2 = Daemon(cfg)
            task = asyncio.create_task(daemon2.start())
            await asyncio.sleep(1)

            result = subprocess.run(
                ["iptables", "-L", "TSUNAMIWALL", "-n"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert "TSUNAMIWALL" in result.stdout

            daemon2._request_stop()
            await task

        asyncio.run(cycle())
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns daemon restart test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_daemon_ipv6_startup_failure_rolls_back():
    """When IPv6 ruleset installation fails during startup, IPv4 rules are also reset."""
    code = '''
    import asyncio
    import os
    import subprocess
    import tempfile
    from tsunamiwall.config import Config
    from tsunamiwall.daemon import Daemon
    from tsunamiwall.firewall import IptablesBackend

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    real_build_rules = IptablesBackend.build_rules
    def failing_ipv6_build_rules(self, chain, allowed, honeypots, *, family, **kwargs):
        if family == "ipv6":
            raise RuntimeError("simulated IPv6 failure")
        return real_build_rules(self, chain, allowed, honeypots, family=family, **kwargs)
    IptablesBackend.build_rules = failing_ipv6_build_rules

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(
            run_dir=tmp,
            log_dir=os.path.join(tmp, "logs"),
            payload_log_dir=os.path.join(tmp, "payloads"),
            enable_ipv6=True,
            max_honeypots=0,
        )
        daemon = Daemon(cfg)

        async def run():
            try:
                await daemon.start()
            except RuntimeError as exc:
                assert "simulated IPv6 failure" in str(exc)

        asyncio.run(run())

        # Both IPv4 and IPv6 chains must have been reset during rollback.
        for binary, chain in [("iptables", "TSUNAMIWALL"), ("ip6tables", "TSUNAMIWALL6")]:
            result = subprocess.run(
                [binary, "-L", chain, "-n"],
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0 or "No chain" in result.stderr

        assert not os.path.exists(cfg.pid_path)
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns startup-failure test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
