"""Network-namespace integration tests for the firewall backends.

These tests exercise real iptables/ip6tables in an isolated network namespace,
so they validate rule creation and cleanup beyond the mocked unit tests. They
are automatically skipped when the test runner cannot create network
namespaces (e.g. inside containers with restricted privileges).
"""

from __future__ import annotations

import pytest

from tests.netns_helper import netns_available, run_in_netns


@pytest.fixture
def netns():
    """Skip tests if network namespaces are not available."""
    if not netns_available():
        pytest.skip("Network namespaces are not available on this host")


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_iptables_builds_chain_with_allowed_ports(netns):
    """IPv4 rules are installed in a fresh network namespace."""
    code = '''
    import subprocess
    from tsunamiwall.firewall import IptablesBackend

    # Bring loopback up so iptables can reference the namespace.
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    backend = IptablesBackend(command="iptables")
    backend.build_rules(
        "TSUNAMIWALL",
        allowed_ports={22, 80, 443},
        honeypot_ports={30000, 30001},
        blocked_ports={1337},
        family="ipv4",
    )

    result = subprocess.run(
        ["iptables", "-L", "TSUNAMIWALL", "-n"],
        capture_output=True,
        text=True,
        check=True,
    )
    output = result.stdout

    assert "ACCEPT" in output
    assert "dpt:22" in output or "dpt:80" in output or "dpt:443" in output
    assert "dpt:30000" in output
    assert "dpt:1337" in output

    backend.reset("TSUNAMIWALL", family="ipv4")
    result = subprocess.run(
        ["iptables", "-L", "TSUNAMIWALL", "-n"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 or "No chain" in result.stderr
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_ip6tables_builds_chain_with_allowed_ports(netns):
    """IPv6 rules are installed in a fresh network namespace."""
    code = '''
    import subprocess
    from tsunamiwall.firewall import IptablesBackend

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    backend = IptablesBackend(command="ip6tables")
    backend.build_rules(
        "TSUNAMIWALL6",
        allowed_ports={22, 80, 443},
        honeypot_ports=set(),
        blocked_ports={1337},
        family="ipv6",
    )

    result = subprocess.run(
        ["ip6tables", "-L", "TSUNAMIWALL6", "-n"],
        capture_output=True,
        text=True,
        check=True,
    )
    output = result.stdout

    assert "ACCEPT" in output
    assert "dpt:22" in output or "dpt:80" in output or "dpt:443" in output
    assert "dpt:1337" in output

    backend.reset("TSUNAMIWALL6", family="ipv6")
    result = subprocess.run(
        ["ip6tables", "-L", "TSUNAMIWALL6", "-n"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 or "No chain" in result.stderr
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_iptables_drop_logs_everything_else(netns):
    """The IPv4 ruleset ends with a log+drop rule for unmatched traffic."""
    code = '''
    import subprocess
    from tsunamiwall.firewall import IptablesBackend

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    backend = IptablesBackend(command="iptables")
    backend.build_rules(
        "TSUNAMIWALL",
        allowed_ports={80},
        honeypot_ports=set(),
        family="ipv4",
    )

    result = subprocess.run(
        ["iptables", "-L", "TSUNAMIWALL", "-n"],
        capture_output=True,
        text=True,
        check=True,
    )
    output = result.stdout

    assert any(line.strip().startswith("LOG") for line in output.splitlines()), output
    assert "DROP" in output, output

    backend.reset("TSUNAMIWALL", family="ipv4")
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"


@pytest.mark.skipif(not netns_available(), reason="network namespaces unavailable")
def test_netns_ip6tables_no_duplicate_jump_after_reset(netns):
    """Reset cleans the jump rule so a second build does not duplicate it."""
    code = '''
    import subprocess
    from tsunamiwall.firewall import IptablesBackend

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)

    backend = IptablesBackend(command="ip6tables")
    backend.build_rules(
        "TSUNAMIWALL6",
        allowed_ports={80},
        honeypot_ports=set(),
        family="ipv6",
    )
    backend.reset("TSUNAMIWALL6", family="ipv6")
    backend.build_rules(
        "TSUNAMIWALL6",
        allowed_ports={443},
        honeypot_ports=set(),
        family="ipv6",
    )

    result = subprocess.run(
        ["ip6tables", "-L", "INPUT", "-n"],
        capture_output=True,
        text=True,
        check=True,
    )
    jumps = [line for line in result.stdout.splitlines() if "TSUNAMIWALL6" in line]
    assert len(jumps) == 1, f"Expected exactly one INPUT jump, found {len(jumps)}: {jumps}"

    backend.reset("TSUNAMIWALL6", family="ipv6")
    '''

    proc = run_in_netns(code)
    assert proc.returncode == 0, f"netns test failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
