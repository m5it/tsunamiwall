import os

import pytest

from tsunamiwall.discovery import (
    _hex_ip_port,
    _parse_proc_net_line,
    discover_listeners,
    discover_ports,
    discover_with_psutil,
)


@pytest.mark.skipif(not os.path.exists("/proc/net/tcp"), reason="/proc/net/tcp not available")
def test_discover_ports_non_empty_on_linux():
    ports = discover_ports()
    assert isinstance(ports, set)
    # Should at least find loopback listeners when run on a normal Linux host.


def test_discover_listeners_falls_back_to_psutil_on_macos(monkeypatch):
    """When /proc/net is missing, discovery should fall back to psutil."""
    monkeypatch.setattr("os.path.exists", lambda path: False if path == "/proc/net/tcp" else True)

    called = {"psutil": False}

    def fake_psutil():
        called["psutil"] = True
        return set()

    monkeypatch.setattr("tsunamiwall.discovery.discover_with_psutil", fake_psutil)
    discover_listeners()
    assert called["psutil"], "discover_listeners should use psutil when /proc/net/tcp is absent"


def test_discover_ports_prefers_proc_net_when_available(monkeypatch):
    """When /proc/net exists, discovery should not call psutil for IPv4."""
    monkeypatch.setattr("os.path.exists", lambda path: path == "/proc/net/tcp")

    called = {"psutil": False}

    def fake_psutil():
        called["psutil"] = True
        return set()

    monkeypatch.setattr("tsunamiwall.discovery.discover_with_psutil", fake_psutil)
    discover_listeners()
    assert not called["psutil"], "discover_listeners should prefer /proc/net when available"


def test_parse_proc_net_line_valid_tcp_listen():
    line = "  0: 0100007F:0016 00000000:0000 0A 00000000:00000000 ..."
    result = _parse_proc_net_line(line)
    assert result is not None
    addr_field, state = result
    assert state == 0x0A
    assert addr_field == "0100007F:0016"


def test_parse_proc_net_line_non_listen_tcp():
    line = "  0: 0100007F:0016 00000000:0000 01 00000000:00000000 ..."
    result = _parse_proc_net_line(line)
    assert result is not None
    assert result[1] == 0x01


def test_hex_ip_port_loopback_22():
    ip, port = _hex_ip_port("0100007F:0016")
    assert ip == "127.0.0.1"
    assert port == 22


def test_hex_ip_port_zero():
    ip, port = _hex_ip_port("00000000:0000")
    assert ip == "0.0.0.0"
    assert port == 0
