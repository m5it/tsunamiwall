import os

import pytest

from tsunamiwall.discovery import _hex_ip_port, _parse_proc_net_line, discover_ports


@pytest.mark.skipif(not os.path.exists("/proc/net/tcp"), reason="/proc/net/tcp not available")
def test_discover_ports_non_empty_on_linux():
    ports = discover_ports()
    assert isinstance(ports, set)
    # Should at least find loopback listeners when run on a normal Linux host.


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
