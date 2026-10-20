import os

import pytest

import sys
import types

import tsunamiwall.discovery as tsunamiwall_discovery_module
from tsunamiwall.discovery import (
    _hex_ip_port,
    _is_psutil_listener,
    _parse_proc_net_line,
    _read_proc_net,
    _read_proc_net_ipv6,
    discover_listeners,
    discover_ports,
    discover_with_psutil,
)


def _fake_psutil_module():
    """Return a minimal fake psutil module for unit tests."""
    mod = types.ModuleType("psutil")
    mod.CONN_LISTEN = "LISTEN"
    mod.CONN_NONE = "NONE"
    mod.CONN_ESTABLISHED = "ESTABLISHED"
    mod.CONN_CLOSE_WAIT = "CLOSE_WAIT"
    return mod


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
    local_field, remote_field, state = result
    assert state == 0x0A
    assert local_field == "0100007F:0016"
    assert remote_field == "00000000:0000"


def test_parse_proc_net_line_non_listen_tcp():
    line = "  0: 0100007F:0016 00000000:0000 01 00000000:00000000 ..."
    result = _parse_proc_net_line(line)
    assert result is not None
    assert result[2] == 0x01


def test_hex_ip_port_loopback_22():
    ip, port = _hex_ip_port("0100007F:0016")
    assert ip == "127.0.0.1"
    assert port == 22


def test_hex_ip_port_zero():
    ip, port = _hex_ip_port("00000000:0000")
    assert ip == "0.0.0.0"
    assert port == 0


def test_read_proc_net_udp_skips_connected_sockets(tmp_path, monkeypatch):
    """Connected UDP sockets (non-zero rem_address) must not be reported."""
    data = (
        "  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 12345\n"
        "   1: 00000000:1F91 0100007F:1234 07 00000000:00000000 00:00000000 00000000   100        0 12346\n"
    )
    path = tmp_path / "udp"
    path.write_text(data, encoding="utf-8")

    listeners = list(_read_proc_net(str(path), "udp"))
    ports = {l.port for l in listeners}
    assert ports == {8080}


def test_read_proc_net_udp_includes_bound_sockets(tmp_path, monkeypatch):
    """Bound UDP sockets with zero rem_address must be reported."""
    data = (
        "  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 12345\n"
    )
    path = tmp_path / "udp"
    path.write_text(data, encoding="utf-8")

    listeners = list(_read_proc_net(str(path), "udp"))
    assert len(listeners) == 1
    assert listeners[0].port == 8080
    assert listeners[0].proto == "udp"


def test_read_proc_net_tcp_still_requires_listen_state(tmp_path, monkeypatch):
    """TCP sockets in non-LISTEN states must be ignored."""
    data = (
        "  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"
        "   1: 0100007F:1234 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12346\n"
    )
    path = tmp_path / "tcp"
    path.write_text(data, encoding="utf-8")

    listeners = list(_read_proc_net(str(path), "tcp"))
    ports = {l.port for l in listeners}
    assert ports == {22}


def _make_fake_conn(proto_name, status, ip, port):
    """Return a fake psutil connection object."""
    LaddrType = type("Laddr", (), {"ip": ip, "port": port})
    SockType = type("SockType", (), {"name": proto_name})
    return type("FakeConn", (), {"type": SockType(), "status": status, "laddr": LaddrType()})()


def test_discover_with_psutil_includes_udp_conn_none(monkeypatch):
    """UDP sockets reported as CONN_NONE by psutil must be discovered."""
    psutil = _fake_psutil_module()
    sys.modules["psutil"] = psutil

    fake_conn = _make_fake_conn("SOCK_DGRAM", psutil.CONN_NONE, "0.0.0.0", 5353)
    psutil.net_connections = lambda kind: [fake_conn]

    listeners = discover_with_psutil()
    del sys.modules["psutil"]
    assert any(l.port == 5353 and l.proto == "udp" for l in listeners)


def test_discover_with_psutil_still_requires_listen_for_tcp(monkeypatch):
    """TCP sockets not in CONN_LISTEN must still be ignored by psutil fallback."""
    psutil = _fake_psutil_module()
    sys.modules["psutil"] = psutil

    fake_conn = _make_fake_conn("SOCK_STREAM", psutil.CONN_ESTABLISHED, "0.0.0.0", 12345)
    psutil.net_connections = lambda kind: [fake_conn]

    listeners = discover_with_psutil()
    del sys.modules["psutil"]
    assert not any(l.port == 12345 for l in listeners)


def test_is_psutil_listener_udp_with_local_address():
    """A UDP socket with a local address and CONN_NONE should be considered a listener."""
    psutil = _fake_psutil_module()
    sys.modules["psutil"] = psutil

    fake_conn = _make_fake_conn("SOCK_DGRAM", psutil.CONN_NONE, "0.0.0.0", 53)
    result = _is_psutil_listener(fake_conn)
    del sys.modules["psutil"]
    assert result is True


def test_is_psutil_listener_tcp_requires_listen():
    """A TCP socket not in LISTEN should not be considered a listener."""
    psutil = _fake_psutil_module()
    sys.modules["psutil"] = psutil

    fake_conn = _make_fake_conn("SOCK_STREAM", psutil.CONN_ESTABLISHED, "0.0.0.0", 443)
    result = _is_psutil_listener(fake_conn)
    del sys.modules["psutil"]
    assert result is False


def test_read_proc_net_tcp6_parses_ipv6_listener(tmp_path, monkeypatch):
    """_read_proc_net_ipv6 should parse a listening IPv6 TCP socket."""
    data = """  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 00000000000000000000000001000000:0051 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12346
"""
    path = tmp_path / "tcp6"
    path.write_text(data, encoding="utf-8")

    listeners = list(_read_proc_net_ipv6(str(path), "tcp"))
    assert len(listeners) == 1
    assert listeners[0].port == 80
    assert listeners[0].local_ip == "::"
    assert listeners[0].proto == "tcp"


def test_read_proc_net_udp6_skips_connected_sockets(tmp_path, monkeypatch):
    """_read_proc_net_ipv6 should skip connected UDP6 sockets."""
    data = """  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 12345
   1: 00000000000000000000000000000000:1F91 00000000000000000000000001000000:1234 07 00000000:00000000 00:00000000 00000000   100        0 12346
"""
    path = tmp_path / "udp6"
    path.write_text(data, encoding="utf-8")

    listeners = list(_read_proc_net_ipv6(str(path), "udp"))
    ports = {l.port for l in listeners}
    assert ports == {8080}


def test_discover_listeners_includes_ipv6_when_requested(monkeypatch, tmp_path):
    """When include_ipv6 is true, IPv6 listeners from /proc/net should be included."""
    proc_dir = tmp_path / "proc_net"
    proc_dir.mkdir()
    tcp4 = proc_dir / "tcp"
    tcp4.write_text(
        """  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1
""",
        encoding="utf-8",
    )
    tcp6 = proc_dir / "tcp6"
    tcp6.write_text(
        """  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2
""",
        encoding="utf-8",
    )
    udp4 = proc_dir / "udp"
    udp4.write_text(
        """  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
""",
        encoding="utf-8",
    )
    udp6 = proc_dir / "udp6"
    udp6.write_text(
        """  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
""",
        encoding="utf-8",
    )

    # Map the exact /proc/net paths to our fake files so the real helpers read them.
    mapping = {
        "/proc/net/tcp": str(tcp4),
        "/proc/net/tcp6": str(tcp6),
        "/proc/net/udp": str(udp4),
        "/proc/net/udp6": str(udp6),
    }

    def exists(path):
        return path in mapping

    monkeypatch.setattr("os.path.exists", exists)

    import builtins

    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path in mapping:
            path = mapping[path]
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    listeners = discover_listeners(include_tcp=True, include_udp=True, include_ipv6=True)
    ports = {l.port for l in listeners}
    assert ports == {80, 443}
    assert any(l.local_ip == "::" and l.port == 443 for l in listeners)

