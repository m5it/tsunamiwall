"""Command-line client for TsunamiWall daemon."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .config import Config, load_config
from .util import _format_hit_time


def _config(args: argparse.Namespace) -> Config:
    """Load config, honoring an explicit --config path if given."""
    return load_config(args.config if args.config else None)


def _send(args: argparse.Namespace, cmd: dict) -> dict:
    cfg = _config(args)
    if not os.path.exists(cfg.socket_path):
        print(f"Daemon socket not found at {cfg.socket_path}", file=sys.stderr)
        sys.exit(2)

    async def _talk() -> dict:
        reader, writer = await asyncio.open_unix_connection(cfg.socket_path)
        writer.write(json.dumps(cmd).encode("utf-8"))
        await writer.drain()
        writer.write_eof()
        data = await reader.read(8192)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        try:
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                return {"ok": False, "error": "bad response from daemon"}
            return parsed
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad response from daemon"}

    try:
        return asyncio.run(_talk())
    except (ConnectionRefusedError, FileNotFoundError) as exc:
        raise DaemonUnreachable(f"Cannot reach daemon at {cfg.socket_path}: {exc}") from exc


class DaemonUnreachable(Exception):
    """Raised when the CLI cannot connect to the daemon socket."""


def _print_response(resp: dict | str) -> int:
    if isinstance(resp, str):
        print(json.dumps({"ok": False, "error": resp}, indent=2))
        return 1
    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 1


def cmd_status(args: argparse.Namespace) -> int:
    return _print_response(_send(args, {"action": "status"}))


def _read_ports_file(path: str) -> list[int]:
    """Read a file containing one port number per line, ignoring blanks/comments."""
    ports: list[int] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ports.append(int(line))
    return ports


def _validate_ip(ip: str | None) -> str | None:
    if ip is None:
        return None
    import ipaddress

    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP/CIDR: {exc}") from exc
    return ip


def cmd_allow(args: argparse.Namespace) -> int:
    if args.file:
        ports = _read_ports_file(args.file)
    else:
        ports = [args.port]
    ip = _validate_ip(args.ip)
    return _print_response(_send(args, {"action": "allow_many", "ports": ports, "ip": ip}))


def cmd_deny(args: argparse.Namespace) -> int:
    if args.file:
        ports = _read_ports_file(args.file)
    else:
        ports = [args.port]
    ip = _validate_ip(args.ip)
    return _print_response(_send(args, {"action": "deny_many", "ports": ports, "ip": ip}))


def cmd_block(args: argparse.Namespace) -> int:
    if args.file:
        ports = _read_ports_file(args.file)
    else:
        ports = [args.port]
    return _print_response(_send(args, {"action": "block_many", "ports": ports}))


def cmd_unblock(args: argparse.Namespace) -> int:
    if args.file:
        ports = _read_ports_file(args.file)
    else:
        ports = [args.port]
    return _print_response(_send(args, {"action": "unblock_many", "ports": ports}))


def cmd_stop(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if not os.path.exists(cfg.socket_path):
        print("Daemon socket not found; daemon is not running.", file=sys.stderr)
        return 0
    try:
        return _print_response(_send(args, {"action": "stop"}))
    except DaemonUnreachable as exc:
        print(f"Daemon socket exists but daemon is not responding: {exc}", file=sys.stderr)
        # Best-effort cleanup of stale socket/PID files so the user can start fresh.
        try:
            os.remove(cfg.socket_path)
        except FileNotFoundError:
            pass
        if os.path.exists(cfg.pid_path):
            try:
                with open(cfg.pid_path, "r", encoding="utf-8") as fh:
                    pid = int(fh.read().strip())
                os.kill(pid, 0)  # raises if process is gone
                print(f"Daemon process {pid} appears stuck; you may need to kill it manually.", file=sys.stderr)
            except (ValueError, ProcessLookupError, PermissionError, FileNotFoundError):
                try:
                    os.remove(cfg.pid_path)
                except FileNotFoundError:
                    pass
        return 1


def cmd_reset(args: argparse.Namespace) -> int:
    cfg = _config(args)
    # If the daemon socket is missing or dead, perform a direct emergency reset
    # instead of failing with a connection error.
    socket_alive = os.path.exists(cfg.socket_path)
    if socket_alive:
        try:
            return _print_response(_send(args, {"action": "reset"}))
        except (ConnectionRefusedError, FileNotFoundError, DaemonUnreachable):
            print("Daemon socket exists but no daemon is listening; performing direct reset.", file=sys.stderr)

    from .emergency import emergency_reset

    try:
        emergency_reset(cfg)
    except Exception as exc:
        print(f"Emergency reset failed: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if not os.path.exists(cfg.hit_log_path):
        print("No honeypot logs yet.")
        return 0
    with open(cfg.hit_log_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    if not lines:
        print("No honeypot logs yet.")
        return 0

    print(f"{'TIME':20} {'FAMILY':6} {'SRC IP':20} {'CC':4} {'SPORT':6} {'DPORT':6} {'SIZE':5}")
    print("-" * 74)
    for line in lines[-50:]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("action") != "honeypot_hit":
            continue
        print(
            f"{_format_hit_time(obj.get('time', '')):20} "
            f"{obj.get('family', 'ipv4'):6} "
            f"{obj.get('src_ip', '?'):20} "
            f"{obj.get('country_code', '?'):4} "
            f"{obj.get('src_port', 0):6} "
            f"{obj.get('dst_port', 0):6} "
            f"{obj.get('payload_size', 0):5}"
        )
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if not os.path.exists(cfg.hit_log_path):
        print("No honeypot logs yet.")
        return 0
    from .tui import run_watch

    return run_watch(cfg.hit_log_path)


def cmd_start(args: argparse.Namespace) -> int:
    from .daemon import run_daemon

    run_daemon(cfg_path=args.config)
    return 0


def _version() -> str:
    import importlib.metadata
    try:
        return importlib.metadata.version("tsunamiwall")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])

    # Extract global --config/-c from anywhere in the argv, so both
    #   tsunamiwall -c path start
    #   tsunamiwall start -c path
    # work and end up on the same Namespace attribute.
    config_path: str | None = None
    i = 0
    while i < len(argv):
        if argv[i] in ("--config", "-c") and i + 1 < len(argv):
            config_path = argv[i + 1]
            del argv[i : i + 2]
            continue
        if argv[i].startswith("--config="):
            config_path = argv[i].split("=", 1)[1]
            del argv[i]
            continue
        i += 1

    parser = argparse.ArgumentParser(prog="tsunamiwall", description="TsunamiWall CLI")
    parser.add_argument("--version", "-v", action="version", version=f"tsunamiwall {_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="start the TsunamiWall daemon (runs in foreground)")

    status_p = sub.add_parser("status", help="show allowed ports and active honeypots")

    stop_p = sub.add_parser("stop", help="gracefully stop the daemon and save state")

    reset_p = sub.add_parser("reset", help="emergency stop: flush rules and exit daemon")

    logs_p = sub.add_parser("logs", help="show recent honeypot hit logs")

    watch_p = sub.add_parser("watch", help="live TUI of honeypot hits")

    allow_p = sub.add_parser("allow", help="explicitly allow one or more ports")
    allow_p.add_argument("port", type=int, nargs="?", help="single port to allow")
    allow_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    allow_p.add_argument(
        "--ip", metavar="IP/CIDR", help="restrict the allowed port(s) to this source IP or CIDR"
    )

    deny_p = sub.add_parser("deny", help="remove one or more allowed/blocked ports")
    deny_p.add_argument("port", type=int, nargs="?", help="single port to deny")
    deny_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    deny_p.add_argument(
        "--ip", metavar="IP/CIDR", help="remove the port(s) only for this source IP or CIDR"
    )

    block_p = sub.add_parser("block", help="explicitly block one or more ports (drops traffic even if a service listens)")
    block_p.add_argument("port", type=int, nargs="?", help="single port to block")
    block_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")

    unblock_p = sub.add_parser("unblock", help="remove one or more blocked ports")
    unblock_p.add_argument("port", type=int, nargs="?", help="single port to unblock")
    unblock_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")

    args = parser.parse_args(argv)
    args = argparse.Namespace(**{**vars(args), "config": config_path})

    for cmd in ("allow", "deny", "block", "unblock"):
        if args.command == cmd and args.port is None and not args.file:
            parser.error(f"{cmd} requires either a PORT argument or --file")
    if args.command == "start":
        return cmd_start(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "stop":
        return cmd_stop(args)
    if args.command == "reset":
        return cmd_reset(args)
    if args.command == "logs":
        return cmd_logs(args)
    if args.command == "watch":
        return cmd_watch(args)
    if args.command == "allow":
        return cmd_allow(args)
    if args.command == "deny":
        return cmd_deny(args)
    if args.command == "block":
        return cmd_block(args)
    if args.command == "unblock":
        return cmd_unblock(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
