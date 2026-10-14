"""Command-line client for TsunamiWall daemon."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .config import Config, load_config


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
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad response from daemon"}

    try:
        return asyncio.run(_talk())
    except (ConnectionRefusedError, FileNotFoundError) as exc:
        raise DaemonUnreachable(f"Cannot reach daemon at {cfg.socket_path}: {exc}") from exc


class DaemonUnreachable(Exception):
    """Raised when the CLI cannot connect to the daemon socket."""


def _print_response(resp: dict) -> int:
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
    return _print_response(_send(args, {"action": "stop"}))


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
        emergency_reset()
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
        # Tail last 50 lines.
        lines = fh.readlines()
    for line in lines[-50:]:
        print(line, end="")
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


def _add_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        "-c",
        metavar="PATH",
        help="path to TsunamiWall YAML config file",
    )


def _version() -> str:
    import importlib.metadata
    try:
        return importlib.metadata.version("tsunamiwall")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tsunamiwall", description="TsunamiWall CLI")
    parser.add_argument("--version", "-v", action="version", version=f"tsunamiwall {_version()}")
    _add_config_arg(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="start the TsunamiWall daemon (runs in foreground)")
    _add_config_arg(start_p)

    status_p = sub.add_parser("status", help="show allowed ports and active honeypots")
    _add_config_arg(status_p)

    stop_p = sub.add_parser("stop", help="gracefully stop the daemon and save state")
    _add_config_arg(stop_p)

    reset_p = sub.add_parser("reset", help="emergency stop: flush rules and exit daemon")
    _add_config_arg(reset_p)

    logs_p = sub.add_parser("logs", help="show recent honeypot hit logs")
    _add_config_arg(logs_p)

    watch_p = sub.add_parser("watch", help="live TUI of honeypot hits")
    _add_config_arg(watch_p)

    allow_p = sub.add_parser("allow", help="explicitly allow one or more ports")
    allow_p.add_argument("port", type=int, nargs="?", help="single port to allow")
    allow_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    allow_p.add_argument(
        "--ip", metavar="IP/CIDR", help="restrict the allowed port(s) to this source IP or CIDR"
    )
    _add_config_arg(allow_p)

    deny_p = sub.add_parser("deny", help="remove one or more allowed/blocked ports")
    deny_p.add_argument("port", type=int, nargs="?", help="single port to deny")
    deny_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    deny_p.add_argument(
        "--ip", metavar="IP/CIDR", help="remove the port(s) only for this source IP or CIDR"
    )
    _add_config_arg(deny_p)

    block_p = sub.add_parser("block", help="explicitly block one or more ports (drops traffic even if a service listens)")
    block_p.add_argument("port", type=int, nargs="?", help="single port to block")
    block_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    _add_config_arg(block_p)

    unblock_p = sub.add_parser("unblock", help="remove one or more blocked ports")
    unblock_p.add_argument("port", type=int, nargs="?", help="single port to unblock")
    unblock_p.add_argument("--file", "-f", metavar="PATH", help="file with one port per line")
    _add_config_arg(unblock_p)

    args = parser.parse_args(argv)
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
