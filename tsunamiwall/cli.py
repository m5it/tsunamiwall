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

    return asyncio.run(_talk())


def _print_response(resp: dict) -> int:
    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 1


def cmd_status(args: argparse.Namespace) -> int:
    return _print_response(_send(args, {"action": "status"}))


def cmd_allow(args: argparse.Namespace) -> int:
    return _print_response(_send(args, {"action": "allow", "port": args.port}))


def cmd_deny(args: argparse.Namespace) -> int:
    return _print_response(_send(args, {"action": "deny", "port": args.port}))


def cmd_reset(args: argparse.Namespace) -> int:
    return _print_response(_send(args, {"action": "reset"}))


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tsunamiwall", description="TsunamiWall CLI")
    _add_config_arg(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="start the TsunamiWall daemon (runs in foreground)")
    _add_config_arg(start_p)

    sub.add_parser("status", help="show allowed ports and active honeypots")
    sub.add_parser("reset", help="emergency stop: flush rules and exit daemon")
    sub.add_parser("logs", help="show recent honeypot hit logs")

    allow_p = sub.add_parser("allow", help="explicitly allow a port")
    allow_p.add_argument("port", type=int)

    deny_p = sub.add_parser("deny", help="remove an allowed port")
    deny_p.add_argument("port", type=int)

    args = parser.parse_args(argv)
    if args.command == "start":
        return cmd_start(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "reset":
        return cmd_reset(args)
    if args.command == "logs":
        return cmd_logs(args)
    if args.command == "allow":
        return cmd_allow(args)
    if args.command == "deny":
        return cmd_deny(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
