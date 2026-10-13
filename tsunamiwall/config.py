"""Configuration and defaults for TsunamiWall."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration."""

    honeypot_start: int = 10_000
    honeypot_end: int = 65_535
    discovery_interval: float = 30.0
    iptables_chain: str = "TSUNAMIWALL"
    log_dir: str = "/var/log/tsunamiwall"
    run_dir: str = "/run/tsunamiwall"
    socket_path: str = "/run/tsunamiwall/daemon.sock"
    pid_path: str = "/run/tsunamiwall/daemon.pid"
    hit_log_name: str = "hits.logl"
    # Maximum honeypot listeners. The default is kept below typical Linux
    # soft nofile limits (1024) to avoid startup failures. Raise on servers
    # configured with higher limits if you want wider honeypot coverage.
    max_honeypots: int = 900
    # Trusted source IPs or CIDR blocks that are always allowed inbound before
    # any port filtering. Use this to prevent locking yourself out.
    trusted_ips: list[str] = field(default_factory=list)
    # When true, discovered listening ports are treated as blocked until they are
    # explicitly allowed. This gives a strict default-deny policy where every real
    # service must be whitelisted. When false (the default), TsunamiWall behaves as
    # an allow-list firewall: any listening socket is automatically allowed.
    auto_block_listeners: bool = False
    # Maximum payload bytes to read from each honeypot connection.
    payload_max_bytes: int = 4096
    # Seconds to wait for the attacker to send data before closing.
    payload_read_timeout: float = 2.0
    # Directory under which per-country per-IP payload logs are stored.
    payload_log_dir: str = "/var/log/tsunamiwall/bycountry"

    def __post_init__(self):
        if not 1 <= self.honeypot_start <= 65535:
            raise ValueError("honeypot_start must be a valid port number")
        if not 1 <= self.honeypot_end <= 65535:
            raise ValueError("honeypot_end must be a valid port number")
        if self.honeypot_start > self.honeypot_end:
            raise ValueError("honeypot_start must be <= honeypot_end")
        if not os.path.isabs(self.log_dir):
            raise ValueError("log_dir must be an absolute path")
        if not os.path.isabs(self.run_dir):
            raise ValueError("run_dir must be an absolute path")
        if not os.path.isabs(self.payload_log_dir):
            raise ValueError("payload_log_dir must be an absolute path")
        if self.payload_max_bytes <= 0:
            raise ValueError("payload_max_bytes must be positive")
        if self.payload_read_timeout <= 0:
            raise ValueError("payload_read_timeout must be positive")
        for ip in self.trusted_ips:
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError as exc:
                raise ValueError(f"trusted_ips contains invalid IP/CIDR: {ip}") from exc

    @property
    def hit_log_path(self) -> str:
        return os.path.join(self.log_dir, self.hit_log_name)

    @property
    def state_path(self) -> str:
        return os.path.join(self.run_dir, "daemon-state.json")


def default_config() -> Config:
    """Return the production default configuration."""
    return Config()


def _coerce_field(name: str, value: Any, field_type: str | type) -> Any:
    """Coerce a raw config value to the expected dataclass type.

    Dataclass fields annotated with builtins (e.g. `int`) expose their type
    as a string in Python 3.10+ when evaluated lazily, so we accept both the
    actual type and its string name.
    """
    if isinstance(field_type, str):
        type_name = field_type.split("[", 1)[0]
    else:
        type_name = getattr(field_type, "__name__", "")
    # Generic aliases like list[str] report __name__ as 'list' as well.
    if type_name == "list":
        if not isinstance(value, list):
            raise TypeError(f"Config key {name} must be a list")
        return [str(v) for v in value]
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    if type_name == "str":
        return str(value)
    if type_name == "bool":
        return bool(value)
    raise TypeError(f"Unsupported config field type for {name}: {field_type}")


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load configuration from a YAML file, falling back to defaults.

    If *path* is not given, the following locations are tried in order:
      1. $TSUNAMIWALL_CONFIG
      2. /etc/tsunamiwall/config.yaml
      3. ~/.config/tsunamiwall/config.yaml
    If none exist, defaults are returned.
    """
    if path is not None:
        candidates = [Path(path)]
    else:
        env_path = os.environ.get("TSUNAMIWALL_CONFIG")
        candidates = [
            Path(env_path) if env_path else Path(),
            Path("/etc/tsunamiwall/config.yaml"),
            Path.home() / ".config" / "tsunamiwall" / "config.yaml",
        ]

    config_path: Path | None = None
    for candidate in candidates:
        if candidate.is_file():
            config_path = candidate
            break

    defaults = default_config()
    if config_path is None:
        return defaults

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Config file {config_path} must contain a YAML mapping")

    known = {f.name: f.type for f in fields(Config)}
    overrides: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in known:
            raise ValueError(f"Unknown config key: {key}")
        overrides[key] = _coerce_field(key, value, known[key])

    return Config(**overrides)


def safe_ports(used_ports: set[int], cfg: Config | None = None) -> set[int]:
    """Return candidate honeypot ports in range that are not in use."""
    cfg = cfg or default_config()
    candidates = set(range(cfg.honeypot_start, cfg.honeypot_end + 1))
    available = candidates - used_ports
    if len(available) > cfg.max_honeypots:
        available = set(sorted(available)[: cfg.max_honeypots])
    return available
