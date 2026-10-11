# TsunamiWall — Agent Notes

## Project goal
Build a Linux server firewall with two jobs:
1. Block all unwanted inbound traffic.
2. Run stealth honeypot listeners on unused high ports to log what attackers/scanners are probing.

## v1 scope
- Target environment: servers.
- Packet filter backend: `iptables`.
- Service discovery: listening sockets only (read from `/proc/net/tcp`, `/proc/net/udp`, `ss`, and `psutil` if available).
- Management interface: manual CLI.
- Honeypot scope: ports `10000-65535`, excluding ports already used by real services.
- Honeypot behavior: silently accept connections, log source IP/port/destination port/timestamp, then close.
- Safety: emergency `reset` command that flushes all TsunamiWall-managed iptables rules.

## Architecture
```
+----------------------------------+
|  tsunamiwall daemon (asyncio)    |
|  - listens on CLI unix socket    |
|  - scans listening sockets       |
|  - manages honeypot coroutines   |
|  - pushes iptables rules         |
+----------------------------------+
                |
                v
+----------------------------------+
|  iptables                        |
|  - default DROP for INPUT        |
|  - allow loopback                |
|  - allow established/related     |
|  - allow real service ports      |
|  - allow honeypot ports          |
|    (packets redirected/accepted) |
+----------------------------------+
```

## Key modules
- `tsunamiwall/config.py` — configuration, defaults, paths, YAML config file loading.
- `tsunamiwall/discovery.py` — find listening TCP/UDP sockets and their ports.
- `tsunamiwall/iptables.py` — safe wrapper around `iptables`/`ip6tables`.
- `tsunamiwall/honeypot.py` — asyncio honeypot listener per port.
- `tsunamiwall/daemon.py` — main asyncio daemon.
- `tsunamiwall/cli.py` — CLI client talking to the daemon via Unix socket.
- `tsunamiwall/emergency.py` — standalone reset tool.

## Safety rules
- Never mutate pre-existing iptables rules outside a marked TsunamiWall chain.
- All TsunamiWall rules live in a dedicated chain (`TSUNAMIWALL`) jumped from `INPUT`.
- The emergency reset flushes only the `TSUNAMIWALL` chain and removes the jump.
- Do not bind honeypots to ports below 10000 to avoid stealing system services.
- Daemon must detect new real services and immediately release conflicting honeypots.
