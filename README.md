# TsunamiWall

Linux server firewall with built-in per-port honeypot listeners.

## What it does
- Blocks all unsolicited inbound traffic by default.
- Allows traffic only to real listening services you approve.
- Opens stealth honeypot listeners on unused high ports (`10000-65535`) to log attacker probes.
- Provides a simple CLI for control and an emergency reset for safety.

## Status
Early development — v1 focuses on IPv4, TCP/UDP listening socket discovery, iptables backend, and manual CLI.

## Quick commands
```bash
tsunamiwall start      # start the daemon + apply rules
tsunamiwall status     # show active services and honeypots
tsunamiwall allow 22   # explicitly allow a real service port
tsunamiwall deny 8080  # remove an allowed port
tsunamiwall logs       # show recent honeypot hits
tsunamiwall reset      # emergency: remove all TsunamiWall rules
```

## Architecture
- **Daemon**: asyncio-based, watches listening sockets, manages honeypot listeners.
- **Firewall backend**: `iptables` via a dedicated `TSUNAMIWALL` chain.
- **CLI**: Unix-socket client talking to the daemon.

See `DESIGN.md` and `AGENTS.md` for details.
