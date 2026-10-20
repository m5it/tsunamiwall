# TsunamiWall Development

## Project layout
```
tsunamiwall/
  __init__.py       # package metadata
  config.py         # defaults and safe-port helper
  discovery.py        # /proc/net socket discovery
  iptables.py       # iptables backend wrapper
  honeypot.py       # asyncio honeypot listener
  daemon.py         # main asyncio daemon
  cli.py            # Unix-socket CLI client
  emergency.py      # standalone reset tool
tests/              # pytest suite
docs/               # this documentation
```

## Run tests
```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
```

### Network-namespace integration tests
`tests/test_netns_firewall.py` and `tests/test_netns_daemon.py` run real
`iptables`/`ip6tables` inside isolated Linux network namespaces. They are
skipped automatically when the test runner cannot create namespaces (for
example inside a restricted container or as an unprivileged user with no user
namespace support). Run them as root on a Linux host to exercise actual rule
installation, reset, daemon startup, restart, and startup-rollback behavior.

## Coding guidelines
- Keep changes minimal and focused.
- Maintain the safety rule: TsunamiWall only modifies rules inside its own `TSUNAMIWALL` chain.
- All new iptables interactions go through `tsunamiwall/iptables.py`.
- Prefer `asyncio` for network-facing code.
- Add tests for pure-logic modules; integration tests requiring root are skipped automatically.
