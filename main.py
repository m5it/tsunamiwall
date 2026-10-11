#!/usr/bin/env python3
"""Standalone entry point for running TsunamiWall without package install.

Usage:
    sudo python main.py start
    sudo python main.py status
    sudo python main.py -c /etc/tsunamiwall/config.yaml start
    sudo python main.py reset
"""

from __future__ import annotations

import sys

from tsunamiwall.cli import main

if __name__ == "__main__":
    sys.exit(main())
