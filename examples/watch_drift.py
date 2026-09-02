#!/usr/bin/env python3
"""
Drift monitoring example: continuously watch for MCP tool changes.

Polls all detected MCP servers every N seconds and alerts when tool
descriptions or capabilities change between polls (rug-pull detection).

Usage:
    python examples/watch_drift.py
    python examples/watch_drift.py --interval 60 --config path/to/config.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
import time
from datetime import datetime


class DriftWatcher:
    """Watches MCP servers for tool drift and prints alerts."""

    def __init__(self, config_path: str | None = None, interval: int = 30):
        self.config_path = config_path
        self.interval = interval
        self.baseline: dict | None = None
        self.running = True

    async def snapshot(self) -> dict:
        """Take a snapshot of all currently discovered tools."""
        from mcp_audit.parser.config_parser import ConfigParser
        from mcp_audit.parser.tool_discovery import MockToolDiscoverer
        from mcp_audit.drift.hasher import ToolHasher

        parser = ConfigParser()
        clients = ([parser.parse_file(self.config_path)] if self.config_path
                   else parser.auto_detect())
        servers = [s for c in clients for s in c.servers] if clients else []

        discoverer = MockToolDiscoverer()
        tools = await discoverer.discover_all(servers)

        hasher = ToolHasher()
        return {
            f"{t.server_name}::{t.name}": hasher.hash_tool(t)
            for t in tools
        }

    def compare(self, old: dict, new: dict) -> list[str]:
        """Return list of human-readable change descriptions."""
        changes = []
        for key in set(old) | set(new):
            if key not in old:
                changes.append(f"ADDED   {key}")
            elif key not in new:
                changes.append(f"REMOVED {key}")
            elif old[key] != new[key]:
                changes.append(f"CHANGED {key}")
        return changes

    async def run(self):
        """Main watch loop."""
        print(f"Starting drift watch (interval={self.interval}s). Ctrl+C to stop.")
        print("Taking initial baseline snapshot...")

        self.baseline = await self.snapshot()
        print(f"Baseline: {len(self.baseline)} tool(s) tracked.")
        print()

        while self.running:
            await asyncio.sleep(self.interval)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                current = await self.snapshot()
                changes = self.compare(self.baseline, current)
                if changes:
                    print(f"[{ts}] DRIFT DETECTED -- {len(changes)} change(s):")
                    for c in changes:
                        print(f"  {c}")
                    self.baseline = current
                else:
                    print(f"[{ts}] No changes detected ({len(current)} tools).")
            except Exception as e:
                print(f"[{ts}] Error during snapshot: {e}")


async def main():
    parser = argparse.ArgumentParser(description="MCP drift watcher")
    parser.add_argument("--config", help="Path to MCP client config file")
    parser.add_argument("--interval", type=int, default=30,
                        help="Poll interval in seconds (default: 30)")
    args = parser.parse_args()

    watcher = DriftWatcher(config_path=args.config, interval=args.interval)

    def handle_signal(sig, frame):
        print("\nStopping drift watcher.")
        watcher.running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    await watcher.run()
    print("Drift watcher stopped.")


if __name__ == "__main__":
    asyncio.run(main())
