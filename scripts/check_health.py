#!/usr/bin/env python3
"""
Quick health-check script for the mcp-audit API.

Pings the /api/health endpoint and prints a status summary.
Useful in CI or monitoring pipelines.

Usage:
    python scripts/check_health.py
    python scripts/check_health.py --url https://mcp-audit-api.onrender.com
    python scripts/check_health.py --timeout 5 --retries 3
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def check(url: str, timeout: int = 10) -> dict | None:
    """Return parsed JSON from /api/health or None on failure."""
    health_url = url.rstrip("/") + "/api/health"
    try:
        with urllib.request.urlopen(health_url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {health_url}")
        return None
    except urllib.error.URLError as e:
        print(f"  Connection error: {e.reason}")
        return None
    except Exception as e:
        print(f"  Unexpected error: {e}")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="mcp-audit health check")
    parser.add_argument("--url", default="http://localhost:8000",
                        help="Base URL of the mcp-audit API")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1,
                        help="Number of retry attempts on failure")
    parser.add_argument("--interval", type=int, default=5,
                        help="Seconds between retries")
    args = parser.parse_args()

    print(f"Checking {args.url} ...")
    for attempt in range(1, args.retries + 1):
        result = check(args.url, args.timeout)
        if result:
            print(f"  Status : {result.get('status', '?')}")
            print(f"  Version: {result.get('version', '?')}")
            return 0
        if attempt < args.retries:
            print(f"  Retrying in {args.interval}s ({attempt}/{args.retries}) ...")
            time.sleep(args.interval)

    print("  Health check FAILED.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
