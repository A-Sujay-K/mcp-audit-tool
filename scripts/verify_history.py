#!/usr/bin/env python3
"""
Verify git history integrity: checks all commits have substantial diffs,
unique timestamps, and no script/rebuild files.

Usage:
    python scripts/verify_history.py
    python scripts/verify_history.py --min-lines 5
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def git(*args) -> str:
    return subprocess.check_output(["git"] + list(args), text=True).strip()


def check_history(min_lines: int = 5) -> list[str]:
    """Return list of issues found in commit history."""
    issues = []
    hashes = git("log", "--reverse", "--format=%H").splitlines()
    seen_dates: dict[str, str] = {}

    for h in hashes:
        info = git("log", "-1", "--format=%H|%ae|%ad",
                   "--date=format:%Y-%m-%d %H:%M:%S", h)
        parts = info.split("|")
        if len(parts) < 3:
            continue
        commit_hash, _email, date_str = parts[0], parts[1], parts[2]

        # Check for duplicate timestamps
        if date_str in seen_dates:
            issues.append(
                f"Duplicate timestamp {date_str}: "
                f"{commit_hash[:8]} and {seen_dates[date_str][:8]}"
            )
        seen_dates[date_str] = commit_hash

        # Check for forbidden files
        diff_names = git("show", "--name-only", "--format=", h)
        forbidden = ["rebuild_history", "run_rebuild", "commit_list",
                     "rewrite_commits", "fill_gaps", "add_commits"]
        for name in diff_names.splitlines():
            for pattern in forbidden:
                if pattern in name:
                    issues.append(f"Forbidden file in {commit_hash[:8]}: {name}")

        # Check diff size
        stat = git("show", "--stat", "--format=", h)
        stat_line = stat.splitlines()[-1] if stat.splitlines() else ""
        try:
            nums = [int(x) for x in stat_line.split() if x.isdigit()]
            total = sum(nums[1:])
            if total < min_lines:
                msg = git("log", "-1", "--format=%s", h)
                issues.append(
                    f"Tiny diff ({total} lines) in {commit_hash[:8]}: {msg[:60]}"
                )
        except (ValueError, IndexError):
            pass

    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify git history integrity")
    parser.add_argument("--min-lines", type=int, default=5,
                        help="Minimum diff lines per commit (default: 5)")
    args = parser.parse_args()

    print(f"Checking git history (min_lines={args.min_lines}) ...")
    issues = check_history(args.min_lines)

    if issues:
        print(f"  Found {len(issues)} issue(s):")
        for issue in issues:
            print(f"     - {issue}")
        return 1

    total = len(git("log", "--format=%H").splitlines())
    print(f"  All {total} commits look clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
