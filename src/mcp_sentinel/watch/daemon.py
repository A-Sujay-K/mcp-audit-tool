import logging
import time
from collections.abc import Sequence
from pathlib import Path

from mcp_sentinel.core.console import console
from mcp_sentinel.discovery.detector import discover_targets
from mcp_sentinel.rules.registry import RuleRegistry
from mcp_sentinel.watch.github import GitHubIssueManager

logger = logging.getLogger(__name__)


def run_watch_loop(
    paths: Sequence[Path] | None = None,
    interval_seconds: int = 60,
    github_repo: str | None = None,
    max_cycles: int | None = None,
) -> None:
    """Runs autonomous continuous audit loop over discovered targets."""
    console.print(
        f"[bold cyan]Starting MCP-Sentinel autonomous watch daemon (interval: {interval_seconds}s)...[/bold cyan]"
    )
    if github_repo:
        console.print(
            f"[green]GitHub issue synchronization enabled for repository: {github_repo}[/green]"
        )

    gh_manager = GitHubIssueManager(repo=github_repo) if github_repo else None
    registry = RuleRegistry()
    cycle = 0

    try:
        while True:
            cycle += 1
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            console.print(
                f"\n[bold blue][{timestamp}] Audit cycle #{cycle} executing...[/bold blue]"
            )

            targets = discover_targets(paths)
            findings = registry.run_static_scan(targets=targets)

            console.print(
                f"Scanned {len(targets)} target(s) — detected {len(findings)} finding(s)."
            )

            if gh_manager and findings:
                opened, closed = gh_manager.sync_findings(findings)
                if opened or closed:
                    console.print(
                        f"[yellow]GitHub Sync: {opened} opened, {closed} closed.[/yellow]"
                    )

            if max_cycles and cycle >= max_cycles:
                console.print("[cyan]Completed requested watch cycles. Exiting.[/cyan]")
                break

            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        console.print("\n[yellow]Watch daemon stopped by operator.[/yellow]")
