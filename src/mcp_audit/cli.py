"""MCP Audit Tool CLI — the main user-facing interface.

Usage:
    mcp-audit scan [--config PATH] [--confirm-exploits] [--output json|table] [--verbose]
    mcp-audit drift-check [--config PATH]
    mcp-audit serve [--host HOST] [--port PORT]
    mcp-audit export [--scan-id UUID] [--format json|csv|sarif] [--output PATH]
    mcp-audit info
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from mcp_audit import __version__
from mcp_audit.config import get_settings

app = typer.Typer(
    name="mcp-audit",
    help="Cross-server MCP security auditor with sandboxed exploit confirmation.",
    no_args_is_help=True,
)
console = Console()

BANNER = f"""[bold cyan]
╔══════════════════════════════════════════════════╗
║           MCP AUDIT TOOL v{__version__}                 ║
║   Cross-Server Security Auditor                  ║
║   with Sandboxed Exploit Confirmation            ║
╚══════════════════════════════════════════════════╝
[/bold cyan]"""


def _risk_color(score: float) -> str:
    """Return rich color tag for a risk score."""
    if score >= 7:
        return "bold red"
    elif score >= 4:
        return "bold yellow"
    return "bold green"


def _print_banner() -> None:
    console.print(BANNER)


# ═══════════════════════════════════════════════════════════════════════
# SCAN command
# ═══════════════════════════════════════════════════════════════════════


@app.command()
def scan(
    config: str | None = typer.Option(
        None, "--config", "-c", help="Path to MCP config file (auto-detect if omitted)."
    ),
    confirm_exploits: bool = typer.Option(
        False, "--confirm-exploits", "-x", help="Run sandboxed exploit confirmations."
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output format: table or json."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose output."),
) -> None:
    """Run a full security scan across all configured MCP servers."""
    _print_banner()
    asyncio.run(_run_scan(config, confirm_exploits, output, verbose))


async def _run_scan(
    config_path: str | None,
    confirm_exploits: bool,
    output_fmt: str,
    verbose: bool,
) -> None:
    """Execute the full scan pipeline."""
    from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
    from mcp_audit.graph.risk_scorer import RiskScorer
    from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
    from mcp_audit.parser.capability_classifier import (
        CapabilityClassifier,
        RuleBasedFallbackClassifier,
    )
    from mcp_audit.parser.config_parser import ConfigParser
    from mcp_audit.parser.schemas import ScanResult, ScanStatus
    from mcp_audit.parser.tool_discovery import MockToolDiscoverer, ToolDiscoverer

    settings = get_settings()
    scan = ScanResult(config_source=config_path or "auto-detect")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # ── Step 1: Parse configs ──────────────────────────────────────
        task = progress.add_task("Parsing MCP configurations...", total=None)
        parser = ConfigParser()

        if config_path:
            client_configs = [parser.parse_file(config_path)]
        else:
            client_configs = parser.auto_detect()

        servers = []
        for cc in client_configs:
            servers.extend(cc.servers)

        scan.servers_discovered = servers
        scan.status = ScanStatus.DISCOVERING
        progress.update(task, description=f"Found {len(servers)} servers across {len(client_configs)} config(s)")
        progress.remove_task(task)

        if not servers:
            console.print(
                Panel(
                    "[yellow]No MCP servers found.[/yellow]\n\n"
                    "Specify a config file with --config or ensure your MCP client "
                    "(Claude Desktop, Cursor, etc.) is configured.",
                    title="No Servers Detected",
                    border_style="yellow",
                )
            )
            return

        # ── Step 2: Discover tools ─────────────────────────────────────
        task = progress.add_task("Discovering tools from servers...", total=None)
        try:
            discoverer = ToolDiscoverer()
            discovered = await discoverer.discover_all(servers)
        except Exception:
            if verbose:
                console.print("[dim]Live discovery failed, using mock discoverer.[/dim]")
            mock = MockToolDiscoverer()
            discovered = await mock.discover_all(servers)

        scan.tools_discovered = discovered
        progress.update(task, description=f"Discovered {len(discovered)} tools")
        progress.remove_task(task)

        # ── Step 3: Classify capabilities ──────────────────────────────
        task = progress.add_task("Classifying tool capabilities...", total=None)
        scan.status = ScanStatus.CLASSIFYING

        try:
            classifier = CapabilityClassifier(settings)
            classified = await classifier.classify_batch(discovered)
        except Exception as e:
            if verbose:
                console.print(f"[dim]LLM classifier failed ({e}), using rule-based fallback.[/dim]")
            fallback = RuleBasedFallbackClassifier()
