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
            classified = [fallback.classify_tool(t) for t in discovered]

        scan.tools_classified = classified
        progress.update(task, description=f"Classified {len(classified)} tools")
        progress.remove_task(task)

        # ── Step 4: Build graph & analyze ──────────────────────────────
        task = progress.add_task("Analyzing capability graph...", total=None)
        scan.status = ScanStatus.ANALYZING

        builder = CapabilityGraphBuilder()
        graph = builder.build(classified)

        analyzer = TrifectaAnalyzer(graph)
        findings = analyzer.find_all()

        scorer = RiskScorer()
        findings = scorer.score_all(findings, servers)
        overall_risk = scorer.compute_overall_risk(findings)

        scan.findings = findings
        scan.overall_risk_score = overall_risk
        progress.update(task, description=f"Found {len(findings)} findings, overall risk: {overall_risk:.1f}/10")
        progress.remove_task(task)

        # ── Step 5: Sandbox exploits (optional) ────────────────────────
        if confirm_exploits and findings:
            task = progress.add_task("Running sandboxed exploit confirmations...", total=len(findings))
            scan.status = ScanStatus.EXPLOITING

            from mcp_audit.sandbox.sandbox_manager import SandboxManager

            sandbox = SandboxManager(settings)
            image_ok = await sandbox.ensure_image()

            if image_ok:
                results = await sandbox.run_all_exploits(findings)
                scan.exploit_results = results
                progress.update(task, advance=len(findings))
            else:
                console.print("[yellow]Docker not available — skipping exploit confirmation.[/yellow]")
            progress.remove_task(task)

    scan.status = ScanStatus.COMPLETED

    # ── Output ─────────────────────────────────────────────────────────
    if output_fmt == "json":
        console.print(scan.model_dump_json(indent=2))
    else:
        _print_scan_table(scan)


def _print_scan_table(scan) -> None:
    """Print a rich summary of the scan results."""
    # Summary panel
    console.print()
    console.print(
        Panel(
            f"[bold]Servers:[/bold] {scan.total_servers}  |  "
            f"[bold]Tools:[/bold] {scan.total_tools}  |  "
            f"[bold]Findings:[/bold] {scan.total_findings}  |  "
            f"[bold]Confirmed Exploits:[/bold] {scan.confirmed_exploits}  |  "
            f"[bold]Risk:[/bold] [{_risk_color(scan.overall_risk_score)}]{scan.overall_risk_score:.1f}/10.0[/{_risk_color(scan.overall_risk_score)}]",
            title="📊 Scan Summary",
            border_style="cyan",
        )
    )

    # Findings table
    if scan.findings:
        console.print()
        table = Table(title="⚠️  Findings", show_lines=True)
        table.add_column("Risk", justify="center", style="bold", width=6)
        table.add_column("Type", style="cyan")
        table.add_column("Chain", style="white")
        table.add_column("Servers", style="dim")
        table.add_column("Cross-Server", justify="center")

        for f in scan.findings:
            risk_str = f"[{_risk_color(f.risk_score)}]{f.risk_score:.1f}[/{_risk_color(f.risk_score)}]"

            chain_parts = []
            if f.injection_tool:
                chain_parts.append(f"[yellow]{f.injection_tool.tool_name}[/yellow]")
            if f.data_tool:
                chain_parts.append(f"[red]{f.data_tool.tool_name}[/red]")
            if f.exfil_tool:
                chain_parts.append(f"[blue]{f.exfil_tool.tool_name}[/blue]")
            if f.code_exec_tool:
                chain_parts.append(f"[magenta]{f.code_exec_tool.tool_name}[/magenta]")
            chain = " → ".join(chain_parts)

            servers = ", ".join(f.servers_involved) if f.servers_involved else "—"
            cross = "[red]YES[/red]" if f.is_cross_server else "[dim]no[/dim]"

            table.add_row(risk_str, f.finding_type.value, chain, servers, cross)

        console.print(table)

    # Exploit results
    if scan.exploit_results:
        console.print()
        table = Table(title="💥 Exploit Confirmation Results", show_lines=True)
        table.add_column("Verdict", justify="center")
        table.add_column("Data Exfiltrated", justify="center")
        table.add_column("Steps", justify="center")

        for er in scan.exploit_results:
            verdict_style = {
                "CONFIRMED": "[bold red]🔴 CONFIRMED[/bold red]",
                "PARTIAL": "[bold yellow]🟡 PARTIAL[/bold yellow]",
                "FAILED": "[bold green]🟢 NOT EXPLOITABLE[/bold green]",
                "TIMEOUT": "[bold blue]⏱️ TIMEOUT[/bold blue]",
                "ERROR": "[bold red]⚠️ ERROR[/bold red]",
            }
            verdict_str = verdict_style.get(
                er.verdict.value if hasattr(er.verdict, "value") else er.verdict,
                str(er.verdict),
            )
            exfil = "[red]YES[/red]" if er.sensitive_data_exfiltrated else "[green]NO[/green]"
