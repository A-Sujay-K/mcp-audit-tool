import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from mcp_sentinel import __version__
from mcp_sentinel.core.console import console, print_banner, print_findings_table, print_summary
from mcp_sentinel.core.models import ScanReport, Severity
from mcp_sentinel.discovery.detector import discover_targets
from mcp_sentinel.reporting.html import generate_html_report
from mcp_sentinel.reporting.markdown import generate_markdown_report
from mcp_sentinel.reporting.sarif import serialize_sarif
from mcp_sentinel.rules.registry import RuleRegistry
from mcp_sentinel.supply_chain.cyclonedx import generate_cyclonedx_sbom
from mcp_sentinel.watch.daemon import run_watch_loop

app = typer.Typer(
    name="mcp-sentinel",
    help="Autonomous security auditor for Model Context Protocol (MCP) servers and client configurations.",
    no_args_is_help=True,
)

SEVERITY_ORDER = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@app.command()
def version() -> None:
    """Displays the MCP-Sentinel version."""
    print_banner(__version__)


@app.command()
def scan(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Explicit paths to MCP configuration files or project directories."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write the audit report file."),
    ] = None,
    format_type: Annotated[
        str,
        typer.Option(
            "--format", "-f", help="Report output format: table, json, sarif, markdown, html."
        ),
    ] = "table",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit with non-zero status if findings meet or exceed severity: CRITICAL, HIGH, MEDIUM, LOW.",
        ),
    ] = "HIGH",
) -> None:
    """Performs static security analysis on discovered or explicitly specified MCP client configurations."""
    print_banner(__version__)

    targets = discover_targets(paths)
    if not targets:
        console.print("[yellow]No MCP client configuration targets discovered.[/yellow]")
        raise typer.Exit(code=0)

    console.print(
        f"[bold green]Discovered {len(targets)} MCP server target(s). Running static analysis...[/bold green]\n"
    )

    registry = RuleRegistry()
    raw_findings = registry.run_static_scan(targets=targets)

    report = ScanReport(
        version=__version__,
        timestamp=datetime.now(UTC).isoformat(),
        targets_scanned=len(targets),
        findings=raw_findings,
    )
    report.recompute_summary()

    # Formatted rendering
    fmt = format_type.lower()
    if fmt == "json":
        json_output = json.dumps(report.model_dump(), indent=2)
        if output:
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            print(json_output)
    elif fmt == "sarif":
        sarif_output = serialize_sarif(report)
        if output:
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[green]SARIF report saved to {output}[/green]")
        else:
            print(sarif_output)
    elif fmt == "markdown":
        md_output = generate_markdown_report(report)
        if output:
            output.write_text(md_output, encoding="utf-8")
            console.print(f"[green]Markdown report saved to {output}[/green]")
        else:
            print(md_output)
    elif fmt == "html":
        html_output = generate_html_report(report)
        if output:
            output.write_text(html_output, encoding="utf-8")
            console.print(f"[green]HTML report saved to {output}[/green]")
        else:
            print(html_output)
    else:
        # Default table output
        print_findings_table(report)
        print()
        print_summary(report)

        if output:
            output.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
            console.print(f"\n[green]Detailed report saved to {output}[/green]")

    # Check failure threshold
    try:
        threshold_sev = Severity(fail_on.upper())
        threshold_level = SEVERITY_ORDER[threshold_sev]
        max_detected_level = max(
            (SEVERITY_ORDER[f.severity] for f in report.findings),
            default=-1,
        )
        if max_detected_level >= threshold_level:
            console.print(
                f"\n[bold red]Audit failed: findings met or exceeded threshold '{fail_on.upper()}'.[/bold red]"
            )
            raise typer.Exit(code=1)
    except KeyError:
        console.print(
            f"[yellow]Warning: Unrecognized --fail-on level '{fail_on}'. Defaulting to zero exit.[/yellow]"
        )


@app.command()
def sbom(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Paths to MCP configuration files or directories."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write the CycloneDX SBOM JSON file."),
    ] = None,
) -> None:
    """Generates a CycloneDX v1.6 SBOM JSON for declared MCP servers and runtimes."""
    targets = discover_targets(paths)
    sbom_dict = generate_cyclonedx_sbom(targets, version=__version__)
    serialized = json.dumps(sbom_dict, indent=2)

    if output:
        output.write_text(serialized, encoding="utf-8")
        console.print(f"[green]CycloneDX SBOM saved to {output}[/green]")
    else:
        print(serialized)


@app.command()
def watch(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Paths to MCP configuration files or directories to monitor."),
    ] = None,
    interval: Annotated[
        int,
        typer.Option("--interval", "-i", help="Interval in seconds between scan cycles."),
    ] = 60,
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo", "-r", help="GitHub repository slug (owner/repo) to synchronize issues."
        ),
    ] = None,
    cycles: Annotated[
        int | None,
        typer.Option(
            "--cycles",
            help="Maximum scan cycles to execute before exiting (useful for testing/CI).",
        ),
    ] = None,
) -> None:
    """Runs autonomous continuous monitoring and syncs security findings to GitHub Issues."""
    print_banner(__version__)
    run_watch_loop(
        paths=paths,
        interval_seconds=interval,
        github_repo=repo,
        max_cycles=cycles,
    )


if __name__ == "__main__":
    app()
