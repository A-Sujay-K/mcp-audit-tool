from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_sentinel.core.models import ScanReport, Severity
from mcp_sentinel.core.sanitization import sanitize_terminal

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFORMATIONAL: "cyan",
}


def print_banner(version: str = "0.1.0") -> None:
    text = Text(f"MCP-Sentinel v{version} — Autonomous Security Auditor for MCP", style="bold cyan")
    console.print(Panel(text, border_style="cyan"))


def print_findings_table(report: ScanReport) -> None:
    if not report.findings:
        console.print("[bold green]✓ Zero security findings detected.[/bold green]")
        return

    table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Rule ID", width=14)
    table.add_column("Target", width=18)
    table.add_column("Message", width=40)
    table.add_column("Remediation", width=36)

    for f in report.findings:
        sev_style = SEVERITY_STYLES.get(f.severity, "white")
        table.add_row(
            Text(f.severity.value, style=sev_style),
            f.rule_id,
            sanitize_terminal(f.target, max_length=25),
            sanitize_terminal(f.message, max_length=80),
            sanitize_terminal(f.remediation, max_length=80),
        )

    console.print(table)


def print_summary(report: ScanReport) -> None:
    summary_table = Table(title="Audit Summary", show_header=True, header_style="bold blue")
    summary_table.add_column("Severity Level", style="bold")
    summary_table.add_column("Count", justify="right")

    for sev in Severity:
        count = report.summary.get(sev.value, 0)
        style = SEVERITY_STYLES.get(sev, "white")
        summary_table.add_row(Text(sev.value, style=style), str(count))

    console.print(summary_table)
