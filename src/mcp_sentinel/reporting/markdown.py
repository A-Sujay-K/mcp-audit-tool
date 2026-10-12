from mcp_sentinel.core.models import ScanReport, Severity
from mcp_sentinel.core.sanitization import sanitize_terminal

SEVERITY_BADGES = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH: "🟠 **HIGH**",
    Severity.MEDIUM: "🟡 **MEDIUM**",
    Severity.LOW: "🔵 **LOW**",
    Severity.INFORMATIONAL: "⚪ **INFO**",
}


def generate_markdown_report(report: ScanReport) -> str:
    """Generates a GitHub-flavored Markdown report."""
    lines: list[str] = [
        "# MCP-Sentinel Security Audit Report",
        "",
        f"**Audit Timestamp:** `{report.timestamp}`  ",
        f"**Targets Scanned:** `{report.targets_scanned}`  ",
        f"**Total Findings:** `{len(report.findings)}`  ",
        "",
        "## Summary",
        "",
        "| Severity Level | Finding Count |",
        "| :--- | :--- |",
    ]

    for sev in Severity:
        cnt = report.summary.get(sev.value, 0)
        lines.append(f"| {SEVERITY_BADGES[sev]} | {cnt} |")

    lines.extend(
        [
            "",
            "## Findings Detail",
            "",
        ]
    )

    if not report.findings:
        lines.append(
            "✅ **Zero security findings detected.** All inspected configurations and tools passed security checks."
        )
        return "\n".join(lines)

    for idx, f in enumerate(report.findings, start=1):
        lines.extend(
            [
                f"### {idx}. [{f.rule_id}] {f.rule_name}",
                "",
                f"- **Severity:** {SEVERITY_BADGES[f.severity]}",
                f"- **Target:** `{sanitize_terminal(f.target, max_length=100)}`",
                f"- **Message:** {sanitize_terminal(f.message, max_length=200)}",
                f"- **Evidence:** `{sanitize_terminal(f.evidence, max_length=200)}`",
                f"- **Remediation:** {sanitize_terminal(f.remediation, max_length=300)}",
            ]
        )
        standards = (
            list(f.standards.cwe) + list(f.standards.owasp_llm) + list(f.standards.owasp_mcp)
        )
        if standards:
            lines.append(f"- **Standard References:** {', '.join(f'`{s}`' for s in standards)}")
        lines.append("")

    return "\n".join(lines)
