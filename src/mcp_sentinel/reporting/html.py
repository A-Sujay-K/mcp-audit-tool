from mcp_sentinel.core.models import ScanReport, Severity
from mcp_sentinel.core.sanitization import sanitize_html

SEVERITY_COLORS = {
    Severity.CRITICAL: "#d73a49",
    Severity.HIGH: "#e36209",
    Severity.MEDIUM: "#dbab09",
    Severity.LOW: "#005cc5",
    Severity.INFORMATIONAL: "#6a737d",
}


def generate_html_report(report: ScanReport) -> str:
    """Generates a self-contained zero-CDN HTML audit report."""
    rows = []
    for f in report.findings:
        color = SEVERITY_COLORS.get(f.severity, "#586069")
        standards = ", ".join(list(f.standards.cwe) + list(f.standards.owasp_llm))
        rows.append(f"""
        <tr>
            <td><span class="badge" style="background-color: {color};">{sanitize_html(f.severity.value)}</span></td>
            <td><code>{sanitize_html(f.rule_id)}</code></td>
            <td><strong>{sanitize_html(f.target)}</strong></td>
            <td>{sanitize_html(f.message)}</td>
            <td><code>{sanitize_html(f.evidence)}</code></td>
            <td>{sanitize_html(f.remediation)}</td>
            <td><small>{sanitize_html(standards)}</small></td>
        </tr>
        """)

    summary_cards = []
    for sev in Severity:
        cnt = report.summary.get(sev.value, 0)
        color = SEVERITY_COLORS.get(sev, "#586069")
        summary_cards.append(f"""
        <div class="card" style="border-top: 4px solid {color};">
            <h3>{cnt}</h3>
            <p>{sanitize_html(sev.value)}</p>
        </div>
        """)

    findings_table = (
        f"""
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Rule ID</th>
                <th>Target</th>
                <th>Message</th>
                <th>Evidence</th>
                <th>Remediation</th>
                <th>Standards</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
    """
        if report.findings
        else "<p class='clean'>Zero security findings detected. Audited environment is clean.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sentinel Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f6f8fa; color: #24292e; margin: 0; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
        h1 {{ border-bottom: 1px solid #e1e4e8; padding-bottom: 12px; margin-top: 0; }}
        .meta {{ color: #586069; font-size: 14px; margin-bottom: 24px; }}
        .cards {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
        .card {{ flex: 1; min-width: 140px; background: #fdfdfd; padding: 16px; border-radius: 6px; border: 1px solid #e1e4e8; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 28px; }}
        .card p {{ margin: 4px 0 0; font-size: 13px; color: #586069; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
        th, td {{ border: 1px solid #e1e4e8; padding: 10px 12px; text-align: left; vertical-align: top; }}
        th {{ background: #fafbfc; }}
        .badge {{ color: #fff; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; display: inline-block; }}
        code {{ background: #f1f1f1; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
        .clean {{ color: #22863a; font-weight: bold; font-size: 16px; padding: 16px; background: #dcffe4; border-radius: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>MCP-Sentinel Security Audit Report</h1>
        <div class="meta">
            Timestamp: {sanitize_html(report.timestamp)} &bull; Targets Scanned: {report.targets_scanned} &bull; Findings: {len(report.findings)} &bull; Version: {sanitize_html(report.version)}
        </div>
        <div class="cards">
            {"".join(summary_cards)}
        </div>
        <h2>Findings Detail</h2>
        {findings_table}
    </div>
</body>
</html>
"""
