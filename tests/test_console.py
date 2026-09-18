from mcp_sentinel.core.console import print_banner, print_findings_table, print_summary
from mcp_sentinel.core.models import Finding, ScanReport, Severity, StandardMapping


def test_console_print_banner() -> None:
    print_banner("0.1.0")


def test_console_print_empty_findings() -> None:
    report = ScanReport(timestamp="2026-11-23T12:00:00Z")
    print_findings_table(report)


def test_console_print_findings_and_summary() -> None:
    finding = Finding(
        rule_id="MCP-SEC-001",
        rule_name="Hardcoded Secret",
        severity=Severity.CRITICAL,
        target="srv1",
        message="Hardcoded API token",
        evidence="token=ghp_****",
        remediation="Use env var",
        standards=StandardMapping(cwe=["CWE-798"], owasp_llm=["OWASP-LLM06:2025"]),
    )
    report = ScanReport(
        timestamp="2026-11-23T12:00:00Z",
        targets_scanned=1,
        findings=[finding],
    )
    report.recompute_summary()
    print_findings_table(report)
    print_summary(report)
