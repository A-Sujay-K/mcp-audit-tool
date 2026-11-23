from mcp_sentinel.core.models import Finding, ScanReport, Severity, StandardMapping
from mcp_sentinel.reporting.html import generate_html_report
from mcp_sentinel.reporting.markdown import generate_markdown_report
from mcp_sentinel.reporting.sarif import generate_sarif_report, serialize_sarif


def test_sarif_report_structure() -> None:
    f1 = Finding(
        rule_id="MCP-SEC-001",
        rule_name="Hardcoded Secret",
        severity=Severity.CRITICAL,
        target="server-a",
        message="Hardcoded GitHub token",
        evidence="ghp_***",
        remediation="Use environment variable",
        standards=StandardMapping(cwe=["CWE-798"], owasp_llm=["OWASP-LLM06:2025"]),
        location="claude_desktop_config.json",
    )
    report = ScanReport(
        version="0.1.0", timestamp="2026-11-23T12:00:00Z", targets_scanned=1, findings=[f1]
    )
    report.recompute_summary()

    sarif = generate_sarif_report(report)
    assert sarif["version"] == "2.1.0"
    assert "https://docs.oasis-open.org/sarif/sarif/v2.1.0" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-sentinel"
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "MCP-SEC-001"
    assert "CWE-798" in driver["rules"][0]["properties"]["tags"]

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "MCP-SEC-001"
    assert results[0]["level"] == "error"

    serialized = serialize_sarif(report)
    assert "MCP-SEC-001" in serialized


def test_markdown_report() -> None:
    report = ScanReport(
        version="0.1.0", timestamp="2026-11-23T12:00:00Z", targets_scanned=2, findings=[]
    )
    report.recompute_summary()
    md_empty = generate_markdown_report(report)
    assert "Zero security findings detected" in md_empty

    f = Finding(
        rule_id="MCP-SEC-002",
        rule_name="Dangerous Shell Wrapper",
        severity=Severity.HIGH,
        target="srv",
        message="Shell wrapper sh -c invoked",
        evidence="sh -c",
        remediation="Direct execution",
        standards=StandardMapping(cwe=["CWE-78"]),
    )
    report.findings = [f]
    report.recompute_summary()
    md_findings = generate_markdown_report(report)
    assert "MCP-SEC-002" in md_findings
    assert "Dangerous Shell Wrapper" in md_findings


def test_html_report() -> None:
    report = ScanReport(
        version="0.1.0", timestamp="2026-11-23T12:00:00Z", targets_scanned=1, findings=[]
    )
    report.recompute_summary()
    html_empty = generate_html_report(report)
    assert "<!DOCTYPE html>" in html_empty
    assert "Zero security findings detected" in html_empty
    assert "Akarsh Sujay Kumar" in html_empty
    assert "All rights reserved" in html_empty
