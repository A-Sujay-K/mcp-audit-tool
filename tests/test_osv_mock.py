from unittest.mock import MagicMock, patch

from mcp_sentinel.core.models import Finding, Severity, StandardMapping
from mcp_sentinel.supply_chain.osv import OsvVulnerabilityRule
from mcp_sentinel.watch.github import GitHubIssueManager


def test_osv_mock_response() -> None:
    rule = OsvVulnerabilityRule()
    fake_osv_resp = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-1234-5678-90ab",
                        "summary": "Remote Code Execution in sample package",
                        "details": "A vulnerability allows arbitrary code execution under specific conditions.",
                    }
                ]
            }
        ]
    }

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_osv_resp
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client

    with patch("httpx.Client", return_value=mock_client):
        findings = rule.query_packages([("sample-pkg", "1.0.0", "PyPI")])
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP-SEC-016"
        assert findings[0].severity == Severity.HIGH
        assert "GHSA-1234-5678-90ab" in findings[0].message


def test_github_issue_manager_sync_mock() -> None:
    mgr = GitHubIssueManager(repo="test/repo", token="ghp_test123")

    mock_client = MagicMock()
    # Mock list open issues returning 1 existing issue
    existing_issue = {
        "number": 42,
        "title": "[MCP-SEC-001] Old finding",
        "body": "<!-- fingerprint: old-fp-123 -->\nFinding details",
    }
    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.json.return_value = [existing_issue]

    mock_post = MagicMock()
    mock_post.status_code = 201

    mock_patch = MagicMock()
    mock_patch.status_code = 200

    mock_client.get.return_value = mock_get
    mock_client.post.return_value = mock_post
    mock_client.patch.return_value = mock_patch
    mock_client.__enter__.return_value = mock_client

    with patch("httpx.Client", return_value=mock_client):
        new_finding = Finding(
            rule_id="MCP-SEC-002",
            rule_name="Dangerous Command",
            severity=Severity.HIGH,
            target="srv",
            message="sh -c invoked",
            evidence="sh -c",
            remediation="Direct exec",
            standards=StandardMapping(cwe=["CWE-78"]),
            fingerprint="new-fp-456",
        )
        opened, closed = mgr.sync_findings([new_finding])
        assert opened == 1
        assert closed == 1  # old-fp-123 should be closed since it was not in findings
