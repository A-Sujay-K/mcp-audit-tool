import logging
import os
from collections.abc import Sequence
from typing import Any

import httpx

from mcp_sentinel.core.models import Finding

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
FINDING_LABEL = "mcp-sentinel-finding"


class GitHubIssueManager:
    """Manages the autonomous lifecycle of GitHub Issues for security findings."""

    def __init__(self, repo: str, token: str | None = None) -> None:
        self.repo = repo
        # Strictly read token from parameter or GITHUB_TOKEN environment variable
        self.token = token or os.environ.get("GITHUB_TOKEN", "")

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "mcp-sentinel-watch",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def sync_findings(self, findings: Sequence[Finding]) -> tuple[int, int]:
        """Opens new GitHub issues for new findings and auto-closes resolved ones."""
        if not self.token:
            logger.warning("GITHUB_TOKEN not configured; skipping GitHub Issue synchronization.")
            return 0, 0

        existing_issues = self._fetch_open_finding_issues()
        existing_by_fingerprint: dict[str, dict[str, Any]] = {}

        for issue in existing_issues:
            body = issue.get("body", "")
            # Fingerprint marker in issue body
            for line in body.splitlines():
                if line.startswith("<!-- fingerprint: ") and line.endswith(" -->"):
                    fp = line.replace("<!-- fingerprint: ", "").replace(" -->", "").strip()
                    existing_by_fingerprint[fp] = issue
                    break

        opened_count = 0
        closed_count = 0
        active_fps = {f.fingerprint for f in findings}

        # 1. Open issues for new findings
        for f in findings:
            if f.fingerprint not in existing_by_fingerprint:
                self._create_finding_issue(f)
                opened_count += 1

        # 2. Close issues for resolved findings
        for fp, issue in existing_by_fingerprint.items():
            if fp not in active_fps:
                self._close_resolved_issue(issue)
                closed_count += 1

        return opened_count, closed_count

    def _fetch_open_finding_issues(self) -> list[dict[str, Any]]:
        url = f"{GITHUB_API_BASE}/repos/{self.repo}/issues?state=open&labels={FINDING_LABEL}&per_page=100"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        return [item for item in data if isinstance(item, dict)]
                    return []
        except httpx.RequestError as e:
            logger.error("Failed to query open GitHub issues: %s", e)
        return []

    def _create_finding_issue(self, f: Finding) -> None:
        url = f"{GITHUB_API_BASE}/repos/{self.repo}/issues"
        standards = ", ".join(list(f.standards.cwe) + list(f.standards.owasp_llm))
        body = f"""<!-- fingerprint: {f.fingerprint} -->
## [{f.rule_id}] {f.rule_name}

**Severity:** {f.severity.value}
**Target:** `{f.target}`
**Standards:** {standards or "N/A"}

### Message
{f.message}

### Evidence
```
{f.evidence}
```

### Remediation
{f.remediation}

---
*Generated autonomously by MCP-Sentinel.*
"""
        payload = {
            "title": f"[{f.rule_id}] {f.rule_name} on {f.target}",
            "body": body,
            "labels": [FINDING_LABEL, f.severity.value.lower(), "security"],
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, json=payload, headers=self._get_headers())
                if resp.status_code == 201:
                    logger.info("Opened GitHub Issue for %s on %s", f.rule_id, f.target)
        except httpx.RequestError as e:
            logger.error("Failed to create GitHub Issue: %s", e)

    def _close_resolved_issue(self, issue: dict[str, Any]) -> None:
        issue_number = issue.get("number")
        if not issue_number:
            return
        url = f"{GITHUB_API_BASE}/repos/{self.repo}/issues/{issue_number}"
        payload = {
            "state": "closed",
            "state_reason": "completed",
        }
        comment_url = f"{GITHUB_API_BASE}/repos/{self.repo}/issues/{issue_number}/comments"
        comment_payload = {"body": "Finding remediated. Closed autonomously by MCP-Sentinel."}

        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(comment_url, json=comment_payload, headers=self._get_headers())
                client.patch(url, json=payload, headers=self._get_headers())
                logger.info("Closed resolved GitHub Issue #%d", issue_number)
        except httpx.RequestError as e:
            logger.error("Failed to close resolved GitHub Issue #%d: %s", issue_number, e)
