import logging
from collections.abc import Sequence

import httpx

from mcp_sentinel.core.models import Finding, RuleMetadata, Severity, StandardMapping
from mcp_sentinel.rules.base import BaseRule

logger = logging.getLogger(__name__)

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 10.0


class OsvVulnerabilityRule(BaseRule):
    """Queries the Open Source Vulnerabilities (OSV.dev) API for known advisories and CVEs."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-016",
            name="Known Vulnerability in Declared Dependency",
            severity=Severity.HIGH,
            description="The declared MCP package or runtime component matches an active security advisory or published CVE in the OSV database.",
            standards=StandardMapping(
                cwe=["CWE-1395"],
                owasp_llm=["OWASP-LLM05:2025"],
                owasp_mcp=["OWASP-MCP-M05"],
            ),
            remediation="Upgrade the affected dependency to a non-vulnerable patched version specified in the linked advisory.",
        )

    def query_packages(
        self,
        packages: Sequence[tuple[str, str, str]],  # (name, version, ecosystem)
    ) -> list[Finding]:
        """Queries OSV batch API synchronously with fallback to empty on network failure."""
        if not packages:
            return []

        queries = [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for name, ver, eco in packages
        ]

        findings: list[Finding] = []
        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
                resp = client.post(OSV_BATCH_ENDPOINT, json={"queries": queries})
                if resp.status_code != 200:
                    logger.warning("OSV API returned status %d", resp.status_code)
                    return []
                data = resp.json()
        except (httpx.RequestError, ValueError) as e:
            logger.warning("Failed to reach OSV API: %e", e)
            return []

        results = data.get("results", [])
        for idx, res in enumerate(results):
            vulns = res.get("vulns", [])
            name, ver, eco = packages[idx]
            for v in vulns:
                vuln_id = v.get("id", "UNKNOWN-VULN")
                summary = v.get("summary") or v.get("details", "")[:100]
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.HIGH,
                        target=f"{eco}:{name}@{ver}",
                        message=f"Known vulnerability {vuln_id} detected in {name}@{ver}: {summary}",
                        evidence=f"Advisory: https://osv.dev/vulnerability/{vuln_id}",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

        return findings
