from urllib.parse import urlparse

import httpx

from mcp_sentinel.core.models import (
    Finding,
    RuleMetadata,
    ServerTarget,
    Severity,
    StandardMapping,
    TransportType,
)
from mcp_sentinel.rules.base import BaseRule

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class InsecureTransportRule(BaseRule):
    """Detects unencrypted HTTP or WebSocket transports for non-loopback MCP endpoints."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-011",
            name="Insecure Transport Protocol",
            severity=Severity.HIGH,
            description="The MCP server communicates over plaintext HTTP or WebSocket without TLS over a non-loopback network interface.",
            standards=StandardMapping(
                cwe=["CWE-319"],
                owasp_llm=["OWASP-LLM06:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Enforce HTTPS/TLS encryption for all non-loopback MCP network transports to protect credentials and tool calls from eavesdropping.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []
        if target.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and target.url:
            parsed = urlparse(target.url)
            host = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "").lower()

            if scheme in ("http", "ws") and host not in LOOPBACK_HOSTS:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=self.metadata.severity,
                        target=target.name,
                        message=f"Server '{target.name}' uses plaintext '{scheme}://' to remote host '{host}'.",
                        evidence=f"Target URL: {target.url}",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                        location=target.source_file,
                    )
                )

        return findings


class DnsRebindingRule(BaseRule):
    """Detects lack of Host header validation on local/loopback HTTP MCP endpoints."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-012",
            name="DNS Rebinding / Host Header Permissiveness",
            severity=Severity.HIGH,
            description="The local MCP HTTP/SSE endpoint fails to validate the Host request header, leaving local tools exposed to browser-based DNS rebinding attacks.",
            standards=StandardMapping(
                cwe=["CWE-942", "CWE-346"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M02"],
            ),
            remediation="Configure the MCP server to validate the 'Host' and 'Origin' request headers, rejecting requests that do not match expected local domains.",
        )

    def check_dns_rebinding_live(self, target: ServerTarget) -> list[Finding]:
        """Actively checks if target rejects foreign Host header (requires live target)."""
        if not target.url:
            return []
        parsed = urlparse(target.url)
        if parsed.hostname not in LOOPBACK_HOSTS:
            return []

        try:
            with httpx.Client(timeout=2.0) as client:
                # Send request with spoofed Host header
                resp = client.get(
                    target.url,
                    headers={"Host": "attacker.com", "Origin": "http://attacker.com"},
                )
                if resp.status_code == 200:
                    return [
                        Finding(
                            rule_id=self.metadata.id,
                            rule_name=self.metadata.name,
                            severity=self.metadata.severity,
                            target=target.name,
                            message=f"Local server '{target.name}' accepted request with spoofed Host 'attacker.com' (status 200).",
                            evidence=f"URL: {target.url} | Host: attacker.com | Status: {resp.status_code}",
                            remediation=self.metadata.remediation,
                            standards=self.metadata.standards,
                        )
                    ]
        except (httpx.RequestError, OSError):
            pass

        return []
