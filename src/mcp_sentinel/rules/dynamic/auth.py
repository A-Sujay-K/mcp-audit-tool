from urllib.parse import urlparse

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


class MissingAuthRule(BaseRule):
    """Detects remote MCP servers configured without authentication or authorization tokens."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-013",
            name="Missing Authentication / Insecure Auth Flow",
            severity=Severity.HIGH,
            description="Remote MCP server endpoint lacks required authentication headers or does not adhere to the MCP OAuth 2.1 / PKCE profile.",
            standards=StandardMapping(
                cwe=["CWE-306"],
                owasp_llm=["OWASP-LLM06:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Implement OAuth 2.1 authorization with PKCE and require Bearer token validation for all remote tool and resource access.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []
        if target.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and target.url:
            parsed = urlparse(target.url)
            host = (parsed.hostname or "").lower()

            if host not in LOOPBACK_HOSTS:
                # Check headers for authorization
                headers = {k.lower(): v for k, v in target.headers.items()}
                has_auth = "authorization" in headers or "x-api-key" in headers

                if not has_auth:
                    findings.append(
                        Finding(
                            rule_id=self.metadata.id,
                            rule_name=self.metadata.name,
                            severity=self.metadata.severity,
                            target=target.name,
                            message=f"Remote server '{target.name}' ({target.url}) is configured without an Authorization header or API key.",
                            evidence=f"Target URL: {target.url} | Configured Headers: {list(target.headers.keys())}",
                            remediation=self.metadata.remediation,
                            standards=self.metadata.standards,
                            location=target.source_file,
                        )
                    )

        return findings
