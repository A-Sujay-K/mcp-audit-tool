import uuid
from collections.abc import Sequence

from mcp_sentinel.core.exceptions import AuthorizationRequiredError
from mcp_sentinel.core.models import (
    Finding,
    RuleMetadata,
    Severity,
    StandardMapping,
    ToolDefinition,
)
from mcp_sentinel.rules.base import BaseRule


class BenignCanaryProbeRule(BaseRule):
    """Performs strictly benign, non-destructive canary probing against authorized MCP tool inputs."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-015",
            name="Canary Input Reflection / Unvalidated Execution Sink",
            severity=Severity.HIGH,
            description="The tool input handler reflected raw canary test payloads or returned unhandled backend error traces under benign boundary testing.",
            standards=StandardMapping(
                cwe=["CWE-20", "CWE-22", "CWE-78"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M02"],
            ),
            remediation="Validate tool parameter inputs against strict allowlists or regex bounds before passing them to internal execution sinks.",
        )

    def generate_canary_payload(self) -> str:
        """Generates a benign, unique sentinel canary string."""
        return f"mcp-canary-{uuid.uuid4().hex[:12]}"

    def evaluate_tool_canary(
        self,
        tool: ToolDefinition,
        tool_output: str,
        canary_sent: str,
        authorized: bool = False,
        target_allowlist: Sequence[str] = (),
    ) -> list[Finding]:
        """Evaluates whether an authorized tool output reflects canary payloads insecurely."""
        if not authorized:
            raise AuthorizationRequiredError(
                "Active probing requires the explicit '--i-have-authorization' flag and an authorized target allowlist."
            )

        if tool.server_name and target_allowlist and tool.server_name not in target_allowlist:
            raise AuthorizationRequiredError(
                f"Server '{tool.server_name}' is not in the authorized target allowlist."
            )

        findings: list[Finding] = []

        # Check for unhandled command or SQL error patterns in response
        error_indicators = [
            "syntax error in sql statement",
            "unhandled exception",
            "traceback (most recent call last)",
            "command not found",
            "/bin/sh:",
        ]

        output_lower = tool_output.lower()
        for indicator in error_indicators:
            if indicator in output_lower:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.MEDIUM,
                        target=f"{tool.server_name}:{tool.name}",
                        message=f"Tool '{tool.name}' leaked raw execution trace or syntax error under boundary test.",
                        evidence=f"Indicator: '{indicator}' | Output snippet: {tool_output[:120]}...",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )
                break

        return findings
