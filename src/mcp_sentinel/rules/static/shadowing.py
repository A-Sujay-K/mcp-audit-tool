import re
from collections.abc import Sequence

from mcp_sentinel.core.models import (
    Finding,
    RuleMetadata,
    ServerTarget,
    Severity,
    StandardMapping,
    ToolDefinition,
)
from mcp_sentinel.rules.base import BaseRule


def tokenize(text: str) -> set[str]:
    """Tokenizes text into lowercase alphanumeric words."""
    return set(re.findall(r"\b\w{3,}\b", text.lower()))


def jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """Calculates Jaccard similarity between two token sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


class ToolShadowingRule(BaseRule):
    """Detects cross-server tool shadowing, duplicate tool names, and description collisions."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-009",
            name="Tool Shadowing & Namespace Hijacking",
            severity=Severity.MEDIUM,
            description="Duplicate tool names or highly similar tool descriptions detected across multiple MCP servers, creating potential for tool hijacking or model confusion.",
            standards=StandardMapping(
                cwe=["CWE-699"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M02"],
            ),
            remediation="Use unique server prefixes for tool names (e.g. serverA_toolName) and provide distinct, non-overlapping tool descriptions.",
        )

    def evaluate_context(
        self,
        targets: Sequence[ServerTarget],
        tools: Sequence[ToolDefinition],
    ) -> list[Finding]:
        findings: list[Finding] = []
        name_map: dict[str, list[ToolDefinition]] = {}

        # 1. Check exact name collisions across servers
        for t in tools:
            name_map.setdefault(t.name, []).append(t)

        for name, tool_list in name_map.items():
            servers = {t.server_name for t in tool_list if t.server_name}
            if len(servers) > 1:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.HIGH,
                        target=name,
                        message=f"Duplicate tool name '{name}' defined across multiple distinct servers: {', '.join(sorted(servers))}.",
                        evidence=f"Servers declaring '{name}': {', '.join(sorted(servers))}",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

        # 2. Check high description similarity between different tools
        for i in range(len(tools)):
            for j in range(i + 1, len(tools)):
                t1, t2 = tools[i], tools[j]
                if t1.name != t2.name and t1.server_name != t2.server_name:
                    tokens1 = tokenize(t1.description)
                    tokens2 = tokenize(t2.description)
                    sim = jaccard_similarity(tokens1, tokens2)
                    if sim >= 0.85 and len(tokens1) >= 6:
                        findings.append(
                            Finding(
                                rule_id=self.metadata.id,
                                rule_name=self.metadata.name,
                                severity=Severity.MEDIUM,
                                target=f"{t1.server_name}:{t1.name}",
                                message=f"Tool '{t1.name}' on '{t1.server_name}' has 85%+ description similarity with '{t2.name}' on '{t2.server_name}'.",
                                evidence=f"Jaccard similarity: {sim:.2f} | T1: '{t1.description[:60]}...' vs T2: '{t2.description[:60]}...'",
                                remediation=self.metadata.remediation,
                                standards=self.metadata.standards,
                            )
                        )

        return findings
