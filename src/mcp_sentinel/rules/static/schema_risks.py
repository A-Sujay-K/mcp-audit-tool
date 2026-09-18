import re

from mcp_sentinel.core.models import (
    Finding,
    RuleMetadata,
    Severity,
    StandardMapping,
    ToolDefinition,
)
from mcp_sentinel.rules.base import BaseRule

# Sensitive sink identifiers (substring or word)
SENSITIVE_PARAM_REGEX = re.compile(
    r"(cmd|command|exec|execute|shell|bash|powershell|query|sql|statement|path|filepath|filename|file_path|script|code|eval|payload|url|uri|webhook)",
    re.IGNORECASE,
)


class OverPermissiveSchemaRule(BaseRule):
    """Detects unbounded string inputs in tool schemas that connect to sensitive sinks."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-010",
            name="Over-Permissive String Parameter Schema",
            severity=Severity.MEDIUM,
            description="Tool parameter takes an unbounded string without maxLength, regex pattern, or enum validation while targeting a sensitive execution or query sink.",
            standards=StandardMapping(
                cwe=["CWE-20"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M02"],
            ),
            remediation="Enforce strict JSON schema bounds: add 'maxLength', 'pattern' (regex validation), or 'enum' restrictions to sensitive string parameters.",
        )

    def evaluate_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        schema = tool.input_schema or {}
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return findings

        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                continue

            prop_type = prop_def.get("type")
            if prop_type != "string":
                continue

            # Check if parameter name hints at sensitive sink
            if not SENSITIVE_PARAM_REGEX.search(prop_name):
                continue

            # Check for constraints: maxLength, enum, pattern
            has_bounds = any(k in prop_def for k in ("maxLength", "enum", "pattern"))
            if not has_bounds:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=self.metadata.severity,
                        target=f"{tool.server_name}:{tool.name}" if tool.server_name else tool.name,
                        message=f"Parameter '{prop_name}' in tool '{tool.name}' is an unbounded string targeting a sensitive sink.",
                        evidence=f"Parameter: '{prop_name}' | Schema: {prop_def}",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

        return findings
