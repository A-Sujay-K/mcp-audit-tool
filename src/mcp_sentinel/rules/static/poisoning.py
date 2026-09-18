import re

from mcp_sentinel.core.models import (
    Finding,
    RuleMetadata,
    Severity,
    StandardMapping,
    ToolDefinition,
)
from mcp_sentinel.rules.base import BaseRule

ZERO_WIDTH_CHARS = {
    "\u200b": "Zero-Width Space (U+200B)",
    "\u200c": "Zero-Width Non-Joiner (U+200C)",
    "\u200d": "Zero-Width Joiner (U+200D)",
    "\ufeff": "Byte Order Mark / Zero-Width No-Break Space (U+FEFF)",
    "\u2060": "Word Joiner (U+2060)",
}

BIDI_OVERRIDE_CHARS = {
    "\u202a": "Left-to-Right Embedding (U+202A)",
    "\u202b": "Right-to-Left Embedding (U+202B)",
    "\u202c": "Pop Directional Formatting (U+202C)",
    "\u202d": "Left-to-Right Override (U+202D)",
    "\u202e": "Right-to-Left Override (U+202E)",
    "\u2066": "Left-to-Right Isolate (U+2066)",
    "\u2067": "Right-to-Left Isolate (U+2067)",
    "\u2068": "First Strong Isolate (U+2068)",
    "\u2069": "Pop Directional Isolate (U+2069)",
}

INJECTION_PATTERNS = [
    re.compile(
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bdisregard\s+(all\s+)?(previous|prior|system)\b", re.IGNORECASE),
    re.compile(
        r"\b(system\s+prompt|developer\s+mode|jailbreak|admin\s+mode)\s+(override|activated|enabled)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(do\s+not\s+follow|bypass)\s+(safety|content|system)\s+(filter|guidelines|rules)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\boutput\s+(the\s+)?(entire|full|secret)?\s*(system\s+instructions|system\s+prompt)\b",
        re.IGNORECASE,
    ),
]


class ZeroWidthUnicodeRule(BaseRule):
    """Detects invisible or zero-width Unicode characters used for description cloaking."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-006",
            name="Zero-Width & Invisible Unicode Characters",
            severity=Severity.HIGH,
            description="Invisible or zero-width Unicode characters detected in tool descriptions or names, indicating hidden instructions or cloaked payloads.",
            standards=StandardMapping(
                cwe=["CWE-116"],
                owasp_llm=["OWASP-LLM01:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Strip all non-printable and zero-width Unicode characters from tool names and manifest descriptions.",
        )

    def evaluate_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        combined = f"{tool.name} {tool.description}"

        detected: list[str] = []
        for char, desc in ZERO_WIDTH_CHARS.items():
            if char in combined:
                detected.append(desc)

        if detected:
            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=self.metadata.severity,
                    target=f"{tool.server_name}:{tool.name}" if tool.server_name else tool.name,
                    message=f"Tool '{tool.name}' contains invisible Unicode characters: {', '.join(detected)}.",
                    evidence=f"Characters found: {', '.join(detected)} | Tool name: {tool.name}",
                    remediation=self.metadata.remediation,
                    standards=self.metadata.standards,
                )
            )

        return findings


class BidiOverrideRule(BaseRule):
    """Detects bidirectional Unicode override characters used for visual deception."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-007",
            name="Bidirectional Text Override",
            severity=Severity.HIGH,
            description="Bidirectional Unicode formatting characters detected in tool descriptions, which can visually reverse strings to deceive human reviewers.",
            standards=StandardMapping(
                cwe=["CWE-116"],
                owasp_llm=["OWASP-LLM01:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Enforce strictly normalized text without bidirectional overrides in tool definitions.",
        )

    def evaluate_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        combined = f"{tool.name} {tool.description}"

        detected: list[str] = []
        for char, desc in BIDI_OVERRIDE_CHARS.items():
            if char in combined:
                detected.append(desc)

        if detected:
            findings.append(
                Finding(
                    rule_id=self.metadata.id,
                    rule_name=self.metadata.name,
                    severity=self.metadata.severity,
                    target=f"{tool.server_name}:{tool.name}" if tool.server_name else tool.name,
                    message=f"Tool '{tool.name}' contains bidirectional override characters: {', '.join(detected)}.",
                    evidence=f"Characters detected: {', '.join(detected)}",
                    remediation=self.metadata.remediation,
                    standards=self.metadata.standards,
                )
            )

        return findings


class InstructionPoisoningRule(BaseRule):
    """Detects prompt injection and system override instructions embedded in tool descriptions."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-008",
            name="Prompt Injection / Instruction Smuggling",
            severity=Severity.HIGH,
            description="Tool description contains instructions targeting the LLM system prompt or attempting to override model safety directives.",
            standards=StandardMapping(
                cwe=["CWE-74"],
                owasp_llm=["OWASP-LLM01:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Remove instruction-like imperative directives from tool descriptions and confine tool manifests to factual descriptions of inputs and outputs.",
        )

    def evaluate_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []

        for pattern in INJECTION_PATTERNS:
            match = pattern.search(tool.description)
            if match:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=self.metadata.severity,
                        target=f"{tool.server_name}:{tool.name}" if tool.server_name else tool.name,
                        message=f"Tool '{tool.name}' contains instruction override phrase: '{match.group(0)}'.",
                        evidence=f"Matched: '{match.group(0)}' in description: {tool.description[:120]}...",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )
                break

        return findings
