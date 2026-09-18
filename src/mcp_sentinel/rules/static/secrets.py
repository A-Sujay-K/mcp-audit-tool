import math
import re

from mcp_sentinel.core.models import Finding, RuleMetadata, ServerTarget, Severity, StandardMapping
from mcp_sentinel.rules.base import BaseRule

# Verified token patterns
SECRET_PATTERNS = [
    (
        "GitHub Token",
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
    ),
    ("OpenAI API Key", re.compile(r"\b(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_\-]{40,})\b")),
    ("Anthropic API Key", re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{40,})\b")),
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z\-]{10,})\b")),
    (
        "JSON Web Token (JWT)",
        re.compile(r"\b(ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9._-]{10,})\b"),
    ),
]


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def mask_secret(secret: str) -> str:
    """Masks a secret string showing only the first 4 and last 3 characters."""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}...{secret[-3:]}"


class HardcodedSecretsRule(BaseRule):
    """Detects hardcoded API keys, tokens, and high-entropy credentials in MCP configs."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-001",
            name="Hardcoded Secret in Environment or Arguments",
            severity=Severity.CRITICAL,
            description="Hardcoded API keys, tokens, or high-entropy credentials detected in command-line arguments or environment variables.",
            standards=StandardMapping(
                cwe=["CWE-798"],
                owasp_llm=["OWASP-LLM06:2025"],
                owasp_mcp=["OWASP-MCP-M01"],
            ),
            remediation="Extract credentials to an external secret manager or load from environment variables dynamically using standard client expansion syntax.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []

        # Check environment variables
        for env_key, env_val in target.env.items():
            found_pattern, secret_type = self._check_patterns(env_val)
            if found_pattern:
                findings.append(
                    self._build_finding(target, f"env['{env_key}']", secret_type, env_val)
                )
            elif len(env_val) >= 20 and shannon_entropy(env_val) >= 4.3:
                # High entropy suspicious token
                findings.append(
                    self._build_finding(target, f"env['{env_key}']", "High-Entropy Secret", env_val)
                )

        # Check command-line arguments
        for idx, arg in enumerate(target.args):
            found_pattern, secret_type = self._check_patterns(arg)
            if found_pattern:
                findings.append(self._build_finding(target, f"args[{idx}]", secret_type, arg))
            elif (
                len(arg) >= 24
                and shannon_entropy(arg) >= 4.4
                and not arg.startswith(("http://", "https://", "/", "C:\\"))
            ):
                findings.append(
                    self._build_finding(target, f"args[{idx}]", "High-Entropy Argument", arg)
                )

        return findings

    def _check_patterns(self, text: str) -> tuple[bool, str]:
        for name, pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                return True, name
        return False, ""

    def _build_finding(
        self, target: ServerTarget, location: str, secret_type: str, raw_secret: str
    ) -> Finding:
        masked = mask_secret(raw_secret)
        return Finding(
            rule_id=self.metadata.id,
            rule_name=self.metadata.name,
            severity=self.metadata.severity,
            target=target.name,
            message=f"Hardcoded {secret_type} detected in {location} of server '{target.name}'.",
            evidence=f"Field: {location} | Masked Value: {masked}",
            remediation=self.metadata.remediation,
            standards=self.metadata.standards,
            location=target.source_file or location,
        )
