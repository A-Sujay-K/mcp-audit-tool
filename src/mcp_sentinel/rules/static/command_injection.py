import re

from mcp_sentinel.core.models import Finding, RuleMetadata, ServerTarget, Severity, StandardMapping
from mcp_sentinel.rules.base import BaseRule

DANGEROUS_SHELL_PATTERNS = [
    re.compile(r"\b(sh|bash|zsh|dash)\s+-c\b", re.IGNORECASE),
    re.compile(r"\b(cmd(\.exe)?)\s+/[cC]\b", re.IGNORECASE),
    re.compile(r"\b(powershell(\.exe)?|pwsh)\s+(-[cC]ommand|-[cC])\b", re.IGNORECASE),
    re.compile(r"\|\s*(sh|bash|zsh|python|perl)\b", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
]

BROAD_ROOT_PATTERNS = [
    re.compile(r"^(/|~|/etc|/var|/root|/usr)$"),
    re.compile(r"^[a-zA-Z]:[/\\]?$"),
    re.compile(r"(^|[/\\])\.\.([/\\]|$)"),
]


class DangerousCommandRule(BaseRule):
    """Detects shell interpreter wrappers and command pipe chains in MCP server execution."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-002",
            name="Dangerous Shell Wrapper Execution",
            severity=Severity.HIGH,
            description="The MCP server is launched via an interactive shell wrapper or piped interpreter, opening high-risk command injection pathways.",
            standards=StandardMapping(
                cwe=["CWE-78"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M02"],
            ),
            remediation="Execute the binary or script directly with discrete argument arrays instead of invoking an interactive shell interpreter.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []
        cmd_str = f"{target.command or ''} {' '.join(target.args)}".strip()

        for pattern in DANGEROUS_SHELL_PATTERNS:
            match = pattern.search(cmd_str)
            if match:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=self.metadata.severity,
                        target=target.name,
                        message=f"Server '{target.name}' invokes an interactive shell wrapper or shell pipe: '{match.group(0)}'.",
                        evidence=f"Full command line: {cmd_str}",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                        location=target.source_file,
                    )
                )
                break

        return findings


class BroadFilesystemRootRule(BaseRule):
    """Detects broad filesystem exposure or unrestricted directory mount targets."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-003",
            name="Broad Filesystem Root Access",
            severity=Severity.HIGH,
            description="Server command arguments specify root or sensitive OS directories, exposing excessive host filesystem access to the LLM agent.",
            standards=StandardMapping(
                cwe=["CWE-22", "CWE-552"],
                owasp_llm=["OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M04"],
            ),
            remediation="Scope filesystem access strictly to a dedicated, unprivileged workspace directory rather than root or user home folders.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []

        for idx, arg in enumerate(target.args):
            for pattern in BROAD_ROOT_PATTERNS:
                if pattern.search(arg.strip()):
                    findings.append(
                        Finding(
                            rule_id=self.metadata.id,
                            rule_name=self.metadata.name,
                            severity=self.metadata.severity,
                            target=target.name,
                            message=f"Server '{target.name}' passes broad or traversing filesystem path in args[{idx}]: '{arg}'.",
                            evidence=f"Argument: {arg}",
                            remediation=self.metadata.remediation,
                            standards=self.metadata.standards,
                            location=target.source_file,
                        )
                    )
                    break

        return findings
