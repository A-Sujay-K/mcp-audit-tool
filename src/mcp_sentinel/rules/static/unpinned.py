import re

from mcp_sentinel.core.models import Finding, RuleMetadata, ServerTarget, Severity, StandardMapping
from mcp_sentinel.rules.base import BaseRule

UNPINNED_RUNNERS = [
    ("npx", re.compile(r"^npx(\.cmd)?$", re.IGNORECASE)),
    ("uvx", re.compile(r"^uvx(\.exe)?$", re.IGNORECASE)),
    ("bunx", re.compile(r"^bunx(\.exe)?$", re.IGNORECASE)),
    ("pipx", re.compile(r"^pipx(\.exe)?$", re.IGNORECASE)),
    ("docker", re.compile(r"^docker(\.exe)?$", re.IGNORECASE)),
]


class UnpinnedPackageRule(BaseRule):
    """Detects unpinned package execution via dynamic runtime package managers."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-004",
            name="Unpinned Package Execution",
            severity=Severity.MEDIUM,
            description="The MCP server is executed via dynamic package runners without explicit version pinning, introducing vulnerability to upstream package takeover.",
            standards=StandardMapping(
                cwe=["CWE-829"],
                owasp_llm=["OWASP-LLM05:2025"],
                owasp_mcp=["OWASP-MCP-M05"],
            ),
            remediation="Pin package executions to an exact version (e.g., npx -y pkg@1.2.3 or uvx pkg==1.2.3) and verify package checksums.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []
        cmd = (target.command or "").strip()

        # Check command or first argument runner
        matched_runner = None
        for runner_name, pattern in UNPINNED_RUNNERS:
            if pattern.search(cmd):
                matched_runner = runner_name
                break

        if not matched_runner:
            return findings

        if matched_runner in ("npx", "uvx", "bunx"):
            # Inspect args for package name
            for arg in target.args:
                if arg.startswith("-"):
                    continue
                # If argument is a package name
                if "@latest" in arg:
                    findings.append(
                        self._build_finding(target, matched_runner, arg, "explicitly uses @latest")
                    )
                    break
                # Check if pinned with @ or ==
                if matched_runner == "npx" and "@" not in arg:
                    findings.append(
                        self._build_finding(
                            target, matched_runner, arg, "missing SemVer @version pin"
                        )
                    )
                    break
                if matched_runner == "uvx" and ("==" not in arg and "@" not in arg):
                    findings.append(
                        self._build_finding(
                            target, matched_runner, arg, "missing exact ==version or @version pin"
                        )
                    )
                    break

        elif matched_runner == "docker":
            # Check docker run image tag
            is_run = any(a.lower() == "run" for a in target.args)
            if is_run:
                for idx, a in enumerate(target.args):
                    if a.lower() == "run" and idx + 1 < len(target.args):
                        # Look ahead for image name
                        for cand in target.args[idx + 1 :]:
                            if cand.startswith("-"):
                                continue
                            if ":" not in cand or cand.endswith(":latest"):
                                findings.append(
                                    self._build_finding(
                                        target,
                                        "docker",
                                        cand,
                                        "missing immutable digest or pinned tag",
                                    )
                                )
                                break
                        break

        return findings

    def _build_finding(self, target: ServerTarget, runner: str, pkg: str, reason: str) -> Finding:
        return Finding(
            rule_id=self.metadata.id,
            rule_name=self.metadata.name,
            severity=self.metadata.severity,
            target=target.name,
            message=f"Server '{target.name}' invokes {runner} with package '{pkg}' that {reason}.",
            evidence=f"Runner: {runner} | Package Spec: {pkg}",
            remediation=self.metadata.remediation,
            standards=self.metadata.standards,
            location=target.source_file,
        )
