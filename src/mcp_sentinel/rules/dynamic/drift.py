import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from mcp_sentinel.core.exceptions import BaselineError
from mcp_sentinel.core.models import (
    BaselineEntry,
    Finding,
    RuleMetadata,
    ServerBaseline,
    Severity,
    StandardMapping,
    ToolDefinition,
)
from mcp_sentinel.rules.base import BaseRule


def compute_canonical_hash(data: dict[str, object] | str) -> str:
    """Computes a deterministic SHA-256 hash of a JSON-serializable dictionary or string."""
    if isinstance(data, str):
        serialized = data.strip().encode("utf-8")
    else:
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def build_tool_baseline_entry(tool: ToolDefinition) -> BaselineEntry:
    schema_h = compute_canonical_hash(tool.input_schema)
    desc_h = compute_canonical_hash(tool.description)
    comp_h = hashlib.sha256(f"{tool.name}:{schema_h}:{desc_h}".encode()).hexdigest()
    return BaselineEntry(
        tool_name=tool.name,
        schema_hash=schema_h,
        description_hash=desc_h,
        composite_hash=comp_h,
    )


def save_baseline(
    server_name: str, tools: Sequence[ToolDefinition], baseline_file: Path
) -> ServerBaseline:
    """Computes and saves a baseline file for an MCP server's declared tools."""
    entries: dict[str, BaselineEntry] = {}
    for t in tools:
        entries[t.name] = build_tool_baseline_entry(t)

    baseline = ServerBaseline(
        server_name=server_name,
        baseline_timestamp=Path.cwd().name,  # or timestamp
        tools=entries,
    )
    try:
        baseline_file.write_text(json.dumps(baseline.model_dump(), indent=2), encoding="utf-8")
    except OSError as e:
        raise BaselineError(f"Failed to write baseline file to {baseline_file}: {e}") from e

    return baseline


def load_baseline(baseline_file: Path) -> ServerBaseline:
    """Loads a previously recorded baseline from disk."""
    if not baseline_file.is_file():
        raise BaselineError(f"Baseline file does not exist: {baseline_file}")
    try:
        data = json.loads(baseline_file.read_text(encoding="utf-8"))
        return ServerBaseline.model_validate(data)
    except (json.JSONDecodeError, OSError, ValueError) as e:
        raise BaselineError(f"Invalid baseline file format in {baseline_file}: {e}") from e


class ManifestDriftRule(BaseRule):
    """Detects manifest mutation or stealth description modifications relative to an approved baseline."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-014",
            name="Manifest Drift ('Rug Pull')",
            severity=Severity.CRITICAL,
            description="The live MCP tool manifest has diverged from the cryptographically hashed baseline, indicating possible schema tampering or late-stage prompt injection.",
            standards=StandardMapping(
                cwe=["CWE-353"],
                owasp_llm=["OWASP-LLM05:2025", "OWASP-LLM02:2025"],
                owasp_mcp=["OWASP-MCP-M05"],
            ),
            remediation="Audit the modified tool definition before execution and re-establish a signed baseline if the changes were authorized.",
        )

    def compare_tools_against_baseline(
        self,
        server_name: str,
        current_tools: Sequence[ToolDefinition],
        baseline: ServerBaseline,
    ) -> list[Finding]:
        findings: list[Finding] = []
        current_map = {t.name: t for t in current_tools}

        # 1. Check for removed tools
        for tool_name in baseline.tools:
            if tool_name not in current_map:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.MEDIUM,
                        target=f"{server_name}:{tool_name}",
                        message=f"Tool '{tool_name}' was present in baseline but has been removed from live server '{server_name}'.",
                        evidence=f"Baseline Hash: {baseline.tools[tool_name].composite_hash[:12]}...",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

        # 2. Check for added or modified tools
        for t in current_tools:
            if t.name not in baseline.tools:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.HIGH,
                        target=f"{server_name}:{t.name}",
                        message=f"New unbaselined tool '{t.name}' was introduced on server '{server_name}'.",
                        evidence=f"New Tool: '{t.name}' | Description: '{t.description[:60]}...'",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )
                continue

            base_entry = baseline.tools[t.name]
            curr_entry = build_tool_baseline_entry(t)

            if curr_entry.description_hash != base_entry.description_hash:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.CRITICAL,
                        target=f"{server_name}:{t.name}",
                        message=f"Tool description drift detected for '{t.name}' on '{server_name}' (potential prompt injection rug pull).",
                        evidence=f"Baseline Desc Hash: {base_entry.description_hash[:12]}... | Live Desc Hash: {curr_entry.description_hash[:12]}...",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

            if curr_entry.schema_hash != base_entry.schema_hash:
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        rule_name=self.metadata.name,
                        severity=Severity.HIGH,
                        target=f"{server_name}:{t.name}",
                        message=f"Tool input schema mutation detected for '{t.name}' on server '{server_name}'.",
                        evidence=f"Baseline Schema Hash: {base_entry.schema_hash[:12]}... | Live Schema Hash: {curr_entry.schema_hash[:12]}...",
                        remediation=self.metadata.remediation,
                        standards=self.metadata.standards,
                    )
                )

        return findings
