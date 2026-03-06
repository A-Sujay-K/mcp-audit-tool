"""Shared Pydantic models used across every module in the MCP Audit Tool.

This is the single source of truth for data structures that flow between
the parser, graph analyser, sandbox, API, and CLI layers.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

# ════════════════════════════════════════════════════════════════════════
# Tool Capability Taxonomy
# ════════════════════════════════════════════════════════════════════════

class ToolCapability(str, Enum):
    """Security-relevant capability categories for MCP tools.

    The classifier assigns one or more of these to every discovered tool.
    """

    READS_SENSITIVE_DATA = "reads_sensitive_data"
    """Tool can read files, databases, secrets, PII, or private user data."""

    INGESTS_UNTRUSTED = "ingests_untrusted_content"
    """Tool fetches URLs, reads emails, processes user-uploaded files,
    or ingests any content not fully controlled by the tool owner."""

    SENDS_DATA_OUT = "sends_data_out"
    """Tool can make outbound HTTP requests, send emails, post to webhooks,
    or transmit data to external services."""

    EXECUTES_CODE = "executes_code"
    """Tool can run shell commands, evaluate code, or execute scripts."""

    MODIFIES_FILESYSTEM = "modifies_filesystem"
    """Tool can create, write, or delete files on the host."""

    MANAGES_CREDENTIALS = "manages_credentials"
    """Tool handles API keys, tokens, passwords, or secrets."""


# ════════════════════════════════════════════════════════════════════════
# MCP Transport & Server Configuration
# ════════════════════════════════════════════════════════════════════════

class TransportType(str, Enum):
    """MCP server transport mechanism."""

    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class ServerConfig(BaseModel):
    """Parsed configuration for a single MCP server from a client config file."""

    name: str = Field(..., description="Server identifier from the config key.")
    transport: TransportType = Field(default=TransportType.STDIO)
    command: str | None = Field(default=None, description="Executable command (stdio transport).")
    args: list[str] = Field(default_factory=list, description="Command arguments.")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables.")
    url: str | None = Field(default=None, description="Server URL (SSE / HTTP transport).")
    config_source: str = Field(
        default="unknown",
        description="Path to the config file this server was parsed from.",
    )
    has_auth: bool = Field(
        default=False,
        description="Whether authentication is configured for this server.",
    )


class ClientConfig(BaseModel):
    """Parsed MCP client configuration containing multiple servers."""

    client_type: str = Field(
        ..., description="Client type: claude_desktop, cursor, windsurf, generic, etc."
    )
    config_path: str = Field(..., description="Absolute path to the config file.")
    servers: list[ServerConfig] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════
# Tool Discovery & Classification
# ════════════════════════════════════════════════════════════════════════

class DiscoveredTool(BaseModel):
    """Raw tool definition as returned by an MCP server's tools/list response."""

    server_name: str
    tool_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = Field(
        default=None,
        description="MCP tool annotations (readOnlyHint, destructiveHint, etc.).",
    )


class ClassificationResult(BaseModel):
    """LLM classification output for a single tool."""

    capabilities: list[ToolCapability]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""


class ClassifiedTool(BaseModel):
    """A discovered tool enriched with its LLM-assigned capability classification."""

    id: UUID = Field(default_factory=uuid4)
    server_name: str
    tool_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[ToolCapability] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    description_hash: str = Field(
        default="",
        description="SHA-256 hash for drift / rug-pull detection.",
    )
    annotations: dict[str, Any] | None = None
    classified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this tool's security-relevant fields."""
        canonical = json.dumps(
            {
                "name": self.tool_name,
                "description": self.description,
                "input_schema": self.input_schema,
                "annotations": self.annotations,
            },
            sort_keys=True,
            ensure_ascii=True,
        )
        self.description_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.description_hash


# ════════════════════════════════════════════════════════════════════════
# Cross-Server Graph & Trifecta Analysis
# ════════════════════════════════════════════════════════════════════════

class TrifectaType(str, Enum):
    """Types of dangerous cross-server capability combinations."""

    LETHAL_TRIFECTA = "lethal_trifecta"
    """Read private data + ingest untrusted content + send data out."""

    CODE_EXECUTION_CHAIN = "code_execution_chain"
    """Ingest untrusted content → execute code (RCE via prompt injection)."""

    CREDENTIAL_THEFT = "credential_theft"
    """Manage credentials → send data out."""

    FILESYSTEM_MANIPULATION = "filesystem_manipulation"
    """Ingest untrusted content → modify filesystem (persistent backdoor)."""


class TrifectaFinding(BaseModel):
    """A single dangerous capability combination found across MCP servers."""

    id: UUID = Field(default_factory=uuid4)
    finding_type: TrifectaType
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)

    # The tools forming this chain
    injection_tool: ClassifiedTool | None = Field(
        default=None, description="Tool providing the untrusted content ingestion surface."
    )
    data_tool: ClassifiedTool | None = Field(
        default=None, description="Tool that reads sensitive / private data."
    )
    exfil_tool: ClassifiedTool | None = Field(
        default=None, description="Tool that can send data outbound."
    )
    code_exec_tool: ClassifiedTool | None = Field(
        default=None, description="Tool that can execute code (for RCE chains)."
    )
    credential_tool: ClassifiedTool | None = Field(
        default=None, description="Tool that manages credentials."
    )
    filesystem_tool: ClassifiedTool | None = Field(
        default=None, description="Tool that modifies the filesystem."
    )

    description: str = ""
    recommendation: str = ""
    servers_involved: list[str] = Field(default_factory=list)
    is_cross_server: bool = Field(
        default=False,
        description="True if the chain spans multiple MCP servers.",
    )


# ════════════════════════════════════════════════════════════════════════
# Exploit Sandbox Results
# ════════════════════════════════════════════════════════════════════════

class ExploitVerdict(str, Enum):
    """Outcome of a sandboxed exploit attempt."""

    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class ExploitStep(BaseModel):
    """A single step in the exploit attempt timeline."""

    step_number: int
    action: str = Field(..., description="What the agent attempted.")
    detail: str = ""
    tool_used: str | None = None
    succeeded: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExploitResult(BaseModel):
    """Full result of a sandboxed exploit confirmation attempt."""

    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    verdict: ExploitVerdict
    steps: list[ExploitStep] = Field(default_factory=list)
    sensitive_data_exfiltrated: bool = Field(
        default=False,
        description="Whether mock sensitive data appeared in the exfiltration channel.",
    )
    injection_payload_used: str | None = None
    failure_reason: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float | None = None


# ════════════════════════════════════════════════════════════════════════
# Drift / Rug-Pull Detection
# ════════════════════════════════════════════════════════════════════════

class DriftType(str, Enum):
    """Types of tool definition changes between scans."""

    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    DESCRIPTION_CHANGED = "description_changed"
    SCHEMA_CHANGED = "schema_changed"
    CAPABILITY_ESCALATION = "capability_escalation"
    CAPABILITY_DEESCALATION = "capability_deescalation"


class DriftEvent(BaseModel):
    """A detected change in a tool's definition between two scans."""

    id: UUID = Field(default_factory=uuid4)
    server_name: str
    tool_name: str
    drift_type: DriftType
    description: str = ""
    old_hash: str | None = None
    new_hash: str | None = None
    old_capabilities: list[ToolCapability] | None = None
    new_capabilities: list[ToolCapability] | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: Literal["low", "medium", "high", "critical"] = "medium"


# ════════════════════════════════════════════════════════════════════════
# Scan Session
# ════════════════════════════════════════════════════════════════════════

class ScanStatus(str, Enum):
    """Status of a scan session."""

    PENDING = "pending"
    DISCOVERING = "discovering"
    CLASSIFYING = "classifying"
    ANALYZING = "analyzing"
    EXPLOITING = "exploiting"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResult(BaseModel):
    """Top-level result of a complete audit scan."""

    id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.PENDING
    config_source: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    # Discovery
    servers_discovered: list[ServerConfig] = Field(default_factory=list)
    tools_discovered: list[DiscoveredTool] = Field(default_factory=list)
    tools_classified: list[ClassifiedTool] = Field(default_factory=list)

    # Analysis
    findings: list[TrifectaFinding] = Field(default_factory=list)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)

    # Exploitation
    exploit_results: list[ExploitResult] = Field(default_factory=list)

    # Drift
    drift_events: list[DriftEvent] = Field(default_factory=list)

    # Summary counts
    @property
    def total_servers(self) -> int:
        return len(self.servers_discovered)

    @property
    def total_tools(self) -> int:
        return len(self.tools_classified)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def confirmed_exploits(self) -> int:
        return sum(1 for e in self.exploit_results if e.verdict == ExploitVerdict.CONFIRMED)
